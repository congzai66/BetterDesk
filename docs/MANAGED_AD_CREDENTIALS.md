# Managed AD Devices and Temporary Credentials

This feature extends BetterDesk with read-only Active Directory inventory, OU-to-organization mapping, and short-lived RustDesk connection passwords for managed Windows endpoints.

## Scope and security boundary

- Windows endpoints only in this release.
- The agent supports exactly two actions: `rotate` and `revoke`. It does not expose a shell, arbitrary process execution or file management.
- Existing user-selected permanent RustDesk passwords are not collected.
- Passwords travel only in authenticated CDAP TLS commands and are stored encrypted in the existing organization peer vault.
- Command responses, CDAP events and logs must not contain plaintext passwords. Do not add request/response payload logging.
- Production use requires an installed RustDesk service, administrator privileges, `ORG_PEER_VAULT_KEY`, and CDAP TLS.

## Server configuration

Set the following environment variables using the existing BetterDesk deployment mechanism:

```dotenv
CDAP_TLS=Y
CDAP_TLS_REQUIRED=true
TLS_CERT=/secure/path/fullchain.pem
TLS_KEY=/secure/path/private-key.pem
ORG_PEER_VAULT_KEY=replace-with-a-long-random-secret
```

Generate a vault secret with your secret manager, or for an initial installation:

```sh
openssl rand -base64 32
```

Back up this secret independently of the database. Losing it makes existing encrypted peer credentials undecryptable. Changing it without a planned migration has the same effect.

The CDAP gateway defaults to TCP `21122`. Allow managed endpoints to reach that port over TLS. Keep the existing RustDesk rendezvous/relay and Console rules unchanged.

Start the upgraded BetterDesk server once to apply the `managed_credentials` and `directory_objects` migrations. SQLite and PostgreSQL are supported. Migrations are idempotent and run lazily at managed-store entry points, so both API and direct database calls initialize the schema safely. Take a database backup before upgrading a production installation.

## Active Directory configuration

1. In the existing LDAP/AD settings, configure a read-only bind account, Base DN and LDAPS or StartTLS. Test AD sign-in before enabling inventory synchronization.
2. Open **Devices → AD Directory**.
3. Review users, groups, computers and OUs with **Sync now**. Manual sync does not change organization assignments unless **Apply mappings** is selected.
4. Add OU mappings, one per line:

   ```text
   OU=Finance Workstations,DC=example,DC=com | 3
   OU=IT Workstations,DC=example,DC=com | 4
   ```

   The number after `|` is the existing BetterDesk organization ID. Use the longest matching OU DN. Leave this list empty to inventory AD computers without moving them.
5. Set **Sync interval** to `0` to disable periodic synchronization, or `5`–`1440` minutes. The default is `0`.
6. Enable **Apply mappings from scheduled sync** only after manually validating the mapping result.

Computers are matched by normalized hostname. A missing match is `unmatched`; duplicate peer hostnames are `ambiguous` and are never assigned automatically. Existing organization device metadata is preserved. Each object class is capped at 10,000 entries per synchronization and LDAP pages contain 500 entries.

The directory synchronizer is read-only: it does not create, delete or modify AD objects.

## Windows agent installation

Build on a development machine with Go support for cross-compilation:

```sh
cd managed-agent
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o BetterDeskManagedAgent.exe .
```

Copy `BetterDeskManagedAgent.exe` and `Install.ps1` to the endpoint. From elevated PowerShell:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Install.ps1 `
  -ServerUrl "wss://betterdesk.example.com:21122/cdap" `
  -DeviceId "RUSTDESK-PEER-ID" `
  -DeviceToken "BOUND-CDAP-DEVICE-TOKEN" `
  -RustDeskPath "C:\Program Files\RustDesk\rustdesk.exe" `
  -TLSCAFile "C:\ProgramData\BetterDesk\internal-ca.pem"
```

Use the RustDesk peer ID bound to the endpoint's CDAP device token. Keep the token secret. `-TLSCAFile` is required when the server certificate is signed by an internal CA; omit it for a certificate already trusted by Windows. Optionally specify `-InstallDir` and `-BinaryPath` when the defaults are not suitable. The installer writes its configuration to `C:\ProgramData\BetterDesk\managed-agent.json`.

The installer copies the executable, writes UTF-8 configuration, restricts access to SYSTEM and Administrators, and installs the `BetterDeskManagedAgent` service. The default configuration is `C:\ProgramData\BetterDesk\managed-agent.json`; expiry metadata is stored separately in `managed-state.json` without plaintext passwords.

To inspect the service:

```powershell
Get-Service BetterDeskManagedAgent
Get-WinEvent -LogName Application -MaxEvents 50 |
  Where-Object { $_.Message -like '*BetterDeskManagedAgent*' }
```

Do not enable verbose CDAP payload logging in production.

## RustDesk prerequisites

- RustDesk must already be installed as a service; portable/uninstalled mode is not sufficient for `--password`.
- The agent service must have administrator privileges (the installer uses LocalSystem).
- The endpoint must not enforce `disable-change-permanent-password`, because that RustDesk strategy intentionally blocks this feature.
- A successful rotation requires RustDesk to print its real `Done!` confirmation. Process exit code alone is not accepted.

## Permissions

| Permission | Purpose | super_admin / admin | global_admin | operator |
| --- | --- | --- | --- | --- |
| `credential.view` | View a currently valid decrypted temporary password | Yes | Yes | Yes |
| `credential.rotate` | Rotate or revoke a temporary password | Yes | Yes | No |
| `directory.view` | View AD configuration and snapshots | Yes | Yes | Yes |
| `directory.sync` | Change sync settings and run synchronization | Yes | Yes | No |

Global administrators are restricted to their assigned organizations. Node.js Console routes also enforce session CSRF protection, device scope and organization scope. Remove `credential.view` from operators who should be able to connect but must not see managed passwords.

All password views, rotations, revocations, expirations and directory synchronizations are audited. Audit records contain metadata, not plaintext passwords.

## Operator workflow

1. Open **Devices**, locate a computer and choose **Temporary password**.
2. Select a TTL of 5–120 minutes (default 15) and choose **Rotate**.
3. Wait for endpoint acknowledgement. Only then does **Show** decrypt and display the password.
4. Use the password before the displayed expiry. Copying does not extend the TTL.
5. Choose **Revoke** to replace the endpoint password with an unknown random value and clear the server vault entry. Revocation requires online agent confirmation.

Expired and failed credentials never return plaintext. The agent also schedules local expiry recovery and resumes pending recovery after restart, including while disconnected from the server.

## API

Device-scoped Console/Go route (organization resolved from the peer):

```text
GET    /api/peers/{peerId}/managed-credential
POST   /api/peers/{peerId}/managed-credential   {"ttl_minutes":15}
DELETE /api/peers/{peerId}/managed-credential
```

Organization-scoped equivalents are available at `/api/org/{id}/managed-credentials/{peerId}`.

Directory routes:

```text
GET  /api/directory/config
PUT  /api/directory/config
POST /api/directory/sync       {"apply":false}
GET  /api/directory/objects?kind=computer&q=pc01&limit=100
```

## Troubleshooting

| Symptom | Checks |
| --- | --- |
| Rotation reports device offline | CDAP service, TCP 21122, device ID/token, peer binding and agent service status |
| TLS handshake fails | `wss://`, certificate SAN, internal CA file, server TLS_CERT/TLS_KEY |
| Rotation reports vault unavailable | `ORG_PEER_VAULT_KEY` is present and unchanged across server replicas |
| RustDesk rejects rotation | Installed service, admin rights, client version, `disable-change-permanent-password` policy |
| AD computer is unmatched | Peer hostname, computer name and duplicate hostname records |
| AD computer is ambiguous | Resolve duplicate peers; automatic assignment intentionally stops |
| Device is not moved by scheduled sync | OU mapping, organization ID, apply-mappings option and nonzero interval |
| Password disappears at expiry | Expected behavior; rotate again rather than extending an expired item |

## Acceptance testing still required on your infrastructure

Automated unit tests and cross-platform builds do not replace endpoint/domain acceptance. Before production rollout, validate on a dedicated Windows test VM and test AD domain:

1. AD login, group-to-role mapping and all four object types over your real LDAPS/StartTLS chain.
2. Unique, unmatched and ambiguous computer matching; longest-OU organization mapping.
3. Windows service installation, restart, upgrade and uninstallation.
4. CDAP TLS with the production/internal CA and peer-bound device token.
5. Password actually works with your RustDesk client version; verify expiry and revoke on the endpoint.
6. Operator/global-admin positive and negative permission tests, CSRF and audit review.
7. GPO/SCCM deployment if desired, followed by a staged pilot and database rollback plan.
