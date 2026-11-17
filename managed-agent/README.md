# BetterDesk Managed Credential Agent

Windows SYSTEM service that accepts only the fixed CDAP widget
`betterdesk.managed_credential` and its `rotate` / `revoke` actions. It changes
RustDesk's unattended password through the official privileged CLI, persists
only request/expiry metadata, and rotates to an unknown random local password
when the credential expires or is revoked.

## Install

1. Use an installed RustDesk Windows client. Do not enable RustDesk's
   `disable-change-permanent-password` policy on managed endpoints.
2. Create a device token in BetterDesk and bind it to the RustDesk peer ID.
3. Enable CDAP with TLS (`CDAP_TLS=Y` and valid `TLS_CERT` / `TLS_KEY`).
4. Build or copy `BetterDeskManagedAgent.exe` beside `Install.ps1`.
5. From elevated PowerShell:

```powershell
.\Install.ps1 `
  -ServerUrl "wss://rustdesk.example.com:21122/cdap" `
  -DeviceId "123456789" `
  -DeviceToken "REPLACE_WITH_BOUND_DEVICE_TOKEN" `
  -RustDeskPath "C:\Program Files\RustDesk\rustdesk.exe"
```

For a private CA, pass `-TLSCAFile C:\path\ca.pem`. Do not use
`insecure_skip_verify` in production. The installer restricts config and state
ACLs to SYSTEM and Administrators because the config contains a device token.

## Security properties

- CDAP `wss://` is mandatory; plaintext WebSocket URLs are rejected.
- No arbitrary shell, terminal, file or process control is implemented.
- Passwords are never written to agent logs or its state file.
- The agent returns only execution status, never the password, in CDAP responses.
- Repeated request IDs are idempotent.
- Expiry survives service restart and is enforced locally even while offline.

The agent requires administrator/SYSTEM privileges because RustDesk accepts
permanent-password changes only from its installed privileged service.
