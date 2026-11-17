# Managed AD and Temporary Credentials — Test Report

Date: 2026-11-17
Baseline: BetterDesk v3.5.200 (`eb84feff61c25595e326294fccd13e27ccd14a29`)
Feature branch: `feature/ad-managed-credentials`

## Environment

- Linux cloud VM, x86-64
- Go server toolchain: go1.26.10 (automatic toolchain selected by the server module)
- Managed agent toolchain: go1.25.0
- Node.js 22.23.4 / npm 10.9.9
- Docker and a real Active Directory domain were not available
- A separate Windows WORKGROUP endpoint with an installed RustDesk service was available for non-destructive native build checks; it was not domain-joined and no password/service mutation was authorized

## Final automated results

| Check | Result |
| --- | --- |
| `go test ./...` in `betterdesk-server` | PASS — all packages |
| `go vet ./...` in `betterdesk-server` | PASS |
| `go test -race ./...` in `managed-agent` | PASS |
| `go vet ./...` in `managed-agent` | PASS |
| Windows amd64 agent cross-build | PASS — PE32+ x86-64 executable |
| Linux amd64 server build | PASS — ELF x86-64 executable |
| Native Windows agent test and vet (`CGO_ENABLED=0`) | PASS on Windows 11 with Go 1.25.0 |
| Native Windows amd64 agent build | PASS — 9,463,296-byte executable with Windows/amd64 build metadata |
| Console full Jest suite | PASS — 139 suites passed, 2 conditionally skipped; 928 tests passed, 3 skipped |
| `npm run check:frontend` | PASS — 116 browser scripts |
| `node --check` on modified Node.js files | PASS |
| Managed Compose override static validation | PASS — YAML parsing, CDAP port/TLS, required secrets and read-only certificate mounts |

The Docker split-volume shell test is conditionally skipped when the host does not provide both POSIX `sh` and the `sqlite3` CLI. The production guard itself was not changed. The other skipped suite is an existing conditional suite. No failed test remains in the final run.

The Windows host has no C compiler, so native Windows tests ran without `-race`; the agent race-enabled suite passed separately on the Linux toolchain.

The update preflight test injects Go and GitHub HTTPS test doubles before loading the unmodified upstream update service, preventing accidental live GitHub calls without changing production behavior.

## Feature coverage

### Server and database

- Default role grants for credential and directory permissions
- AD GUID and parent-DN parsing
- Longest-OU organization mapping
- Unique hostname matching and ambiguous-hostname protection
- SQLite managed credential and directory snapshot CRUD
- Valid credential decryption/view path
- No plaintext returned after expiry
- Expired vault cleanup
- Organization/peer route resolution and scoped authorization
- Serialized rotate/revoke operations
- Modular route registration through the existing authentication and secure HTTP middleware
- SQLite/PostgreSQL lazy managed-store migrations, including direct store calls

### Managed agent

- Rotation and duplicate-request idempotency
- Local random password replacement at expiry
- Retry after local expiry failure
- Restart recovery from metadata-only state
- Revocation
- Plaintext excluded from command results and persisted state
- RustDesk `Done!` confirmation required
- Plaintext `ws://` rejected
- Repeated state replacement supported on Windows through `MoveFileEx`

### Console

- Existing device, authentication, organization, RBAC and security regression suites
- Five focused managed-AD route tests: denied permission, denied device scope, authorized read, rotation/TTL forwarding and sync-option mapping
- Permission-matrix and frontend script syntax
- Deterministic update preflight tests

## Acceptance tests not performed

These require the user's infrastructure and must not be represented as completed:

1. Real AD login, LDAPS/StartTLS certificate validation, paged synchronization and group-to-role mapping.
2. Real OU-to-organization assignment against production-like OUs and device names.
3. Windows service install/start/stop/restart/uninstall, ACL verification and GPO/SCCM deployment.
4. Real CDAP TLS connection using the site CA and peer-bound device token.
5. Actual RustDesk password change, successful remote connection, expiry and revocation on a Windows endpoint.
6. Docker/PostgreSQL deployment migration and rollback on the target topology.

Use the checklist in `docs/MANAGED_AD_CREDENTIALS.md` for a staged pilot before production rollout.
