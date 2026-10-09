# Initial threat model

## Assets and trust boundaries

Critical assets are management credentials, network configuration, packet/body
artifacts, TLS secrets, CA private material, audit history, and update trust
roots. Trust boundaries exist between the browser and API, application and
host daemon, each packet parser, containers and host, and release service and
installer.

## Primary threats and initial controls

| Threat | Initial control | Remaining work |
|---|---|---|
| Web compromise reaches root | Closed JSON-RPC schema over restricted Unix socket; no command/path arguments | Peer-credential role mapping and syscall sandbox verification on Ubuntu |
| Network lockout | Installer never changes networking; strict host-aware preview; independent apply watchdog; clean-VM timeout, daemon-kill, host-reboot, live-SSH, and Docker-stopped bypass proofs | Wider VLAN/topology and upgrade matrix |
| Parser exploit | Privileged daemon handles typed capture metadata only; analyzer broker verifies an `O_NOFOLLOW` descriptor, drops each parser to a UID/GID of its own (no two running parsers share one) with no supplementary groups, and withholds capture-tree, token, and checkpoint access; live Zeek and live Suricata receive only a packet stream on standard input from the broker | Per-engine seccomp/AppArmor profiles and malicious corpus expansion |
| Docker socket abuse | Socket is never mounted into application services | CI assertion against rendered Compose |
| WAN management exposure | Development binds to loopback; production binds port 8443 to loopback and terminates with a generated management-only leaf | Transactional interface-specific bind, firewall test, and remote-management enrollment UX |
| CA purpose confusion or theft | Management root is root-only; edge receives only its server leaf; interception has a separate root-only keyless namespace; provisioning rejects public-key reuse | Encrypted backup/restore, hardware-backed custody option, and clean-VM rotation evidence |
| Token/password theft | One-time token digest, constant-time check, Argon2id password hash, restrictive secret files; sliding sessions with server-side logout; failed-attempt rate limits; password every time for network, deletion, token-creation and global-decryption actions (see below) | Session cookies, CSRF, passkeys |
| Automation credential abuse | Display-once digest-only API tokens require expiry and exact scopes; optional case/device restrictions fail closed on collection paths; every successful use is rate-limited and hash-chain audited; management/destructive routes remain session-only | Role-specific administrators, source-network policy, global distributed rate limits, and hardware-backed secrets |
| Forwarder leaks sensitive content or reaches internal services | The outbound schema has no payload/body/key/credential fields; integrations start disabled; queues are bounded; only a queue-only `forwarderd` with no appliance credential has egress; it also sends the webhook and Slack notifications the control API queues on their shared volume, and a queued delivery holds its channel URL and signing secret only until it is sent, given up or the channel changes; network transports require public TLS endpoints and revalidate DNS on every dial; redirects and proxies are disabled | Clean-VM receiver/TLS/load tests, HMAC rotation, mTLS option, and SIEM-specific mappings |
| Supply-chain tampering | Pinned signed release manifest, artifact hashes, immutable image digests, and fixed application service boundary | Published stable release evidence, SBOM/provenance attestation, and release-key rotation ceremony |
| Disk exhaustion | One active capture, validated ring quota, duration cap, 1 GiB emergency reserve, continuous free-space stop; analyzer output uses a 384 MiB tmpfs plus a 256 MiB per-segment application limit; finalized named captures have exact host/event/analyzer previews, automatic retention, replay barriers, and verified four-backend deletion; normalized events are kept 30 days after they are stored and deleted in short batches; below 2 GiB free the oldest past month is deleted early only while the event database is what fills the disk, never the current month or rows recorded in the last 24 hours, and early deletion is held once it gives no space back | Index/export/backup deletion, a database size quota, and sustained-load evidence |
| Evidence deleted after an investigation starts | Case membership is revisioned; applying/releasing a hold is reauthenticated and idempotent; the host persists a post-capture sidecar checked by manual deletion, selective impact, and automatic retention; partial application is explicit | Managed backup/index propagation, signed custody checkpoints, encrypted bundles, roles, and power-loss evidence |
| Device spoofing or mistaken merge | IP is never an identity; DHCP MAC/client evidence carries source, confidence, and validity windows; contradictions remain separate and visible; reauthenticated exact-evidence merge/split operations publish atomically with bounded SHA-256-chained actor audit records | Multi-source evidence, signed audit checkpoints, randomized-MAC guidance |
| Analyzer event flood or malformed output | Internal token, 256 KiB envelope/192 KiB payload caps, count/byte queue limits, 1 GiB reserve, deterministic deduplication, bounded quarantine prefix | Per-source rate limits, database drain, malicious engine corpus |
| Analyzer read-path data exposure | Distinct query-only token, authenticated control API, fixed filters, 100-record cursor pages, 256 KiB event and 32 KiB health response limits, no raw payloads, and no database credential in the API | Field-level authorization, retention policy, and deep-search threat review |
| Routing/interception loop | Product interception remains disabled; the namespace proof redirects one exact client/origin/TCP-443 tuple and demonstrates nonmatching TLS pass-through | Production marks, exemptions, conntrack ownership, rollback, and broader netlab proofs |
| Misleading decryption claims | Stable reason taxonomy and explicit state model | Adapter evidence and UI flow explanations |

## Administrator sessions and password confirmation

Sign-in returns a bearer session that slides with use: it expires after one
hour without requests and in any case twelve hours after sign-in
(`expires_at` in the login response, `X-ShakerProxy-Session-Expires-At` on every
authenticated response). `POST /api/v1/auth/logout` revokes it server-side.
Sessions are kept (as SHA-256 digests) across a control API restart, so an
upgrade does not sign anyone out; a request with an ended session answers
`401 session_idle_timeout` (an hour without requests, for example in a hidden
browser tab) or `401 session_lifetime_reached` (twelve hours) instead of a bare
`invalid_session`. An open live event stream checks its session or API token
every few seconds and ends with an `event: error` frame once it is signed out,
revoked or reset. One session or token holds at most four live streams, and
API tokens never take the last stream slot.

Ten failed password attempts within five minutes are answered with `429` and
`Retry-After`. Sign-in and confirmation have separate counters per account, so
a mistyped confirmation does not lock out sign-in; recovery codes have their
own counter. Each attempt is counted before the password is checked, and at
most two Argon2id checks run at once (`503 password_check_busy` when a caller
waits too long).

`POST /api/v1/auth/password` changes the password from a signed-in session. It
always needs the current password, signs out every other session and, with
`revoke_api_tokens`, revokes every API token.

A successful password check—signing in, or any request that includes the
correct `password`—starts a ten-minute *recent confirmation* window for that
session only. Inside the window the routes below accept an omitted `password`;
outside it they answer `401 reauthentication_required` and the client asks for
the password once.

| Password every time (`401 password_required` without it) | Recent confirmation is enough |
|---|---|
| Network commit and confirm | Device rename, metadata and tags, merge, split, alias/tag import |
| Capture deletion, deletion retry and supersede | Address alias create, update and delete |
| Device traffic deletion and retry | Case status, hold/release, and case deletion |
| Capture retention policy apply and manual retention runs | Forwarder create, enable/disable, edit and delete |
| API token and AI-investigator token creation | API token revocation; capture and device-deletion cancellation |
| Traffic policy that turns on HTTPS decryption for every client | Other traffic-policy changes and rollback |
| Turning on decrypted HTTP body retention | Turning decrypted HTTP body retention off; capture file export |
| | Virtual test-lab run and cleanup |

Scoped API tokens never satisfy either tier: these routes remain session-only.

**Forgotten password.** `POST /api/v1/auth/recover` accepts the username, one
of the eight recovery codes shown at setup (each works once; case, spaces and
dashes are ignored) and a new password that meets the setup policy. It revokes
every session and returns a new one with `remaining_recovery_codes`. With
`revoke_api_tokens` it also revokes every API token.

**No recovery codes left.** Local root can reset the administrator:
`sudo shakerproxy admin reset` writes
`/var/lib/shakerproxy/control-api/admin-reset.request` (JSON
`{"requested_at","requested_by"}`, root-owned, mode `0600`). The control API
polls for it every five seconds and honours it only when it is a regular,
root-owned, mode-`0600` file (symbolic links are never followed); any other
request file is logged and deleted. On reset it writes a new one-time setup
token to `/var/lib/shakerproxy/control-api/setup-token` (mode `0600`) and its
digest next to it (the digest supersedes the installation verifier, so the
original setup token cannot be replayed), deletes the administrator credential
and recovery codes, ends every session, deletes the request, and logs the
reset. Setup then works as on first run; the token receipt is removed when
setup consumes it. API tokens are not revoked by a reset unless it is run
with `--revoke-api-tokens`: the command then first writes
`admin-reset.revoke-api-tokens` beside the request (root-owned, mode `0600`,
checked like the request), the control API revokes every token and only then
removes it, and a marker the control API left in place (an older release, a
rejected marker or a failed revocation) is reported as "not revoked". The flag
is refused while a reset without it is already waiting, because that request
cannot be given the marker after the fact.

ShakerProxy cannot defend its audit trail or secrets against an already fully
compromised root account. Hash chaining will make casual or accidental audit
tampering detectable, not root compromise impossible.
