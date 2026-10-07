# API, CLI and MCP parity

ShakerProxy's goal is complete visibility of every device connection, the same
in the Web UI, through the REST API, in the `shakerproxy` CLI and through MCP
for AI agents. This page maps each piece of traffic and device visibility the
Web UI shows to the API route behind it, the CLI command and the MCP tool that
expose it, and lists what is deliberately left out of MCP.

Scopes: a signed-in administrator session reaches every route. API tokens need
the scope shown. MCP uses an API token, normally the investigator token
(`system:read`, `devices:read`, `traffic:read`, `captures:read`, `cases:read`,
all read scopes and none sensitive); `http_exchange` additionally needs
`traffic:content`, a sensitive scope the AI agents wizard adds when
**Include HTTP content** is ticked (see [AI agent quick connect](ai-agent-quick-connect.md)).
The CLI uses the token `shakerproxy login` creates; reading HTTP content
(`shakerproxy event <id> --http`) asks for the administrator password.

## The default view

The Traffic page lists one row per connection and per lookup: it leaves out
the analyzers' duplicate records (Suricata's copies of what Zeek records,
Zeek's handshake records next to their connection, the connection records of
DNS lookups) and network chatter no lab device sent, and folds a long
connection, which each capture segment records again, into one row with all
of its bytes. `shakerproxy watch`, `shakerproxy search` and the MCP tools
`search_traffic`, `device_activity`, `follow_traffic` and `dns_lookups` list
the same rows: they send the server's own default view
(`ingest.DefaultViewFilter`, checked against what the page sends) and fold the
page with `agentapi.FoldEvents`, the Go copy of the page's folding.
`--all` (CLI) and `all: true` (MCP) list every stored record, as the page's
"any event" mode does; a query that names `kind:` gets exactly those records.
The API itself returns every record and leaves the view to its caller.

## Traffic

| Web UI | API route | Token scope | MCP tool | CLI |
| --- | --- | --- | --- | --- |
| Live view stream (rows: From → To, type, owner, bytes) | `GET /api/v1/events` | `traffic:read` | `search_traffic`, `device_activity` | `search` |
| Live view following new traffic as it arrives | `GET /api/v1/events/live` (SSE, cursor) | `traffic:read` | `follow_traffic` | `watch [<ref>]` |
| Filters: client, type, time, search, advanced query | `q` on `/events` and `/events/live` | `traffic:read` | `query` on `search_traffic`, `follow_traffic` | `search <query> --device <ref> --window 1h` |
| Timeline and facet counts (devices, types, owners, ports) | `GET /api/v1/events/summary` | `traffic:read` | `traffic_summary` | - |
| Event detail: essentials by type (lookup and answers, connection facts, alert, Wi-Fi) | `GET /api/v1/events/{id}` | `traffic:read` (metadata-only for tokens) | `event_detail` | `event <record-id>` |
| Event detail: HTTP request and response | `GET /api/v1/events/{id}/http-exchange` | `traffic:content` (credentials redacted) | `http_exchange` | `event <record-id> --http` |
| DNS rows with answers | `GET /api/v1/events` | `traffic:read` | `dns_lookups` | `search dns.query:...` |
| DoH, DoT and DoQ badges; blocked encrypted DNS | `GET /api/v1/events` (`app_protocol`, `blocked`) | `traffic:read` | `encrypted_dns`; every event line's `encrypted_dns`, `blocked`, `blocked_reason` | `search app.protocol:doh`, `dns` |
| DNS visibility switches (force plain DNS, block encrypted DNS) | `GET /api/v1/dns-visibility` | `system:read` | `dns_visibility` | `dns` |
| TLS outcomes and likely certificate pinning | `GET /api/v1/events` (mitmproxy events) | `traffic:read` | `tls_issues` | `search tls.state:FAILED` |
| HTTP request list | `GET /api/v1/agent/http-activity` | `traffic:read` | `http_requests` | `search http.method:*` |
| Protocols page | `GET /api/v1/protocols`, `/protocols/catalog` | `traffic:read` | `protocols` | `protocols` |
| Wi-Fi rows and the device Wi-Fi panel | `GET /api/v1/events` (`wifi.*`), `GET /api/v1/wifi-visibility` | `traffic:read`, `system:read` | `wifi_activity` | `wifi` |

## Devices and tests

| Web UI | API route | Token scope | MCP tool | CLI |
| --- | --- | --- | --- | --- |
| Device list: names, addresses, online, vendor | `GET /api/v1/agent/devices` (sessions: `/devices`) | `devices:read` | `list_devices` | `devices` |
| Device named by IP address; merged private-MAC records | `pinned_address`, `former_ids` on `/agent/devices` | `devices:read` | `list_devices` | `device <ip>` |
| Devices on the lab whose traffic bypasses ShakerProxy, with the reason and the fix (Live view banner, Devices badge, System panel) | `GET /api/v1/lab-routing` (also `lab_routing` on `/devices`) | `devices:read` | `lab_routing` | `devices` (ROUTING column), `coverage` |
| Platform in device titles ("GrapheneOS phone") and what showed it | `platform` on `/agent/devices` (sessions: `platform_hints` on `/devices`) | `devices:read` plus `traffic:read` | `list_devices` (`platform`, `platform_evidence`) | `devices`, `device` (names use the platform) |
| Device lab controls (decrypt HTTPS, block internet, blocked domains) | `GET /api/v1/devices/{id}/controls` | `devices:read` | `device_controls` | `device <ref>`, `decrypt`, `block`, `unblock` |
| Find a device by name, IP, MAC or ID | `GET /api/v1/devices/resolve` | `devices:read` | `find_device` (and every `device` argument) | every `<ref>` argument |
| Device report: domains, owners, protocols, HTTPS, findings | `GET /api/v1/devices/{id}/report` | `devices:read` | `device_report` | `report <ref>` |
| Compare two test runs | `GET /api/v1/devices/{id}/compare` | `devices:read` | `compare_runs` | `compare` |
| Test runs | `GET /api/v1/test-sessions` | `devices:read` | `test_sessions` | `test list` |
| VPN devices | `GET /api/v1/vpn` | `system:read` | `vpn_devices` | `vpn` |

## System

| Web UI | API route | Token scope | MCP tool | CLI |
| --- | --- | --- | --- | --- |
| Readiness: gateway mode, analyzers, ingestion, live analysis | `GET /api/v1/agent/system-overview` | `system:read` | `system_status` | `status` |
| Visibility coverage check results and bypass findings | `GET /api/v1/coverage` | `system:read` | `visibility_coverage` | `coverage` |
| System page "Visibility health", `shakerproxy status`: recording loss, lost live events, live analysis, analyzer gaps, storage lag, device discovery, decryption and policy | `GET /api/v1/visibility-health` (also `visibility` in `/coverage`) | `system:read` | `visibility_coverage` (and the gaps in `system_status` limitations) | `status` |
| `shakerproxy doctor` and the System page health checks | `GET /api/v1/system/diagnostics` | `system:read` | `diagnostics` | `doctor` |
| Captures page: recordings, sizes, drops, holds | `GET /api/v1/agent/captures` (full records: `/captures`) | `captures:read` | `captures` | `capture list` |
| Cases: case list, evidence, timeline, hold | `GET /api/v1/agent/cases`, `/agent/cases/{caseID}` (full records: `/cases`) | `cases:read` | `cases` | - |
| Network-gear (UniFi) log collector: on/off, listen, allowlist, counts (Integrations page) | `GET /api/v1/integrations/syslog-collector` (config: `PUT`, session + password) | `system:read` | `syslog_collector` (read-only) | `syslog` |
| Notifications: recent alerts and the unread count (Integrations page) | `GET /api/v1/notifications` (configuration: `/integrations/notifications`, session + password) | `system:read` | `notifications` (read-only) | `alerts` |

## Gaps closed with this page

- `event_detail`: one event's essentials, as the event detail shows them.
- `http_exchange` and the `traffic:content` scope: HTTP requests and responses
  were readable only in a browser session.
- `follow_traffic` and `live_cursor` on `search_traffic`: agents could page
  back in time but not follow new traffic in order.
- `encrypted_dns`, plus `encrypted_dns` and `blocked` on every event line:
  DoT and DoQ were not matched by `dns_lookups`, and blocks were unlabeled.
- `pinned_address` and `former_ids` in `list_devices`.
- Ten routes the UI or agents use were missing from
  `schemas/api/openapi.yaml`; the route check now reads every server file.

## Gaps closed next

- `platform` on agent devices and in `list_devices`, from the same hints the
  Devices page uses (connectivity checks and DHCP requests), for callers that
  may read traffic.
- `device_controls`: a device's lab controls and whether they are enforced.
- `captures` and `GET /api/v1/agent/captures`: the full capture list carries
  every finished capture's file list (583 KB for 12 captures on a test lab),
  so agents get one bounded summary per recording instead.
- `cases`, `GET /api/v1/agent/cases` and `/agent/cases/{caseID}`: case
  summaries, and one case's newest evidence and timeline. A case can hold
  1,024 evidence items and 2,048 timeline events, so the agent view is
  bounded.
- `diagnostics`: the `shakerproxy doctor` checks, problems first.
- The investigator token adds `captures:read` and `cases:read`.

## Gaps closed in the CLI

- `shakerproxy watch` and `search` list the Traffic page's default view
  (`--all` for every record), as the MCP traffic tools now do.
- `shakerproxy event <record-id>`: one event's facts, and with `--http` its
  HTTP request and response (credentials redacted).
- `shakerproxy devices` has a ROUTING column: whether each device's traffic
  goes through ShakerProxy, and a warning when a device bypasses it.

## Still open

- The CLI has no command for the traffic summary (`/events/summary`, MCP
  `traffic_summary`) or for cases; use `shakerproxy api GET /api/v1/...`.

Report a gap where the Web UI shows traffic or device facts that the API, the
CLI or MCP does not return.

## Deliberately not in MCP

MCP is read-only. These stay in the Web UI, CLI and API:

- every change: naming or merging devices, device controls (decrypt, block),
  DNS visibility and Wi-Fi switches, VPN devices (their keys are secrets),
  network plans, traffic policy, test runs, captures, cases, retention and
  deletion, tokens and forwarders;
- running the visibility coverage check (`POST /api/v1/coverage/runs`);
- PCAP bytes and capture exports;
- the full raw event payload: tokens get the metadata-only projection of
  `GET /api/v1/events/{id}`, and HTTP content only through `traffic:content`
  with credentials redacted;
- revealing credential headers: the Web UI masks them until an administrator
  reveals them; tokens never see them;
- UI-only presentation: repeat folding, grouping, saved views, query snapshots
  and Copy as cURL.
