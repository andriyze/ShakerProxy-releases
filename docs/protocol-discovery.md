# Protocol discovery

Protocol discovery answers a simple question about a device under test:
**what does it actually talk, and how much of that can ShakerProxy see into?**
It lists every application protocol a device used (HTTPS, MQTT, QUIC,
Google Cast, WireGuard, Modbus, "unidentified UDP", …), flags the unusual
ones, marks protocols that appeared for the first time, and reports how much
of the traffic was decrypted, readable, only partly visible, or opaque.

It is available in the API, the query language, the CLI
(`shakerproxy protocols [<device>] [--exotic]`) and MCP (`protocols`).

## Where the data comes from

| Source | When it runs | What it contributes |
|---|---|---|
| HTTPS interception (mitmproxy) | Always, for devices with **Decrypt HTTPS** on | One event per TLS connection (decrypted, bypassed or failed), HTTP requests/responses, DNS-over-HTTPS lookups |
| Zeek | While a **capture** is running (and when it finishes) | Every connection (`zeek.conn`) with the protocol Zeek's analyzers confirmed, plus DNS, HTTP, TLS, QUIC, MQTT, SSH, DHCP, NTP … records, `weird` and `analyzer` (protocol violation) logs, `known_services` and `software` |
| Suricata | While a capture is running | Flows with the detected app-layer protocol, app-layer records, and alerts |

Without a capture only intercepted traffic is visible. Every summary lists the
`sources` that contributed, so a client can say "start a capture to see all
protocols".

Every event is classified once, at ingest, by `internal/protocolclass`, and
stored with:

- `app_protocol` – a catalog ID such as `mqtt`, `tls`, `quic`, `unknown-udp`
  (`GET /api/v1/protocols/catalog` lists them all);
- `protocol_category` – e.g. `iot-messaging`, `vpn-tunnel`, `casting`;
- `protocol_evidence` – how it was identified (see below);
- `protocol_visibility` – how much ShakerProxy can see (see below);
- `protocol_exotic` – `true` for anything that is not everyday traffic
  (everything except HTTP(S), QUIC, DNS, NTP, DHCP, ICMP and local discovery).
  Unidentified traffic is exotic on purpose.

## Reading evidence

| Evidence | Meaning | How much to trust it |
|---|---|---|
| `ANALYZER` | Zeek, Suricata or the interception proxy recognized the protocol itself from the payload | High – the only payload-confirmed level |
| `CARRIER_AND_PORT` | An analyzer confirmed only the carrier (TLS, QUIC, DNS wire format, HTTP, or the COTP session layer) and the well-known port named the application inside it: TLS on TCP 853 → DNS over TLS, TLS on TCP 5228 → Google push, QUIC on UDP 853 → DNS over QUIC, DNS on UDP 5353 → mDNS, COTP alone on TCP 102 → S7 | Medium – the carrier is certain, the application is the port's guess |
| `PORT_HEURISTIC` | Only a well-known port matched (e.g. TCP 1883 → MQTT) | Low to medium – any program can use any port |
| `UNCLASSIFIED` | Neither matched; the flow is reported as `unknown-tcp`, `unknown-udp` or `unknown` | It is a coverage gap, not a protocol |

A protocol's evidence in a summary is the strongest evidence seen for it, in
the order above. Device reports, findings, the UI ("Port on confirmed
carrier"), the CLI and MCP never present `CARRIER_AND_PORT` as confirmed: a
finding's evidence line says "carrier confirmed by protocol analysis,
application identified by port number".

## Reading visibility and coverage

| Visibility | What ShakerProxy can see | Typical examples |
|---|---|---|
| `DECRYPTED` | Everything: ShakerProxy intercepted and decrypted it | HTTPS with the ShakerProxy CA installed |
| `CLEARTEXT` | The protocol is readable on the wire | HTTP, MQTT, DNS, Telnet, Modbus (what an industrial device is asked to do: [industrial protocols](industrial-protocols.md)) |
| `ENCRYPTED_METADATA` | Encrypted, but the handshake shows who it talks to (SNI, certificates, ALPN) | TLS that was not decrypted, QUIC, SSH, MQTT over TLS |
| `OPAQUE` | Nothing useful: tunnels, proprietary binary protocols, unidentified traffic | WireGuard, Tuya, TeamViewer, `unknown-udp` |
| `UNKNOWN` | Security unknown: the protocol chooses per connection whether to encrypt, and nothing observed showed which | OPC UA (security mode None, Sign or SignAndEncrypt), SMTP/IMAP/POP3/LDAP/XMPP/FTP before STARTTLS is seen, MySQL, PostgreSQL, SMB, VNC, SNMP |

Protocol identity is not a security property. The catalog gives a fixed
visibility only where the protocol's definition fixes it (HTTP is cleartext,
TLS and everything wrapped in it is encrypted, WireGuard is opaque). A
protocol that negotiates encryption in-band on its usual port starts as
`UNKNOWN`, and what the connection shows replaces it: an analyzer that saw the
TLS session a STARTTLS command started (`smtp,ssl`) makes it
`ENCRYPTED_METADATA`, a confirmed DTLS carrier does the same for LwM2M, and an
OPC UA security mode observed on the connection makes `None` and `Sign`
`CLEARTEXT` (signed messages are readable) and `SignAndEncrypt`
`ENCRYPTED_METADATA`. The mode comes from the OT analyzer profile's secure
channel records ([industrial protocols](industrial-protocols.md)): that record
carries the mode's visibility itself, and protocol discovery and device
reports match each OPC UA connection record to the secure channel record of
the same connection (client and server address and port, within ten minutes;
the least protected mode wins if there are several). The connection record
on the Traffic page keeps `UNKNOWN`, because ingest classifies one record at
a time. Chromecast's TCP 8008 is the cleartext DIAL/HTTP service
(`dial`); only TCP 8009 is the encrypted Cast channel.

`coverage` adds up the **bytes of counted flows** by visibility:

```json
"coverage": {"total_bytes": 14048, "decrypted_bytes": 9000, "cleartext_bytes": 3000,
             "encrypted_metadata_bytes": 0, "opaque_bytes": 2048, "unknown_bytes": 0,
             "opaque_percent": 14.6}
```

`decrypted_flows` on each protocol counts the flows ShakerProxy decrypted, each
matched to its own interception. A protocol reads `DECRYPTED` only when every
flow was decrypted; a device with one decrypted and one undecrypted HTTPS
server shows TLS as `ENCRYPTED_METADATA` with `decrypted_flows` 1 of 2.

A high `opaque_percent` means the device moves data ShakerProxy cannot inspect;
look at the `OPAQUE` protocols (`protocol.visibility:OPAQUE`) first. Coverage
always describes every protocol in scope, even when the list is filtered with
`category` or `exotic`. Interception-only flows carry no byte counts, so
coverage is most meaningful while a capture is running.

A passively analyzed TLS flow is upgraded to `DECRYPTED` when ShakerProxy
intercepted the same connection (same client and server address and port
within ten minutes).

## How flows are counted (dedupe rule)

The same connection is often seen several times: by Zeek and Suricata, and by
the interception proxy. Protocol discovery counts each connection **once**:

1. **Passive analysis.** `zeek.conn` records are a capture's flows. A capture's
   `suricata.flow` records count only when Zeek produced no connections for that
   capture in the window (Suricata-only analysis).
2. **Interception.** A TLS outcome from the interception proxy (decrypted,
   bypassed, failed) is one connection. It counts as a flow only when no passive
   flow has the same 5-tuple within ten minutes; otherwise it only upgrades
   that flow's visibility.
3. **Observed security.** An OPC UA secure channel record upgrades the
   `UNKNOWN` visibility of the passive flow with the same 5-tuple within ten
   minutes to the security mode it saw; it adds no flow.
4. **Everything else is evidence.** DNS, HTTP, TLS-handshake, QUIC, MQTT and
   other application-layer records, Suricata alerts, and interception HTTP and
   DNS-over-HTTPS records make a protocol appear (with `events`, devices, first
   and last seen) but never add flows or bytes.

So `flows` counts connections, `events` counts every record that identified
the protocol, and a protocol seen only in application-layer records (for
example DNS-over-HTTPS inside an already-counted HTTPS connection) shows
`flows: 0`.

## API

All routes require a signed-in session or an API token with `traffic:read`.

```text
GET /api/v1/protocols?window=24h[&device=<device-id>][&category=<category>][&exotic=true]
GET /api/v1/devices/{device}/protocols?window=7d
GET /api/v1/protocols/catalog
```

- `window` is `1h`, `24h` (default), `7d` or `30d`.
- `device` / `{device}` currently accepts a device ID (`device-<32 hex>`);
  friendly names, IP and MAC addresses will be accepted once the shared device
  resolver lands. An unknown device returns `404 device_not_found`.

```json
{"schema":1,"generated_at":"2026-09-29T12:00:00Z","window":"24h",
 "window_start":"2026-09-28T12:00:00Z","window_end":"2026-09-29T12:00:00Z",
 "protocols":[{"protocol":"mqtt","label":"MQTT","category":"iot-messaging",
   "visibility":"CLEARTEXT","evidence":"ANALYZER","exotic":true,"novel":true,
   "description":"Lightweight IoT publish/subscribe messaging.",
   "flows":12,"bytes":3456,"decrypted_flows":0,"events":20,"device_count":1,
   "devices":[{"device_id":"device-…","device_name":"Bench camera","flows":12,"bytes":3456,"last_seen":"…"}],
   "unattributed_flows":0,"first_seen":"…","last_seen":"…",
   "ports":[{"transport":"tcp","port":1883,"flows":12}]}],
 "coverage":{"total_bytes":3456,"decrypted_bytes":0,"cleartext_bytes":3456,
   "encrypted_metadata_bytes":0,"opaque_bytes":0,"unknown_bytes":0,"opaque_percent":0},
 "sources":["ZEEK","MITMPROXY"],"truncated":false}
```

- `novel` – the protocol's first observation on this appliance (all retained
  history) falls inside the window.
- `unattributed_flows` – flows ShakerProxy could not tie to an inventory device.
- Bounds: 256 protocols, 50 devices and 20 ports per protocol. `truncated` is
  `true` when a bound was hit or the window held more than 500,000 classified
  events (then only the newest 500,000 are summarized).
- Protocols are ordered by bytes, then flows, then events.

## Query language

The event search understands the same classification:

| Query | Finds |
|---|---|
| `proto:mqtt` (also `app:mqtt`, `app.protocol:mqtt`) | MQTT, whether confirmed by an analyzer or only by port |
| `app:ssl`, `proto:https` | Normalized to `app.protocol:tls` |
| `protocol.exotic:true` | Everything that is not everyday traffic |
| `protocol.visibility:OPAQUE` | Traffic ShakerProxy cannot see into |
| `protocol.category:vpn-tunnel` | WireGuard, OpenVPN, IPsec, Tailscale, Tor, … |
| `app.protocol:unknown-*` | Unidentified TCP/UDP flows |
| `service:dns` or `proto:dns` | Every plain DNS record (Zeek `dns.log`, Suricata `dns`) |
| `dns.query:*` | Every DNS lookup with a name, including DNS-over-HTTPS |
| `proto:doh OR proto:dot OR proto:doq` | Encrypted DNS that may bypass the lab resolver |
| `netflix` | A bare word searches DNS names, TLS server names and HTTP hosts |
| `192.168.10.20` | A whole IP address (or a CIDR such as `192.168.10.0/24`) finds traffic to or from it; a fragment such as `192.168.10.` is searched as a host-name part like any other word |
| `device.name:"Bench camera" NOT proto:tls` | Everything the camera sent that is not TLS |
| `time:2026-09-29 protocol.exotic:true` | Exotic traffic on one UTC day |
| `owner:google` (also `dst.owner:google`) | Traffic to destinations the curated domain table attributes to an organization whose name contains the word |
| `category:advertising` (also `dst.category:advertising`) | Traffic to advertising destinations; also `analytics`, `telemetry`, `crash-reporting`, `cloud-platform`, `cdn`, `push`, `os-services`, `streaming`, `iot-cloud` |

Every event row also carries `destination_organization` and
`destination_category` (who operates the destination the event names, from
the same table, absent when unknown) and, for connections the analyzers
counted, `bytes_sent` and `bytes_received` (Zeek `orig_bytes`/`resp_bytes`,
Suricata `bytes_toserver`/`bytes_toclient`). The MCP traffic tools add the
owner to each line's summary, e.g. `TLS to googleads.g.doubleclick.net — Google
(advertising)`, with `from`, `to` and both byte counts.

## Plain-language events

Every event in `/api/v1/events`, `/api/v1/events/live` and the event detail
carries `app_protocol`, `protocol_category`, `protocol_visibility`,
`protocol_evidence`, `protocol_exotic`, `http_method`, `http_host`, `http_path`
(no query string, at most 256 bytes), `http_status`, Suricata `alert_*` fields
and a one-line `summary` (at most 160 characters), for example:

- `DNS lookup api.example.com (A) → 3 answers`
- `Encrypted DNS (DoH) lookup tracker.example (AAAA)`
- `HTTPS api.example.com — decrypted` / `HTTPS api.example.com — not decrypted (pinned?)`
- `GET api.example.com/v1/status → 200`
- `MQTT to 3.4.5.6:1883 · 12 KB`
- `Alert (HIGH): ET POLICY Telnet login`
- `Unidentified UDP to 5.6.7.8:34567 · 2 KB`

Summaries never include headers, bodies, cookies, credentials or query strings.

## How quickly traffic appears

Interception events appear within about **3 seconds** (1 s forwarder, 1 s
database drain, 0.75 s live stream poll).

Passive analysis only reads capture segments after they close, so the capture
rotation interval dominates. Measured on this build (busy 30 s segment: 28,000
packets, 2,000 flows, 4,385 Zeek records):

| Stage | Before | Now |
|---|---|---|
| Capture segment closes (rotation) | 0–300 s | 0–30 s |
| Capture feed publishes the closed segment | ≤1 s | ≤1 s |
| Analyzer notices it (poll) | 0–5 s | 0–2 s |
| Zeek analyzes the segment | ≈0.4 s | ≈0.4 s |
| Delivery to the ingest spool | ≈0.7 ms/record (≈3 s for a busy segment) | same |
| Database drain | ≤1 s + ≈0.6 ms/record | same |
| Live stream poll | ≤0.75 s | ≤0.75 s |
| **Packet → UI** | **≈160 s median, ≈310 s worst** | **≈20 s median, ≈40 s worst** |

The defaults are a 30 s rotation with a 64 × 8 MiB ring (≈32 minutes of
low-rate capture within 512 MiB) and a 2 s analyzer poll
(`SHAKERPROXY_ANALYZER_POLL_INTERVAL`). A capture started with an explicit
`segment_seconds` keeps that value; larger values trade latency for fewer,
larger files. The automatic lab recording rotates every 10 s (120 × 4 MiB,
≈20 minutes within 480 MiB).

### Live analysis of the lab recording

Zeek also follows the automatic lab recording live, so its records do not
wait for the segment to close. dumpcap is unchanged and keeps writing the
evidence segments; the capture worker lets the capture group read the segment
being written, and the Zeek analyzer pipes its packets into one long-running
Zeek as they are written. That Zeek runs as the isolated parser user with no
capture access: it reads only a packet stream on its standard input and
writes logs to its own work directory. Its records are delivered every
250 ms. Measured with the real Zeek on 10 s segments
(`TestLiveZeekEndToEnd`), from the record's packets to ingest:

| Record | Segment analysis (median / worst) | Live |
|---|---|---|
| DNS, HTTP, TLS and QUIC server names, files, NTP, software | 9.6 s / 10.7 s | 0.25–0.4 s |
| Closed TCP connection (`conn.log`) | 9.0 s / 10.7 s | ≈3 s (2 s close delay) |
| Open connection's bytes | per segment | every 10 s |

Live Zeek reports a connection still carrying traffic every 10 seconds; each
report covers only the window since the previous one, so a connection's
records add up to its totals, as per-segment records do. QUIC
records are written at the client hello, so they carry the server name but
not the server's connection ID. Closed TCP connections are logged 2 s after
their last packet, DNS exchanges 3 s, and idle UDP and ICMP flows 30 s.

Each segment reaches ingest once. Live analysis covers a segment only once
its records are in: after it streamed every byte of the closed file into
Zeek, a delivery that began 40 s later (longer than Zeek takes to report any
packet, 30 s for an idle UDP flow) delivered everything Zeek had written, or
Zeek exited after its input ended and everything it wrote was delivered.
Until then the offline pass waits for the segment. It skips a segment only
when live analysis covered it and its SHA-256 matches, and analyzes
everything else: a segment Zeek crashed in, the segments a lagging Zeek
skipped (it jumps to the newest segment when three behind), the segments
whose records ingest had not taken when live analysis stopped (it waits 5
minutes for ingest, 5 s on shutdown) or when the analyzer was killed, and
every segment when live analysis is off (`SHAKERPROXY_ZEEK_LIVE=off`) or the
capture worker predates it. Records live analysis had already delivered from
a segment it hands over this way may appear twice; analyzer health counts
those segments (`segments_reanalyzed`) and the records it could not deliver
(`records_dropped`), and reports `DEGRADED` for 15 minutes after. On
shutdown the analyzer waits up to 12 s for the segment being written to
close, so a restart hands nothing over. Suricata follows the same
recordings live as well ([below](#live-suricata)). A manual capture runs
beside the lab recording, so live analysis keeps following the lab while a
test runs; the analyzers pass over the manual capture's segments the lab
recording covered (it records the same packets) and analyze the rest per
segment.

### Live Suricata

The Suricata analyzer follows the automatic lab and VPN recordings the same
way, so alerts and protocol records do not wait for the segment to close: it
streams the segment being written, converted to one continuous pcap stream,
into one long-running Suricata per recording (`--runmode single`, reading the
stream on its standard input) and delivers its EVE records as Suricata writes
them to `eve.json`. That Suricata runs with the configuration of the analyzer
profile (`suricata-ot.yaml` with the OT profile) and the hash-bound rules,
as the isolated parser user, with no capture access. Measured with the real
Suricata on 10 s segments (`TestLiveSuricataEndToEnd`, run by
`make analyzer-smoke`), from the record's packets to ingest:

| Record | Segment analysis (median / worst) | Live |
|---|---|---|
| Policy alert (HTTP Basic authorization, Telnet) | 11.3 s | 0.35–0.4 s |
| DNS, HTTP, files | 8.3 s / 11.3 s | 0.2–0.4 s |
| Flow record | at the segment's end | when the flow times out or ends |

Reading a trace, Suricata's clock moves only with packets; the same idle
ticks that move live Zeek's clock move Suricata's, so flows time out while
the lab is quiet. Live Suricata times idle flows out sooner than upstream: an
idle UDP, ICMP or other flow after 60 s (upstream 300 s), an unanswered TCP
SYN after 30 s and a closed TCP connection after 10 s; an established TCP
connection keeps 600 s, since Suricata would not reassemble its stream again
after a timeout. The per-segment pass ends every flow at its segment's end,
so a live flow record spans what per-segment records split. Its memory caps
are below upstream's (flows 64 MiB, streams 64 MiB, reassembly 128 MiB, HTTP
64 MiB, defragmentation and hosts 16 MiB each) so the long-running process
stays bounded beside the per-segment Suricata in the 2 GiB container. It is
restarted at a segment boundary after 64 MiB of EVE output.

Coverage works as for Zeek, through Suricata's own coverage state: a segment
is covered once a delivery that began 75 s after it was streamed (longer than
Suricata takes to write the record of a flow that went idle: 60 s and the
flow manager's few seconds) delivered everything Suricata had written, or
once Suricata exited after its input ended and everything it wrote was
delivered. A segment Suricata crashed in, the segments a lagging Suricata
skipped, those whose records ingest had not taken, and every segment while
live Suricata is off (`SHAKERPROXY_SURICATA_LIVE=off`) go to the per-segment
pass, with its per-segment output budget. A Suricata that crashed never
wrote the flow records of the flows still open; analyzer health counts them
in `records_dropped`, beside the segments analyzed again
(`segments_reanalyzed`). Live Suricata replaces each flow's run-specific
`flow_id` with the deterministic one the per-segment pass derives (the
endpoints, transport and first record's time), fixed at the flow's first
record, so all its records share it and a retried delivery is the same
event. As with Zeek, an event delivered live and again by the per-segment
pass after a crash is not deduplicated: its payload differs (`pcap_cnt`,
and a flow's statistics where the flow spans segments). The handoff, not
the event IDs, keeps each segment delivered once.

Analyzers deliver a segment's events in batches (`POST
/v1/adapters/{zeek,suricata}/batch`, NDJSON, up to 256 events), and ingest
stores each batch with one round of disk syncs instead of two syncs per event.
On a virtual machine whose disk takes tens of milliseconds per sync, per-event
delivery managed about 2 events per second per analyzer (a busy segment's 124
Zeek and 192 Suricata records took 80 s and 105 s); batched, a segment's
events are stored in well under a second. The database drain wakes as soon as
the spool accepts events instead of polling once a second.

## Zeek coverage

The analyzer runs Zeek with ShakerProxy's site policy
(`apps/analyzer-worker/zeek/shakerproxy.zeek`). On top of Zeek's defaults (which
already include MQTT, QUIC, WebSocket, `weird.log` and `analyzer.log` for
protocol violations) it adds speculative and failed service names, Community
ID and MAC addresses to `conn.log`, `known_services.log`, and software
detection for HTTP, SSH and DHCP. Every added log is bounded per connection or
per host/service.

## Limits

- **No capture, no passive view.** Without a running capture only intercepted
  HTTPS, HTTP and DNS-over-HTTPS are visible.
- **Ports can lie.** `PORT_HEURISTIC` means "it used MQTT's port", not "it spoke
  MQTT". Treat it as a lead. `CARRIER_AND_PORT` means "it spoke TLS on DNS over
  TLS's port", not "it sent DNS".
- **Rolling back maps the new values.** Releases before 0.1.0-beta.43 refuse
  events with `UNKNOWN` visibility or `CARRIER_AND_PORT` evidence. Before
  `shakerproxy rollback` (or a failed update that puts such a release back)
  starts one, the installer rewrites them in bounded batches to `OPAQUE` and
  `PORT_HEURISTIC` and marks those events for re-projection, so the next
  upgrade classifies the last 30 days truthfully again (protocol columns and
  the [industrial projection](industrial-protocols.md) alike). A downgrade with
  `shakerproxy update --version <older>` runs the older installer, which
  cannot do this; use rollback.
- **The cloud summary is coarser.** The optional cloud connector's hourly
  protocol summary has no `CARRIER_AND_PORT` or `UNKNOWN`: carrier-and-port
  flows count as `PORT_HEURISTIC` and unknown security is sent as `OPAQUE`,
  so neither is ever reported there as confirmed or encrypted.
- **Encrypted is not decrypted.** QUIC, TLS that was not intercepted, SSH, VPNs
  and proprietary tunnels show who a device talks to, not what it says. QUIC
  cannot be intercepted; block UDP/443 so apps fall back to TCP.
- **Correlation is by 5-tuple and time.** NAT or a capture on a different
  interface than the interception path can prevent a passive flow from being
  matched to its interception event; it is then counted from both sides.
- **Flow records, not sessions.** Zeek may split a very long connection into
  several records; each counts as a flow.
- **Novelty depends on history.** `novel` compares with retained events only.
  Events stored before this feature are classified by a background backfill
  for the last 30 days; older history does not count.
- **Attribution.** Flows from addresses ShakerProxy cannot map to an inventory
  device (for example IPv6 without a lease) are `unattributed_flows`.
- **Interception flows carry no byte counts**, so coverage is dominated by
  captured traffic.
