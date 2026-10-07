# Traffic stream types

The live Traffic view, the events summary (`GET /api/v1/events/summary`) and
the MCP `traffic_summary` tool sort every event into one stream type. This is
the specification; three implementations follow it:

- Go: `ingest.StreamType` (`internal/ingest/stream_type.go`);
- PostgreSQL: `streamRules` in the same file, the rules below as SQL
  conditions. They build both `streamTypeSQL`, the CASE expression behind
  the summary's timeline and type counts, and the conditions the `type`
  field compiles to (see [Filtering by type](#filtering-by-type));
- web UI: `streamKind` with the blocked and encrypted-DNS rules of
  `streamLine` (`apps/web-ui/src/lib/liveTraffic.ts`).

`internal/ingest/testdata/stream_types.json` lists one event per rule with its
expected type. A Go unit test, a PostgreSQL integration test and a UI test
(`tests/ui/stream-types.test.mjs`) run every case, so the three cannot drift
apart.

The Live view's type chips are server queries on the `type` field (see
[Filtering by type](#filtering-by-type)), so they are proven against the same
cases: `TestPostgresStreamChipsSelectTheirOwnType` runs the default view's
query and each chip's through the query language and PostgreSQL, and every
row must sit under its own type's chip and no other (encrypted DNS under DNS
only, the router's own logs under Wi-Fi, Alerts, Discovery or Other). The
queries it runs are in `internal/ingest/testdata/stream_chip_queries.json`,
which the UI test keeps equal to what the Live view sends.

## Rules, in order

The first rule that matches decides.

| # | Type | Rule |
|---|---|---|
| 1 | blocked | ShakerProxy refused it: a lookup the DNS forwarder answered NXDOMAIN on purpose, or a connection the gateway rejected (`shakerproxy.blocked`) |
| 2 | wifi | An 802.11 management frame event from ShakerProxy's passive Wi-Fi monitor (HOST `wifi.*`: probe, auth, assoc, deauth, disassoc, beacon summary); see [Wi-Fi visibility](wifi-visibility.md) |
| 3 | dns | Encrypted DNS the classifier identified: app protocol `doh`, `dot` or `doq` |
| 4 | quic / tls / http / other | A connection the gateway reported as it opened (`shakerproxy.conn`): UDP to 443 or with a server name is QUIC, TCP to 443 or with a server name is TLS, TCP to 80 is HTTP, anything else is other |
| 5 | alert | A Suricata alert, or a transition of ShakerProxy's own detector (HOST `shakerproxy.detection.*`: an unapproved DHCP server or router advertisement, gateway spoofing, clock drift, capture loss, resource pressure); see [native detections](native-detections.md) |
| 6 | industrial | An industrial protocol record (it has an industrial projection: Modbus, DNP3, EtherNet/IP and CIP, S7comm, OPC UA), or traffic an analyzer, not just its port, identified as an industrial protocol (`protocol_category` industrial with `ANALYZER` evidence); see [industrial protocols](industrial-protocols.md) |
| 7 | discovery | Local discovery: destination port 5353 (mDNS), 5355 (LLMNR), 1900 (SSDP), 137/138 (NetBIOS), 67/68 (DHCP), 546/547 (DHCPv6), 3702 (WS-Discovery) or 10001 (Ubiquiti); a `zeek.dhcp` record; or the protocol classifier's `local-discovery` category or a discovery/DHCP app protocol |
| 8 | dns | A name lookup (`dns_query` set) |
| 9 | http | A web request (method or host set, or an `*.http` record) |
| 10 | quic | A QUIC record, or a UDP connection with a server name |
| 11 | tls | A connection with a server name, or a TLS handshake record |
| 12 | other | Everything else: unnamed TCP/UDP, ICMP, and other protocols, including traffic only a port suggests is industrial |

Events from a router's own logs (source `NETWORK_GEAR`) are sorted right after
rule 1: a Wi-Fi client log is wifi, an IDS alert is alert, a DHCP lease is
discovery, anything else is other; see [network gear logs](network-gear-logs.md).

## Filtering by type

The query language's `type` field selects events by this classification:
`type:alert`, `type:dns OR type:blocked`, `NOT type:other`. It is exactly what
the summary counts, so the Live view's type chips filter with it and a chip
always lists the events its count counts. The DNS chip holds `dns` and
`blocked`; every other chip is its own type. The analyzer duplicates below
have no type: `type:*` is every event the summary counts (the same events as
"All"), and `NOT type:*` only the duplicates.

`type:x` does not compute the CASE for every stored event: it compiles to the
rules that give type `x`, each with the rules before it ruled out, as
conditions on stored columns. That selects exactly the events the CASE gives
`x` (`TestPostgresStreamTypePredicatesMatchTheClassification` checks every
type, negated too, against the CASE), and lets PostgreSQL estimate it and use
an index: a common type reads the newest events in time order until it has a
page, and Wi-Fi, alerts, web requests and industrial traffic, usually a small
share of the history, read their own partial index. On 2,000,000 stored events each chip
answers in well under a second.

## Analyzer duplicates

The analyzers record some traffic more than once: Suricata's flow and
application-layer records next to Zeek's, Zeek's TLS and QUIC handshakes next
to their connection record, Zeek's bookkeeping logs, and the connection
records of DNS and mDNS lookups (the lookup itself is the event). The summary
always leaves those out with the same filter the UI's "All" uses
(`EVERYTHING_QUERY`):

```text
NOT (kind:suricata.flow OR kind:suricata.dns OR kind:suricata.mdns OR kind:suricata.quic
  OR kind:suricata.tls OR kind:suricata.http OR kind:suricata.anomaly OR kind:zeek.ssl
  OR kind:zeek.quic OR kind:zeek.weird OR kind:zeek.known_services OR kind:zeek.software
  OR kind:zeek.reporter OR (kind:zeek.conn AND (dst.port:53 OR dst.port:5353 OR dst.port:5355)))
```

The UI also hides a Zeek DNS record when the DNS forwarder reported the same
lookup within five seconds; the summary does not, so a capture running next
to the forwarder can count such a lookup twice.

## Network chatter

On a busy LAN most events are network chatter: routers announcing themselves
(UniFi discovery), broadcasts and multicast from other networks, IPv6
listener reports. On the test VM it was 4,574 of 5,142 events in an hour. The
Live view hides chatter by default and says how much it hid ("Network chatter
hidden 4.6k"); one click shows it, dimmed. Chatter is discovery, link-local
multicast or IGMP that no lab device sent:

```text
((protocol.category:local-discovery OR dst.ip:ff02::/16 OR dst.ip:224.0.0.0/4) AND NOT device.id:*)
```

A lab device's own mDNS or DHCP stays in the view. Chatter is hidden whichever
types are chosen (multicast chatter can also be Other), so a chip lists what
its count counts; with a client chosen there is none to hide. The choice is in
the address (`traffic_chatter=shown`), and **Clear filters** returns to the
default: every device and type, live, no search, chatter hidden.

## The same view in the CLI and MCP

`shakerproxy watch`, `shakerproxy search` and the MCP traffic tools
(`search_traffic`, `device_activity`, `follow_traffic`, `dns_lookups`) list
what the Live view lists by default: they send the analyzer-duplicate filter
and the chatter filter above (`ingest.DefaultViewFilter`; a device's view
leaves the chatter filter out, as the Live view does for a chosen client), and
fold each page as the Live view folds it (`agentapi.FoldEvents`): the Zeek
copy of a forwarder lookup, the connection records of DNS lookups, and the
later pieces of a long connection, whose bytes the first piece then carries.
`--all` and `all: true` list every stored record; a query that names `kind:`
is sent as written.
