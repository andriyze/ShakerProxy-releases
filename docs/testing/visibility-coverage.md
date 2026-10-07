# Visibility coverage check

ShakerProxy's goal is complete visibility of every device connection. The visibility coverage
check proves it one traffic type at a time and names every gap. It is both a release test and a
button a tester can press:

- **UI:** System → *What ShakerProxy is proven to see* → **Run coverage check**
- **CLI:** `shakerproxy coverage` (last result and bypass findings), `shakerproxy coverage run --password-file FILE`
- **API:** `GET /api/v1/coverage` (session or `system:read` token), `POST /api/v1/coverage/runs` (administrator session, recent password)
- **MCP:** the read-only `visibility_coverage` tool

## What it proves

Each probe is sent once from a virtual client and must show up in stored events:

| Probe | Sent | Passes when |
|---|---|---|
| DNS via ShakerProxy | UDP 53 to the client's gateway, answered by ShakerProxy's DNS forwarder | A lookup for the run's unique name is stored |
| DNS to another resolver | UDP 53 straight to an outside resolver | The run's unique name is stored from the recording |
| DNS over TLS | TLS to TCP 853 | The connection is stored and named `dot` |
| DNS over HTTPS | HTTPS to `cloudflare-dns.com` | The connection is stored and named `doh` |
| DNS over QUIC | A QUIC Initial with ALPN `doq` to UDP 853 | The datagram is stored and named `doq` |
| HTTP | A cleartext GET with a unique path | The path is stored |
| HTTPS / TLS | A TLS handshake with a unique server name | The server name is stored |
| QUIC / HTTP/3 | A real QUIC v1 Initial with a unique server name | The server name is stored |
| TCP / UDP, unusual port | TCP 9998 / UDP 9997 | The connection is stored |
| ICMP | Two echo requests | Stored and named `icmp` |
| SSH | An SSH version exchange | Stored and named `ssh` |
| NTP | An NTP client request | Stored and named `ntp` |
| mDNS (AirPlay discovery) | A PTR query for `_airplay._tcp.local` to 224.0.0.251 | Stored and named `mdns` |
| SSDP (casting discovery) | An `M-SEARCH` to 239.255.255.250:1900 | Stored and named `ssdp` |
| DNS over IPv6 (AAAA) | An AAAA lookup over IPv6 to the gateway's lab address, answered by ShakerProxy's DNS forwarder | A lookup for the run's IPv6 name is stored |
| HTTP over IPv6 | A cleartext GET with a unique IPv6 path | The path is stored |
| HTTPS / TLS over IPv6 | A TLS handshake with a unique IPv6 server name | The server name is stored |
| QUIC over IPv6 | A QUIC v1 Initial with a unique IPv6 server name | The server name is stored |
| TCP / UDP over IPv6, unusual port | TCP 9998 / UDP 9997 over IPv6 | The connection is stored |
| ICMPv6 | Two ICMPv6 echo requests | Stored and named `icmpv6` |
| Wi-Fi radio | Not probed: the virtual test lab has no radio. Reports whether [Wi-Fi visibility](../wifi-visibility.md) is listening and its events are stored | PASS while the monitor and its frame parser run and a Wi-Fi event was stored in the last 24 hours; SKIP with the reason otherwise, including a monitor that listens with nothing stored to prove it |

The IPv6 probes carry markers of their own and are judged only by events from the client's IPv6 address, so IPv4
evidence can't pass an IPv6 probe or the other way round. If the appliance has IPv6 turned off, the IPv6 rows are
skipped with that reason. If the lab's IPv6 doesn't work, they fail with the reason; the IPv4 rows still run.

Each result also records:

- **Event kinds:** which events showed the probe, such as `zeek.conn` or `shakerproxy.dns`.
- **Delay:** how long after sending the first event was stored, through the offline analysis of the probes'
  own recording. Live analysis of the lab recording is faster; its lag is in visibility health.
- **What is missing:** for a failure, "not recorded" or "recorded but not identified as SSH".

Names are unique per run and live under `.coverage.shakerproxy.test`, which never resolves on the Internet. An
earlier run, or other traffic, can't make a check pass.

## How the probes travel the real path

The check never writes events itself. It only reads back what production stored.

1. **Prepare:** control-api asks the test lab (`shakerproxy-testlabd`) to build the
   [virtual test lab](virtual-test-lab.md), plus the coverage endpoints on the virtual target (SSH banner,
   NTP, TCP/UDP echo, DoH). The virtual clients' DNS for their gateway is redirected to ShakerProxy's DNS
   forwarder, and the forwarder accepts the test lab's `198.18.240.0/24` clients. The redirect lives in the test lab's
   own nftables table; one comment-tagged `INPUT` rule lets the bridge reach the forwarder.
   The lab then gets IPv6 from `fd8a:6c1e:4b37::/48`, routed by its own `lgtest-router` namespace, so the
   host's IPv6 forwarding never changes. DNS to the gateway's IPv6 lab address is redirected the same way. The
   forwarder accepts unique-local clients. Comment-tagged `ip6tables` rules accept the forwarder port and frames
   bridged within each lab bridge, which Docker's `br_netfilter` sends through `FORWARD`.
2. **Record:** control-api starts a normal capture through gatewayd with `coverage_lab: true`. gatewayd
   records the virtual-client bridge (`lgtest-client`) instead of the lab interface, and refuses if that bridge
   does not exist. Like any manual capture, it runs beside the automatic lab recording, which keeps
   running.
3. **Probe:** the test lab runs the probes inside the `lgtest-normal` namespace.
4. **Stop and clean up:** the capture stops and is analyzed by the real Zeek and Suricata workers. The test lab
   removes every `lgtest-` object and its rules. If cleanup never arrives, a 4-minute lease removes them.
   The configuration lock is held only while objects change, so the capture can start in between.
5. **Read back:** control-api queries the stored events with the Traffic page's own query until every probe
   passes or 150 seconds pass:

   ```text
   (capture.id:<run capture> OR (source:HOST AND (src.ip:198.18.240.0/24 OR src.ip:fd8a:6c1e:4b37:f0::/64))) AND time>=<start>
   ```

## Ways around ShakerProxy (routing inspection)

The inspection runs on every `GET /api/v1/coverage`. It judges the live configuration from gatewayd's
managed state, host inspection and DNS policy, plus the last 24 hours of recorded traffic:

| Finding | GAP when |
|---|---|
| Devices bypassing ShakerProxy | A device seen on the lab network in the last 10 minutes sends its traffic straight to the router instead of through ShakerProxy, typically a single-arm device that took the router's DHCP. The fix names ShakerProxy's and the router's addresses. Left out when lab presence could not be checked |
| IPv6 | Another router advertises IPv6: Zeek recorded an ICMPv6 router advertisement (`protocol:icmp AND src.port:134`) from an address that is not one of the appliance's own, link-local included. This is a GAP whether or not ShakerProxy routes IPv6, since devices may pick the other router. Also a GAP when the lab interface has IPv6 that ShakerProxy did not configure while the lab does not route IPv6. UNKNOWN when recorded traffic could not be searched or the lab is not being recorded now; when the lab recording began less than 24 hours ago, OK says since when. ShakerProxy's own addresses are left out in the search itself, so its own advertisements cannot hide another router's. Always OK on an inline bridge, where the router's advertisements cross ShakerProxy |
| Address assignment | Another DHCP server answered on the lab network, or the lab is single-arm (the network's router hands out addresses, so only devices set by hand use ShakerProxy). UNKNOWN, like IPv6, when recorded traffic could not be searched or the lab is not being recorded. OK on an inline bridge, where the router's DHCP crosses ShakerProxy |
| Device-to-device traffic | Single-arm lab (devices talk directly), and a Wi-Fi-only lab (two Wi-Fi devices talk inside the access point); UNKNOWN for wired two-port labs; OK when ShakerProxy's Wi-Fi access point is on a bridge (lab bridge or inline bridge), which sends traffic between Wi-Fi devices through ShakerProxy, and on an inline bridge for traffic between the device port and the router's side |
| Encrypted DNS | DoT, DoQ or known DoH is not blocked by the DNS policy. This is the default: *Block encrypted DNS* is off, so the resolver is named but not the names looked up |
| DNS sent to other resolvers | Plain DNS to other resolvers is not redirected to ShakerProxy (only when *Force plain DNS* was turned off) |
| Local discovery | Never. Every lab records multicast discovery: a single-arm recording keeps every device's mDNS, SSDP, LLMNR, NetBIOS and DHCP on the shared network, and an inline bridge records every multicast frame crossing it. Unicast between two devices is the device-to-device finding |
| VPN devices | Never while VPN mode is on: a full tunnel has no way around ShakerProxy. UNKNOWN until a device is added |
| Device discovery | A source of device evidence failed on the last inventory refresh: ShakerProxy's DHCP lease file could not be used (or is missing or unreadable in a lab where ShakerProxy hands out addresses), the gateway's ARP and NDP tables failed validation, or the observed DHCP or lab presence could not be read. UNKNOWN when only some lease records were skipped. The details are `device_discovery` in the overview |
| Not routing | No confirmed lab routes traffic and VPN mode is off |

## Gaps found on the current test lab

These are on the Proxmox VM: a single-arm lab on 192.168.10.0/24, a home network without IPv6, and the DNS
policy observing.

The routing inspection follows from that configuration:

- **GAP, address assignment:** only devices set by hand to use 192.168.10.177 go through ShakerProxy.
- **GAP, device-to-device traffic:** AirPlay, casting and local SSH between lab devices are invisible.
- **GAP, encrypted DNS:** DoT, DoQ and DoH are allowed, so a phone using Private DNS hides its lookups.
- **GAP, DNS sent to other resolvers:** only DNS sent to the gateway is redirected.
- **OK, local discovery:** the single-arm recording keeps every device's mDNS and SSDP on the shared network
  (earlier releases left it out, and this was a GAP).
- **OK, IPv6:** no IPv6 router on that network.

### Probe results with the real analyzer

These results come from `tests/netlab/coverage-probes.sh` run in a privileged Linux container with
`SHAKERPROXY_COVERAGE_PCAP` set:

1. The probes travel real network namespaces through a forwarding gateway.
2. The pinned Zeek 8.2.1 image analyzes the recording with ShakerProxy's `shakerproxy.zeek` policy.
3. Each log line is normalized and projected by ingest's own `NormalizeZeekJSON` and `ProjectEvent`.
4. The coverage evaluator judges the result.

Out of scope for this run: dnsd, Suricata, PostgreSQL and the capture worker, which only the appliance run
covers.

| Result | Traffic types |
|---|---|
| PASS | DNS via ShakerProxy and to another resolver, DoT (`dot`), DoQ (`doq`), HTTP, HTTPS/TLS, QUIC, TCP and UDP on unusual ports, ICMP, SSH, NTP, mDNS (`mdns`), SSDP (`ssdp`) |
| FAIL, fixed since | **DNS over HTTPS**: recorded (`zeek.conn`, `zeek.ssl`, server name `cloudflare-dns.com`) but classified `tls`, because the protocol classifier named DoH only when an analyzer reported it. Ingest now names a connection to a resolver in the catalog `doh`, by server name or address (`internal/ingest/doh_projection_test.go`). |
| SKIP | IPv6: the virtual lab was IPv4-only at the time |

The IPv6 probes were later proven by running the real `shakerproxy-testlabd` in a privileged container (Linux 7.0,
`br_netfilter` loaded, Docker-like `FORWARD DROP` and an IPv6 `INPUT` drop on the forwarder port):

- prepare, probe and cleanup over its socket all worked;
- all 22 probes were sent and answered, and the AAAA lookup reached the forwarder from `fd8a:6c1e:4b37:f0::10`;
- cleanup left no `lgtest-` objects, the same firewall rules and the same `net.ipv6.conf.all.forwarding`.

Zeek 8.2.1 recorded every IPv6 probe from the bridge capture:

- HTTP with its unique path;
- TLS and QUIC with their unique server names;
- TCP 9998 and UDP 9997;
- ICMPv6 echo, which Zeek logs as `proto=icmp` with the type as the originator port (ingest names it `icmpv6`).

A router advertisement appears the same way, as `proto=icmp`, `id.orig_p=134`, from the router's link-local address.

On the appliance, the delay column adds:

- the 10-second probe recording;
- Zeek and Suricata analysis;
- per-event delivery to ingestd.

DNS through the forwarder appears within seconds.

To run it on the appliance after installing a release that includes it:

```sh
shakerproxy coverage run --password-file ~/admin.pw
shakerproxy coverage
```

## Limitations

- **Not a phone or TV:** the probes come from Linux namespaces on the appliance. They prove what the pipeline
  records, not how a particular phone or TV behaves.
- **No device attribution:** virtual clients are not lab devices, so their events are not attributed to a device;
  `attributed` is reported, but doesn't affect the result.
- **IPv6 inside the appliance:** the IPv6 probes use a private unique-local prefix. They prove ShakerProxy records
  IPv6, not that the lab network routes IPv6 through ShakerProxy; the IPv6 routing finding covers that.
- **Not the lab's own path:** the probes travel the test lab's bridge and its own capture, analyzed offline. They do
  not pass through the lab interface, the automatic lab recording, live analysis, or the single-arm and access-point
  filters. The report's visibility health covers that path: the recording, live events and analysis, the analyzers
  and storage.
