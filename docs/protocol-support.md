# Protocol support matrix

What ShakerProxy sees of each kind of traffic, and how that depends on the way
a device reaches it. "Recorded" means the packets are in the automatic
recording (see [capture and storage](capture-and-storage.md)), "named" means
ShakerProxy says what the traffic is, "live" means it reaches Traffic before
the recording's segment closes, and "content" says what can be read inside it.

The [visibility coverage check](testing/visibility-coverage.md) proves the
rows on the appliance itself: each row lists the coverage probes that send
that traffic through the real capture and analyzers. `make registry-check`
(and `go test ./tools/registrycheck`) fails when a probe or a topology is
missing here.

## Routing modes

Each routed mode gets the same recording, DNS forwarding, live connection
events and per-device controls for the traffic that crosses ShakerProxy. The
modes differ in which traffic crosses it. The passive mirror crosses nothing:
it records and analyzes a copy, so it has the recording, live analysis and
device discovery, and none of the forwarding, live connection events or
controls.

| Mode | Plan | How a device joins | What crosses ShakerProxy | Ways around it (coverage findings) |
|---|---|---|---|---|
| Routed lab | `TWO_NIC`, `THREE_INTERFACE`, `VLAN_TRUNK`, `EXISTING_ROUTED_VLAN`, `ADVANCED_CUSTOM` | Plugs into the lab port or VLAN and gets its address from ShakerProxy's DHCP | Everything the device sends off the lab segment | Another DHCP server or IPv6 router on the lab segment; two devices on one lab switch talk directly |
| Wi-Fi access point | A `WIFI_AP` interface in a routed lab or an inline bridge ([guide](wifi-access-point.md)) | Joins ShakerProxy's Wi-Fi | As for the lab it belongs to; on a bridge, also traffic between two Wi-Fi devices | A Wi-Fi-only lab: two Wi-Fi devices talk inside the access point |
| Single-arm | `SINGLE_ARM` | Is set by hand to use ShakerProxy as its gateway and DNS server | That device's traffic, plus every device's multicast and broadcast on the shared network (mDNS, SSDP, DHCP, router advertisements) | Devices that keep the router's DHCP; unicast between two devices; IPv6 unless it is off on the device |
| Inline bridge | `TRANSPARENT_BRIDGE` ([guide](bridge-mode.md)) | Is cabled through ShakerProxy; keeps the router's DHCP, gateway and DNS | Every frame between the device port and the router side, DHCP and IPv6 router advertisements included | Two devices behind one switch on the device port |
| WireGuard VPN | VPN mode, on its own or beside any of the above ([guide](vpn-mode.md)) | Scans a QR code in the WireGuard app | The device's entire connection, from any network, in its own "VPN traffic" recording | None for the tunnel; local discovery on the device's own Wi-Fi does not enter it |
| Passive mirror | `PASSIVE_SENSOR` ([below](#passive-mirror)) | Nothing on the device: the switch's mirror (SPAN) session or a TAP copies its port or VLAN to ShakerProxy's mirror port | Nothing crosses it. Everything the switch copies is recorded (VLAN tags kept) and analyzed by Zeek (live) and Suricata, and devices are found by MAC from ARP, IPv6 neighbor discovery and DHCP. No DNS answers, no live connection events (no traffic is routed), no HTTPS decryption, no blocking or device controls | Ports and VLANs the mirror session leaves out; traffic between two devices behind one switch port; a switch that drops copies under load |

### Passive mirror

A confirmed passive plan puts the gateway in observing mode
(`PASSIVE_OBSERVING` in `shakerproxy status`, the API and MCP). The mirror
port is silenced and opened: up, ARP and IPv6 off, no address and no route,
so the host sends nothing on it (the netlab proof checks its TX counter and
the far side), and promiscuous, so it receives frames addressed to other
hosts. The automatic recording records it like a lab interface, with every
frame and no filter; live Zeek and Suricata analyze it as they do the lab
recording, and gatewayd learns each device's MAC and address from the ARP,
neighbor discovery and DHCP acknowledgements in the recording, so Traffic,
Devices and reports name the devices without ShakerProxy's DHCP (with
automatic recording turned off, no devices are learned). Forwarding, the
firewall, NAT, DHCP and router advertisements are never touched. Emergency
bypass has nothing to bypass while observing: turning it on keeps the mirror
recorded. Visibility health adds a *Mirror port* signal: link, packets seen,
kernel drops, devices learned, live analysis lag and anything else sending on
the port.

DNS sent over IPv6 is answered by ShakerProxy where the lab routes IPv6 (see
[IPv6 in the lab](ipv6.md)) and, on an inline bridge, when ShakerProxy has an
IPv6 address on the bridge; otherwise it is recorded but not answered.

## Per protocol

| Traffic | Coverage probes | Named as | Live | Content |
|---|---|---|---|---|
| Plain DNS (UDP/TCP 53) | `dns-gateway`, `dns-direct`, `dns-ipv6` | `dns`: name, type, answer code and answers | At once: the forwarder records each lookup it answers (`shakerproxy.dns`); other lookups within about a second from live analysis | Names and answers |
| DNS over TLS | `dot` | `dot` (TCP 853) | Connection within about a second | Encrypted. *Block encrypted DNS* refuses it so devices fall back to plain DNS |
| DNS over HTTPS | `doh` | `doh`, from the resolver catalog by server name or address | Connection within about a second; a decrypted answer at once (`doh_lookup`) | Encrypted. When HTTPS decryption covers the device, each answer is decoded into a DNS lookup "via DoH (decrypted)" with name, type, answer code and answers ([TLS interception](tls-interception.md#dns-over-https-that-shakerproxy-decrypts)). *Block encrypted DNS* refuses the catalog's resolvers and their names |
| DNS over QUIC | `doq` | `doq` (UDP 853) | Connection within about a second | Encrypted. *Block encrypted DNS* refuses it |
| HTTP | `http`, `http-ipv6` | `http`: method, host, path, status | Connection at once; request within about a second | Headers and the start of each body, read from the recording (credentials masked) |
| HTTPS / TLS | `https`, `https-ipv6` | `tls`: server name, version, certificate | Connection at once; server name within about a second | Encrypted, unless HTTPS decryption is on for a device that trusts the ShakerProxy CA ([TLS interception](tls-interception.md)); apps that pin fail or are passed through. A ClientHello using ECH shows only the provider's public name: marked "server name hidden (ECH)" and counted as opaque ([ECH](tls-interception.md#encrypted-client-hello-ech)) |
| WebSocket (`wss://`, and `ws://` with `intercept_http`) | No probe: the add-on's hook tests (`make test-mitm-image`) | `http`: `websocket_session` when a socket opens (host, path, subprotocol, extensions) and closes (close code, who closed it, totals), `websocket_messages` for what it carries ([TLS interception](tls-interception.md#websockets)) | Opening at once; the first 16 messages within about a second; then counts every 10 seconds | On decrypted connections only: direction, type, size and time of each listed message, and with content retention on a 256-byte text preview with credentials masked or a 16-byte hex prefix of a binary message. Ping and pong frames are not counted. On a connection that is not decrypted the socket is the TLS connection it runs in |
| QUIC / HTTP/3 | `quic`, `quic-ipv6` | `quic`: server name, ALPN, version | Connection at once; server name within about a second | Never decrypted. Blocked for decrypted devices so they fall back to TCP, unless `allow_quic` is on |
| TCP, any other port | `tcp-unusual-port`, `tcp-ipv6` | The [protocol catalog](protocol-discovery.md) (MQTT, RTSP, Modbus, …) or `other`, with bytes each way | Connection at once | What the protocol carries in cleartext |
| UDP, any other port | `udp-unusual-port`, `udp-ipv6` | As for TCP | Connection at once | What the protocol carries in cleartext |
| ICMP / ICMPv6 | `icmp`, `icmpv6` | `icmp`, `icmpv6`; IPv6 router advertisements feed the IPv6 finding | Echo at once; the flow when it goes idle (30 s) | Type and code |
| SSH | `ssh` | `ssh`: client and server software | Connection at once | Encrypted, never decrypted |
| NTP | `ntp` | `ntp` | Connection at once; NTP record within about a second | Cleartext |
| mDNS / Bonjour | `mdns` | `mdns` | Within seconds from live analysis (multicast is not a connection) | Names and services announced. Not seen for VPN devices |
| SSDP / UPnP | `ssdp` | `ssdp` | Within seconds from live analysis | Search and announcement headers. Not seen for VPN devices |
| Industrial: Modbus, DNP3, EtherNet/IP and CIP, S7comm and S7comm-plus, OPC UA, BACnet/IP, IEC 60870-5-104 | No probe: the OT recordings and `make ot-smoke` ([industrial protocols](industrial-protocols.md#fixtures-and-proof)) | The industrial projection: operation, whether it changes state, the device's answer; Modbus and DNP3 always, the others with the OT analyzer profile, otherwise port labels | Connection at once where traffic is routed; records within about a second from live analysis (live Zeek uses the profile) | What a device is asked to do and how it answers, never process values. OPC UA is cleartext unless its secure channel was opened with SignAndEncrypt; the visibility is the observed security mode, `UNKNOWN` when none was seen |
| DHCPv4 | No probe | Lease evidence: hostname, vendor, MAC ([device inventory](device-inventory.md)) | Device list on the next inventory refresh | Cleartext. ShakerProxy's own leases in routed labs; the router's are recorded in single-arm and bridge labs |
| Wi-Fi management frames | No probe: the virtual test lab has no radio | `wifi.*`: networks searched for, joins, roaming, disconnect reasons ([Wi-Fi visibility](wifi-visibility.md)) | Within seconds | Frame metadata only; needs a monitor-capable adapter |

"At once" rows come from the gateway itself: the DNS forwarder and the
kernel's connection tracking report a lookup or a new connection within about a
second, whether or not the recording has been analyzed (see
[connections as they open](dns-forwarding.md#connections-as-they-open)).
"Within about a second" rows come from Zeek following the automatic lab and
VPN recordings live, and Suricata alerts within a few seconds from live
Suricata ([live Suricata](protocol-discovery.md#live-suricata)); manual
captures arrive when each 10-second segment is analyzed (see
[live analysis](protocol-discovery.md#live-analysis-of-the-lab-recording)).

## What is never readable

- QUIC and HTTP/3 content, DTLS, SSH, and TLS that a device pins, protects
  with mutual TLS or ECH, or sends to a private destination while
  `intercept_private_destinations` is off.
- Encrypted DNS lookups while *Block encrypted DNS* is off: the resolver is
  named (`doh`, `dot`, `doq`), the names looked up are not, except DoH that
  ShakerProxy decrypts. Firefox's default DoH and iCloud Private Relay stay off
  on the lab with the canary setting `signal-opt-out`
  ([DNS forwarding](dns-forwarding.md#encrypted-dns-canaries-firefox-icloud-private-relay)).
- Traffic inside a VPN or tunnel the device runs itself.
- Anything that does not cross ShakerProxy (the "ways around it" column);
  the coverage check and `lab_routing` name the devices this applies to.

## Proof

- `tests/netlab/coverage-probes.sh` sends every probe above through network
  namespaces and the pinned Zeek and judges the result with the production
  evaluator; `shakerproxy coverage run` does the same on an appliance.
- `tests/netlab/run.sh`, `single-arm.sh`, `bridge-mode.sh`, `vpn-mode.sh`,
  `ipv6-lab.sh` and `dns-forwarding.sh` prove each routing mode's packet path,
  DNS redirect and connection reporting against the real kernel (CI job
  `netlab`); `bridge-ap-hwsim.sh` and `wifi-hwsim.sh` prove the Wi-Fi paths
  with simulated radios (CI job `netlab-wifi`).
- `tests/netlab/mitmproxy-proof.sh` proves HTTPS decryption, pass-through and
  rejection with the shipped addon.
- Physical-device certification for each mode is still pending; see the
  [support matrix](../schemas/support-matrix.yaml).
