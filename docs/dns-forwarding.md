# DNS forwarding and encrypted-DNS policy

ShakerProxy can answer lab devices' DNS itself. That serves two purposes:

- **Force plain DNS through ShakerProxy** (`ENFORCE_LOCAL`): every lab client's
  plain DNS is answered by ShakerProxy, which forwards it to the upstream servers
  you choose, so lookups are visible and cannot silently go elsewhere.
- **Block a domain for one device**: ShakerProxy answers NXDOMAIN ("name does not
  exist") for the names you block, and their subdomains, for that device only.
  See [device-testing-quickstart.md](device-testing-quickstart.md).

Both are installed-host capabilities. They need a confirmed routed or
single-arm network plan and are absent from the safe development profile.

## See every lookup

Two switches once a lab is confirmed (DNS & HTTPS page, `shakerproxy dns`,
`GET/PUT /api/v1/dns-visibility`, MCP `dns_visibility`). Forcing plain DNS is
**on by default**; blocking encrypted DNS is **off by default**: encrypted DNS
is identified and labelled DoH, DoT or DoQ in Traffic (`proto:doh`,
`proto:dot`, `proto:doq`) so testers see a device using it, and blocking it is
a choice for when the lookups themselves matter.

- **Force plain DNS through ShakerProxy**: every lab client's UDP/TCP port-53
  DNS, to any resolver (8.8.8.8 included), is answered by `shakerproxy-dnsd`.
  Plain DNS is never blocked. Without policy upstreams the host's resolvers
  are used.
- **Block encrypted DNS** (off by default): DNS over TLS/QUIC (port 853, any destination) and
  TCP/UDP 443 to the catalog's DNS-over-HTTPS resolver addresses (Cloudflare,
  Google, Quad9, OpenDNS, AdGuard, NextDNS, CleanBrowsing, Mullvad, Control D,
  DNS.SB, AliDNS, DNSPod, Yandex) are rejected, and `shakerproxy-dnsd` answers
  NXDOMAIN for their hostnames (with subdomains) and for the opt-out canaries
  `use-application-dns.net` (Firefox) and `mask.icloud.com`,
  `mask-h2.icloud.com` (iCloud Private Relay). Devices fall back to plain DNS.
  Android Private DNS set to a specific provider loses internet while this is
  on: set it to Automatic or Off.

Every blocked attempt appears in Traffic: refused names as `shakerproxy.dns`
lookups, refused connections as `shakerproxy.blocked` events (gatewayd reads
the block rules' NFLOG group 853, at most one event per client, destination
and reason a minute). Both carry `blocked` and `blocked_reason`.
DNS-over-HTTPS connections that are not blocked are classified as
`app.protocol:doh` (catalog hostname by TLS server name or looked-up name, or
a catalog resolver address on 443).

Migration: an installation still on the untouched observe-only default
(revision 1, never changed) moves to these defaults when gatewayd starts. A
policy an administrator applied is never changed.

The resolver list is `BuiltinCatalog` in `internal/trafficpolicy/catalog.go`:
add a provider there with its documented addresses, hostnames and source URL,
bump `BuiltinCatalogRevision`, and regenerate `apps/mitmproxy/resolvers.json`
(the interception proxy's DoH hostnames) with
`go test ./internal/trafficpolicy -run TestMitmproxyResolverCatalogIsGenerated -update-mitmproxy-catalog`;
the same test fails while the two differ. Like dnsd, the proxy treats each
catalog name as covering its subdomains.

## Packet path

`shakerproxy-gatewayd` owns the revisioned policy and its fixed `iptables` and
`ip6tables` chains on the confirmed lab interface (wired port, Wi-Fi access
point, or the `lgbr0` bridge of both). It redirects client UDP/TCP port 53 to
the unprivileged `shakerproxy-dnsd` listener on port 1053:

- queries to ShakerProxy's own lab address (the usual DHCP-provided resolver,
  and the VPN gateway for VPN devices) are always redirected, from their own
  chain, `SHAKERPROXY-LAB-DNS` (see [When something fails](#when-something-fails));
- queries to resolvers outside the lab are redirected by the policy;
- DNS between two lab devices is left alone, including on a bridged lab;
- for `ENFORCE_LOCAL`, the whole lab is redirected; for domain blocking, only
  the device, matched by MAC address (falling back to its current IPs); DNS
  over TLS and QUIC (port 853) is also rejected for that device, and while
  **Block encrypted DNS** is off the forwarder refuses that device the
  catalog's DNS-over-HTTPS hostnames and the opt-out canaries, so it falls
  back to plain DNS.

`shakerproxy-dnsd` listens on IPv4 and IPv6. Port 1053 is dropped on every
interface except loopback and the lab segment, in both families, and the lab
accept rule only matches queries ShakerProxy itself redirected. As a second
layer, the forwarder ignores queries from anything but loopback, private
(RFC 1918, ULA), CGNAT and link-local addresses and the lab prefixes the
gateway publishes, so a missing firewall rule cannot turn it into an open
resolver. IPv6 redirects of DNS sent to other resolvers are installed only
when the lab routes IPv6 and the gateway has confirmed the forwarder answers
on `::1`. DNS sent to ShakerProxy's own lab IPv6 address is answered whenever
the lab routes IPv6: nothing else would answer it.

The forwarder reads the runtime document the gateway publishes at
`/var/lib/shakerproxy/traffic/policy.json` (the same file mitmproxy reads; the
cloud connector writes its own snapshot there when it manages the policy). It uses:

- the policy's upstream servers when `ENFORCE_LOCAL` lists them;
- otherwise the host's resolver: `SHAKERPROXY_DNS_FALLBACK_UPSTREAMS` if set, else
  the nameservers in `/run/systemd/resolve/resolv.conf` or `/etc/resolv.conf`
  (the systemd-resolved stub at 127.0.0.53 is fine; the forwarder runs on the
  host). This is how per-device domain blocking and cloud-managed DNS
  redirection resolve names.

Upstreams are tried in health order. A silent upstream is hedged by the next
one after a quarter of the timeout (at most 500 ms) and a failing one is
replaced immediately. An upstream that fails, or is still silent when another
answers or the timeout ends, is tried last for 30 seconds, doubled for each
further strike up to 4 minutes, and an answer clears it, so one dead or
blackholed resolver no longer delays lookups. Failed lookups are logged at
most once a minute per kind (upstream failure, unreadable query, concurrency
limit), with the number not logged since.

The policy and the forwarder check upstreams with the same function
(`trafficpolicy.NormalizeDNSUpstream`): `IP:53`, unicast, not loopback, and
not link-local IPv6 (the forwarder's sandbox cannot name the interface such an
address needs; list no upstream and the host's own resolvers, which reach a
link-local router, answer). Releases up to 0.1.0-beta.39 accepted a
link-local IPv6 upstream and then answered every lookup with SERVFAIL; such a
stored policy now loads without it, gatewayd logs that once, and the next
change saves the policy without it.

If the forwarder cannot use a runtime document anyway, it keeps answering with
the last one it accepted (before any, as a plain forwarder to the host's
resolvers that blocks nothing), logs why once, and reports it. gatewayd asks
the forwarder after every publish, with the CHAOS TXT query
`status.shakerproxy-dnsd` on 127.0.0.1:1053 (answered for loopback only, never
recorded), and installs the policy's DNS redirects only once the forwarder
answers with the revision just published; otherwise the apply fails with the
forwarder's reason and the lab fails open. Ask it yourself with
`dig @127.0.0.1 -p 1053 CH TXT status.shakerproxy-dnsd`.

## Lookups in Traffic

Every query the forwarder answers for a lab device appears in Traffic and in
the device report as a DNS lookup (kind `shakerproxy.dns`), whether or not a
capture is running: the name, record type, outcome (`NOERROR`, `NXDOMAIN`,
and so on, including names blocked for the device), and the A, AAAA and CNAME
answers with their TTLs. The device is the one that held the client address at
the time, as for captured traffic. A name with bytes other than letters,
digits, `-`, `_` and `*` (a DNS-SD instance name with spaces, say) is answered
like any other and recorded with those bytes written as `\DDD`
(`office\032printer._ipp._tcp.example.com`); a query that cannot be read at
all gets FORMERR at once instead of no answer.

`shakerproxy-dnsd` writes one event file per lookup to
`/var/lib/shakerproxy/dns-events/pending`, after the answer has been sent, and
the `dns-event-forwarder` container delivers them to ingest. Recording never
delays an answer: lookups wait in a bounded queue, and when the queue or the
spool (20,000 undelivered events) is full they are dropped, counted, and
logged at most every five minutes. If the spool is missing the forwarder still
answers and logs `DNS lookups are not recorded for Traffic` once at start.
Set `SHAKERPROXY_DNS_EVENT_SPOOL=off` to stop recording.

When a capture records the same lookup through Zeek, Traffic shows the
forwarder's row and hides Zeek's copy with the other analyzer duplicates; the
device report counts each name once.

### Connections as they open

`shakerproxy-gatewayd` also reports every connection a lab device opens through
the gateway (kind `shakerproxy.conn`) within about a second, from the kernel's
connection tracking, without waiting for the packet recording to be analyzed.
It writes them to the same spool, and the same forwarder delivers them. Only
connections from the confirmed lab network to somewhere other than the gateway
are reported; lookups to the gateway are the forwarder's own rows. Ingest names
each connection from the same client's DNS answers of the previous 30 minutes
(`dns_name`), so Traffic shows `github.com · 140.82.121.4:443` at once. When the
recording's analysis of that connection arrives, its server name and size fill
in the same Traffic row instead of adding another. Set
`SHAKERPROXY_CONNECTION_EVENT_SPOOL=off` in gatewayd's environment to stop
reporting connections.

What these live events lose is counted, never only logged: the times the
kernel dropped connection or blocked encrypted-DNS events because gatewayd's
socket buffer was full, and the events the queue or the spool could not take
(the forwarder is down). `GET /api/v1/system/status` (`live_events`), `shakerproxy
doctor` (`live_events`) and System → Visibility health show them, and gatewayd
logs them every five minutes. The connections still reach Traffic once the
recording is analyzed. Event files are not synced to disk one by one, so a
power loss can lose the last few seconds of events, as it does the last seconds
of the recording; the forwarder quarantines a file a crash left empty.

Earlier releases decoded that document with the wrong schema and answered
every query with SERVFAIL as soon as "Force plain DNS" was applied; a
cross-component test now checks that the forwarder accepts exactly what the
gateway writes.

Policy writes use optimistic revisions, the appliance-wide configuration lock,
a preview digest, and administrator confirmation. The password terminates at
`control-api` and is never sent to the privileged socket. Device controls use
the same apply path; blocking and DNS changes need no password because they
affect one device, and turning on HTTPS decryption for a device asks for a
recent password confirmation, as selecting devices for decryption does.

## When something fails

Lab DNS is part of the lab, not of the policy. The redirect that answers DNS
sent to ShakerProxy's own lab and VPN addresses, and the INPUT rule that lets
those queries reach port 1053, live in `SHAKERPROXY-LAB-DNS` and the listener
protection chain. They are installed when gatewayd starts and stay in place
whatever happens to the policy, until the lab is turned off:

- **The DNS forwarder does not answer, has not accepted the policy just
  published, or a policy apply fails**: the policy's
  redirects (DNS sent to other resolvers, HTTPS) and its blocks are removed
  and the previous runtime policy is restored, so client traffic fails open
  rather than being blackholed. DNS sent to ShakerProxy's address is still
  redirected and is answered as soon as `shakerproxy-dnsd` is back, without
  waiting for the next 15-second reconcile.
- **The HTTPS decryption service does not answer** (the mitmproxy container is
  restarting, being upgraded or was stopped for memory): only decryption stops.
  The policy applies without the interception redirects and the QUIC block, so
  HTTPS passes through undecrypted, while DNS forcing, encrypted-DNS blocks,
  device controls and the CA page keep working. `shakerproxy status`,
  `GET /api/v1/system/status` (`degraded: ["decryption_service"]`), the DNS &
  HTTPS page and the MCP system overview say so until the service answers again, and
  decryption resumes by itself. Turning decryption on while the service is down
  is refused with `decryption_service_unavailable`.
- **Emergency bypass**: every policy rule is detached (no redirect of DNS sent
  elsewhere, no block, no decryption, and the forwarder blocks no names), but
  ShakerProxy keeps answering DNS sent to its lab and VPN addresses, as it
  keeps answering DHCP, so devices stay online.
- **Fleet manages the policy**: the local chains are detached; lab DNS stays.

## Test from a client

1. In the network planner, confirm a routed or single-arm plan.
2. In **Local DNS forwarder**, select **Force plain DNS through ShakerProxy**,
   enter one or more upstream IP endpoints such as `1.1.1.1:53`, preview the
   exact changes, and apply.
3. Point the test client's gateway and DNS server at ShakerProxy's lab address
   (DHCP from ShakerProxy does this).
4. From the client, verify both transports:

```bash
dig @SHAKERPROXY_CLIENT_IP example.com A
dig +tcp @SHAKERPROXY_CLIENT_IP example.com A
```

To test domain blocking instead, block a name for the device and look it up:

```bash
dig @SHAKERPROXY_CLIENT_IP blocked.example.com A   # status: NXDOMAIN
```

On the ShakerProxy host, inspect only the managed services and listeners:

```bash
sudo systemctl status shakerproxy-gatewayd shakerproxy-dnsd
sudo ss -lntup '( sport = :1053 )'
/usr/libexec/shakerproxy/shakerproxy-dnsd --help
```

Blocked lookups are logged by `shakerproxy-dnsd` at most once a minute per device
and name (`journalctl -u shakerproxy-dnsd`).

A VPS management tunnel by itself is not a client packet path. A remote client
must route its test traffic through ShakerProxy—for example through an explicitly
configured lab network or tunnel—before gateway or DNS interception can be
observed.

## Settings

`shakerproxy-dnsd` is configured through its environment
(`systemctl edit shakerproxy-dnsd`):

| Variable | Default | Meaning |
| --- | --- | --- |
| `SHAKERPROXY_DNS_BIND` | `:1053` | Listen address (both families). |
| `SHAKERPROXY_DNS_TIMEOUT_SECONDS` | 4 | Per-query upstream budget, 1–30. Out-of-range values are clamped and logged. |
| `SHAKERPROXY_DNS_MAX_CONCURRENT` | 256 | Concurrent queries, 16–4096. |
| `SHAKERPROXY_DNS_FALLBACK_UPSTREAMS` | host resolver | Comma-separated `IP:53` used when the policy names no upstream. |
| `SHAKERPROXY_TRAFFIC_POLICY_FILE` | `/var/lib/shakerproxy/traffic/policy.json` | Runtime document. |

## Modes and limits

- `OBSERVE` installs no client DNS enforcement rules.
- `BLOCK_KNOWN` can block selected DoT, DoQ, and catalog-known DoH/HTTP3
  endpoints; unknown resolvers, shared CDNs, relays, VPNs, ECH, and tunnels can
  remain opaque. The LOG rule for each block now precedes its REJECT, so
  blocked attempts reach the kernel log.
- `ENFORCE_LOCAL` redirects client UDP/TCP port 53 for IPv4, and for IPv6 when
  the lab routes it. It does not provide DNS caching, DNSSEC validation, or a
  per-query enforcement-outcome event.
- Domain blocking covers plain DNS, DNS over TLS/QUIC, and DNS over HTTPS to
  the catalog's resolvers looked up by name. DNS over HTTPS to a resolver
  reached by address, cached answers and hard-coded IP addresses bypass it;
  **Block encrypted DNS** stops the catalog's resolvers by address too (for
  the whole lab), and blocking the device's internet rules everything out.
- Policy upstreams are literal unicast IP endpoints on port 53, neither
  loopback nor link-local IPv6. Provider or VPS egress restrictions on UDP/TCP
  53 can still prevent resolution.
- The current isolated namespace proof is deterministic implementation
  evidence, not clean-machine platform certification.

`tests/netlab/dns-forwarding.sh` proves that client UDP and TCP requests to an
unrelated port-53 address are redirected to the packaged DNS daemon, forwarded
to the configured test resolver, and answered correctly. Unit and API tests
cover runtime parsing of every writer's schema, blocking, upstream hedging,
fixed firewall rendering for both families, authenticated preview/apply/
rollback, device controls, revision conflicts, and password separation.
