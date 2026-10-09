# TLS interception

ShakerProxy can decrypt HTTPS from lab devices you select, so you can read what a
device sends and test whether it validates certificates. This page explains
how it works, what the defaults are, and why a connection is decrypted,
passed through or failed. For a step-by-step test, start with
[device-testing-quickstart.md](device-testing-quickstart.md).

## How it works

- `shakerproxy-gatewayd` owns the revisioned traffic policy and installs fixed
  `iptables` and `ip6tables` rules on the confirmed lab interface (a wired
  port, the Wi-Fi access point, or the `lgbr0` bridge of both). No caller can
  pass rule text; only validated policy fields are rendered.
- Client TCP/443 (and TCP/80 when `intercept_http` is on) is redirected to the
  unprivileged mitmproxy container (`apps/mitmproxy`, port 8085) in
  transparent mode. Only traffic leaving the lab is redirected; lab-to-lab
  traffic is left alone even on a bridged lab.
- The ShakerProxy addon decides per connection whether to decrypt or pass the raw
  TLS bytes through, and records normalized events that
  `mitm-event-forwarderd` delivers to local ingest.
- mitmproxy verifies the real server's certificate before decrypting.
- Port 8085 is dropped everywhere except loopback and connections ShakerProxy
  redirected from the lab, and the addon additionally refuses clients outside
  loopback, private ranges and the lab prefixes.
- The gateway keeps its hooks above ShakerProxy's own forward and input hooks, so
  device blocks and encrypted-DNS drops are evaluated before ShakerProxy's
  lab-to-WAN accept rules.
- If the proxy is not listening (its container restarting, being upgraded or
  stopped for memory), only decryption stops: the gateway applies the rest of
  the policy without the interception redirects and the QUIC block, so HTTPS
  passes through undecrypted while DNS and device controls keep working. The
  status reports `decryption_service` as degraded (`shakerproxy status`, the
  DNS & HTTPS page, the MCP system overview) and decryption resumes by itself when
  the proxy answers again. Turning decryption on while the proxy is down is
  refused.
- If the DNS forwarder is not listening, the gateway removes its redirects:
  client traffic fails open to the normal routed path. DNS sent to
  ShakerProxy's own lab address is answered in every case (see
  [DNS forwarding](dns-forwarding.md#when-something-fails)).

## Defaults

| Setting | Default | Effect |
| --- | --- | --- |
| Scope | selected devices | `selected_device_ids`: only listed devices are decrypted. Per-device **Decrypt HTTPS** manages this list. With every selected device's MAC or IP known, other devices never touch the proxy. |
| `allow_quic` | off | QUIC (UDP/443) from decrypted devices is rejected so HTTP/3 apps fall back to TCP. |
| `intercept_http` | off | Plain HTTP (TCP/80) is not sent through the proxy. The lab recording still shows its requests (method, host, path, status), with headers and bodies in the event detail (see [protocol support](protocol-support.md)); turning this on also sends it through the proxy for the decrypted devices, which records it like decrypted HTTPS. |
| `intercept_private_destinations` | off | Connections to 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, fc00::/7 and fe80::/10 are not intercepted, at the firewall and again in the addon. |
| Automatic pinning bypass | off | The policy option covers devices in `mobile_clients` and devices ShakerProxy names a mobile platform (android, android-tv, ios, tvos) from their announced or given name (iPhone, iPad, Pixel, Galaxy, Android and similar). Whatever the option, a device marked *certificate installed* (CA trust INSTALLED, which the Inspect wizard's "See its HTTPS traffic" goal records) gets it, and a device marked NOT_INSTALLED (a certificate-validation test) never does. A host is passed through for the device once it refuses ShakerProxy's certificate 3 times in 10 minutes after ShakerProxy decrypted the device's HTTPS in the last 24 hours (plain HTTP does not count); the failure says `probable_certificate_pinning_or_custom_trust_store` and later connections `dynamic_probable_pinning_bypass`. |

Turning on decryption for every lab device at once (no selected devices) is a
separate policy change that needs the administrator password; per-device
decryption does not.

## The CA and the onboarding page

`shakerproxy-interception-pki` creates a dedicated interception CA; its private
key is readable only by the proxy. While interception is configured, lab
devices can fetch the public certificate at `http://<lab gateway>/`, and VPN
devices at `http://<VPN gateway>/` (`http://10.89.0.1/` by default):

- `/` — a mobile-friendly page with the SHA-256 fingerprint and install steps;
- `/shakerproxy-ca.pem`, `/shakerproxy-ca.crt` (DER), `/shakerproxy-ca.mobileconfig`
  (iOS/iPadOS/macOS profile) and `/shakerproxy-ca-android.0` (Android system-store
  file named by `subject_hash_old`).

The page is served by `shakerproxy-ca-onboarding`, a service with no privileges or
capabilities (`DynamicUser`, read-only access to the public certificate). It
listens on an unprivileged port bound only to ShakerProxy's lab-side and VPN
addresses; the gateway forwards lab and VPN TCP/80 for the gateway addresses
to it only while interception is configured, and drops that port on every
other interface for both IPv4 and IPv6 (the VPN serves it on IPv4, which
every VPN device has). It never serves private keys, and it is plain HTTP, so
compare the fingerprint with the one under **DNS & HTTPS → Install the
ShakerProxy certificate** in the web UI.

`GET /api/v1/interception-ca/onboarding` returns the same steps, the URLs
(the lab network's, then the VPN's) and, when the page is not reachable, a
`reason` that says what to do with a stable `reason_code`. `decryption_off`
is the normal state before the first device is decrypted (the page opens once
one is), and `vpn_only` means VPN devices are decrypted but this gateway
serves the page on the lab network only: download the certificate in the web
UI and copy it to the device. Neither stops you from turning
decryption on; the other codes (`ca_not_created`, `ca_unreadable`,
`gateway_unreachable`, `network_not_routed`, `fleet_managed`,
`emergency_bypass`, `decryption_inactive`) name something to fix.

### When the certificate is replaced

The interception CA is valid for five years. From 90 days before its end the
certificate panel, `GET /api/v1/interception-ca` (`lifecycle`) and
`shakerproxy doctor` (`interception_ca`) say when it expires, and in its last
30 days doctor warns. At the first boot or package update in those 30 days (or
after it expired) ShakerProxy replaces it with a new five-year CA; the old one is kept, never deleted, under
`/var/lib/shakerproxy/mitmproxy/retired/`. Devices that trusted the old
certificate are no longer decrypted: for 30 days the panel, API and doctor say
so, with the new fingerprint. Install the new certificate on each test device
(and remove the old one).

To replace it earlier, for example when its key may have been exposed:

```bash
sudo /usr/libexec/shakerproxy/shakerproxy-interception-pki rotate
sudo systemctl restart shakerproxy-app
```

## Why a connection was not decrypted

TLS events carry a `reason` and a plain `explanation`.

| Event | Reason | Meaning |
| --- | --- | --- |
| passthrough | `interception_disabled` | Decryption is off. |
| passthrough | `device_not_selected` | Decryption is on for other devices only. |
| passthrough | `private_destination` | LAN or link-local server; see `intercept_private_destinations`. |
| passthrough | `manual_host_exclusion`, `manual_cidr_exclusion`, `policy_bypass_rule` | A bypass you configured, including one-click bypasses. |
| passthrough | `dynamic_probable_pinning_bypass` | Automatic pinning bypass for this device and host. |
| passthrough | `upstream_certificate_bypass` | An earlier attempt found the server's certificate untrusted. |
| failed (client side) | `ca_not_trusted_or_pinning` | The device rejected ShakerProxy's certificate: CA not installed or the app pins. |
| failed (client side) | `probable_certificate_pinning_or_custom_trust_store` | Repeated rejection after earlier success: probable pinning. |
| failed (upstream side) | `upstream_certificate_untrusted` | The server's certificate is self-signed, private, expired or for another name. The host is passed through for that device on the next attempt. |
| failed (upstream side) | `upstream_requires_client_certificate` | The server wants mutual TLS; passed through on the next attempt. |
| failed (upstream side) | `upstream_tls_failed` | Other upstream TLS error; the message is included. |
| failed (client side) | `ech_hidden_server_name` | The ClientHello offered Encrypted Client Hello behind a public name (see [ECH](#encrypted-client-hello-ech)); never counted as pinning, never bypassed. |

`http_flow_error` events include the proxy's error message and a reason such as
`upstream_unreachable`. If the proxy cannot read its policy, every connection
passes through and a `tls_policy_unavailable` event says so.

## DNS over HTTPS that ShakerProxy decrypts

A decrypted request to a DNS-over-HTTPS resolver (a catalog hostname, or any
request or answer typed `application/dns-message`) is recorded as
`encrypted_dns_detected` with the question it asks. When the answer arrives,
`apps/mitmproxy/shakerproxy_doh.py` decodes it and the add-on emits a
`doh_lookup` event with the same lookup fields `shakerproxy-dnsd` records for
plain DNS: `query`, `query_type`, `response_code`, `answer_count`, `answers`
(A, AAAA and CNAME data), the resolver (`hostname`, `resolver_id`,
`resolver_provider`), the device, `service: doh` and `via: doh-decrypted`.
Traffic shows it as a DNS lookup "via DoH (decrypted)", the device report
lists the name with the source `doh`, and `kind:doh_lookup` (or `service:doh`)
finds them.

Both wire formats are read: RFC 8484 `application/dns-message` (POST, or GET
with `?dns=`) and the JSON API (`application/dns-json`, `?name=&type=`).
Decoding is bounded: answers larger than 65535 bytes, streamed bodies and
encodings other than gzip/deflate are not decoded (the exchange is still the
usual `http_response` event); a compressed answer is inflated to at most 65535
bytes; at most 32 answers are kept (`answer_count` counts all); name
decompression is loop- and depth-limited, and a malformed message is skipped.
An answer for another question than the one asked keeps only the question
(`mismatched_answer`). No request or response body is stored by this path;
body previews stay as described under [Limits](#limits). A DoH request
ShakerProxy blocks gets no `doh_lookup`. DoH over HTTP/3 (QUIC) and DoH to a
resolver whose connection is not decrypted (pinned apps, Android Private DNS
over DoT, a passed-through host) stays hidden; block encrypted DNS to make
those devices fall back.

## Encrypted Client Hello (ECH)

With ECH a client encrypts the ClientHello that names the server and sends an
outer ClientHello naming only the provider's *public name* (for Cloudflare,
`cloudflare-ech.com`). Sensors then see the public name, not the site.
ShakerProxy detects the `encrypted_client_hello` extension (0xfe0d) in:

- Zeek: `ssl.log` and `conn.log` get `ech: true`
  (`apps/analyzer-worker/zeek/shakerproxy.zeek`, TLS and QUIC, live and
  segment analysis);
- Suricata: `tls.client_handshake.exts` lists 65037 (EVE `tls` custom fields
  with `client_handshake`, which the stock configuration does not log);
- the interception proxy: its TLS events get `ech: true`
  (`apps/mitmproxy/shakerproxy_ech.py`).

Browsers also send the extension as GREASE when they have no ECH
configuration for a site, with the real name outside, and GREASE looks
exactly like ECH on the wire. So a connection is marked **server name hidden
(ECH)** only when it offered ECH *and* the visible name is a known ECH public
name (`internal/ingest/ech.go`; add providers there, in
`apps/mitmproxy/shakerproxy_ech.py` and `apps/web-ui/src/lib/ech.ts`, which
a test keeps equal). Such a record is stored with protocol visibility
`OPAQUE`, so protocol coverage counts it as reduced visibility; its summary
reads "TLS to cloudflare-ech.com — server name hidden (ECH), shown is the
public name"; the event drawer explains it; and the device report counts the
connections per public name (TLS section and the `ech-hidden-names` finding).
An ECH offer with another name is only "ECH offered" in the drawer.

ShakerProxy cannot decrypt the inner ClientHello. When it decrypts a device
that sends real ECH, the browser sees ShakerProxy's certificate for the public
name, ends the connection and retries without ECH, and the retry carries the
real name. The proxy records the first attempt as `ech_hidden_server_name`
and never treats it as pinning: an automatic bypass of the public name would
let every later ECH connection through hidden.

The ECH fallback setting (off by default, [DNS forwarding](dns-forwarding.md#ech-fallback))
removes the `ech` parameter from the HTTPS records ShakerProxy answers, so
browsers that take their ECH configuration from those answers send the real
name from the start. It does not reach HTTPS records fetched over DoH (Firefox
uses ECH only with its own DoH; block encrypted DNS or use the canary
setting) or DNSSEC-validated answers. Records stored before this release keep
their earlier classification.

## Bypassing a host

`POST /api/v1/traffic-policy/bypass` with `{"host": "api.example.com"}` stops
decrypting that host for every device; add `"device": "<ref>"` to limit it to
one device. `DELETE` with the same `host` (and `device`) query parameters
removes it. Bypasses are part of the revisioned traffic policy.

## IPv6

When the confirmed plan routes lab IPv6 (`ULA_NAT66_LAB` or
`NATIVE_ROUTED_PREFIX`), the gateway renders the same rules with `ip6tables`:
TLS and DNS redirects, QUIC and DoT/DoQ blocks, device controls and the
onboarding redirect. IPv6 redirects are installed only after the gateway has
confirmed the proxy and DNS forwarder accept IPv6 on `::1`; device blocks by
MAC apply to IPv6 regardless. The listener protection rules are installed for
IPv6 whenever the host has IPv6.

## WebSockets

A WebSocket on a decrypted connection (or on plain HTTP sent through the proxy
with `intercept_http`) is recorded after the HTTP upgrade that opened it. The
upgrade is an ordinary `http_request` and `http_response` (status 101), and
the socket's events share its mitmproxy flow ID
(`apps/mitmproxy/shakerproxy_websocket.py`):

| Event | When | What it says |
| --- | --- | --- |
| `websocket_session`, `ws_state` open | The socket opens | URL host and path (never the query string), `wss` or `ws`, the negotiated subprotocol and extensions (`permessage-deflate` is flagged), the extensions the device offered, the device |
| `websocket_messages` | Within about a second of the first messages, then at most once per 10 seconds of traffic | The window's counts by direction and type (text, binary), bytes, the largest message, and the messages it lists one by one |
| `websocket_session`, `ws_state` closed | The socket closes | The handshake again, the close code and reason, who closed it, the duration, the socket's totals and its first messages |

A chatty socket cannot flood ingest. Its first 16 messages are listed one by
one (direction, type, size, time); after that only counts are recorded. A
socket produces at most 360 message events, after which its traffic is only
counted in the closing totals, and all sockets together at most 20 message
events a second: a window that finds that budget spent stays open and is sent
with the next one, so no message is lost from the counts. ShakerProxy tracks up
to 4096 sockets at once; more are recorded as opened and closed without
counts. Sizes are of the message payload after permessage-deflate
decompression. mitmproxy answers ping and pong frames itself without telling
add-ons, so they are not counted; a close frame is the session's close code.

Message content follows [decrypted content retention](decrypted-content-retention.md):
with it on, a listed text message keeps at most a 256-byte preview with
credentials masked before the event is written (the field names and headers
HTTP bodies are redacted by, `Authorization: Bearer …` and similar
credentials, and JSON Web Tokens), and a binary message its size and at most
its first 16 bytes in hex. With it off, every message is metadata only.

In the Traffic view WebSocket events are listed under HTTP (`WSS ·
chat.example.com/live · closed 1000 · 42 messages`; a close code other than
1000, 1001 or 1005 is marked as a problem). The event drawer shows the upgrade
under Request / Response and, below it, the socket: how it was negotiated and
closed, its counts and the listed messages. The query language finds them by
`kind:websocket_session`, `kind:websocket_messages`, `ws.host`, `ws.opcode`
(text, binary, close), `ws.subprotocol` and `ws.close_code`; `http.host` and
`type:http` include them. The MCP `http_exchange` tool returns the socket for
a WebSocket event or the 101 response; for API tokens previews pass the HTTP
credential redaction again, binary prefixes and the close reason are left out,
and `event_detail` and `search_traffic` carry the counts only.

## Credentials in URLs

A decrypted request's stored URL (`http_url`, and a WebSocket upgrade's)
keeps its query string with the value of every credential parameter
(`token=`, `access_token=`, `api_key=`, `key=`, `sig=`, `password=`,
`auth=` and the other names HTTP bodies are masked by) replaced with
`%5Bredacted%5D` before the event is written; names and the rest of the URL
stay. URLs from Zeek and Suricata are masked the same way when stored. Rows
stored earlier are not rewritten. See
[decrypted content retention](decrypted-content-retention.md#credentials-in-urls).

## Limits

Certificate pinning, mutual TLS, ECH (marked "server name hidden (ECH)", see
[above](#encrypted-client-hello-ech)), VPNs and tunnels, apps that ignore user
CAs (Android 7+), and QUIC when `allow_quic` is on cannot be decrypted; ShakerProxy
reports them and passes them through. Decrypted bodies are previewed up to
64 KiB per message and retained only as configured in
[decrypted-content-retention.md](decrypted-content-retention.md). Bodies above
5 MiB are streamed through and recorded as metadata only. WebSocket messages
are listed for a socket's first 16 messages and counted after that (see
[WebSockets](#websockets)).

## Testing

Unit tests cover rendering for both families (`internal/trafficpolicy`), the
gateway apply path with IPv6 and device controls
(`host/gatewayd/internal/daemon`), and the control API. Addon hooks are tested
with `mitmproxy.test.taddons` inside the pinned image:

```bash
make test-mitm-image
```

The disposable network proof is described in
[testing/mitmproxy-netlab.md](testing/mitmproxy-netlab.md).
