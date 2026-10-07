# Device testing quickstart

This guide is for someone testing a phone, TV, camera, speaker or other smart
device on a ShakerProxy appliance. It covers the four things testers ask for most:

1. connect the device and see it in ShakerProxy;
2. read its HTTPS traffic, or check whether it validates certificates;
3. cut its internet or block a domain to see how it behaves;
4. understand what "certificate pinning" means when decryption fails.

Everything below works from the web UI, the API and the `shakerproxy` CLI. The API
calls are shown so you can script a test run; every device reference accepts
the device ID, its MAC address, its current IP address or its friendly name.

## Before you start

ShakerProxy must sit between the device and the internet: a device that only
shares a switch with ShakerProxy, and still uses your router as its gateway, is
not in the packet path. Pick how the device reaches ShakerProxy by the kind of
device (the web UI asks the same question on **Start**):

| The device | How it reaches ShakerProxy | What to set up | Guide |
| --- | --- | --- | --- |
| Phone, tablet or laptop | **VPN**: the WireGuard app, from any network | Network → VPN devices → Turn on VPN mode (no lab network needed) | [vpn-mode.md](vpn-mode.md) |
| TV, console, camera or IoT device with a network cable | **Inline bridge** between the device and your router | Two network ports; a `TRANSPARENT_BRIDGE` plan (Network → Apply) | [bridge-mode.md](bridge-mode.md) |
| Wi-Fi device that cannot run a VPN app | **ShakerProxy's Wi-Fi** | A Wi-Fi adapter with AP mode and an internet port; a plan with the access point | [wifi-access-point.md](wifi-access-point.md) |
| Anything you can plug into a spare port | **Lab port** | Two network ports; a two-port plan (Network → Apply) | [networking.md](networking.md) |
| Anything on the same network as a one-port ShakerProxy | **Same network (single-arm)**, with ShakerProxy as its gateway | One network port; a single-arm plan, then the device's gateway and DNS (or your router's DHCP) set to ShakerProxy | [single-arm.md](single-arm.md) |

Then:

- For HTTPS decryption, the HTTPS decryption service (the `mitm` application
  profile) is running.
- Only test devices you own or are authorised to test. Decrypted content stays
  on the appliance and is covered by the retention settings in
  [decrypted-content-retention.md](decrypted-content-retention.md).

## 1. Connect the device

How depends on the way you chose above:

- **VPN:** add the device under Network → VPN devices (or `shakerproxy vpn add
  Pixel`) and scan the QR code with the WireGuard app. It appears as
  `Pixel (VPN)` once the tunnel is on.
- **Inline bridge:** plug the device into ShakerProxy's device port. It keeps
  getting its address from your router; nothing changes on the device.
- **ShakerProxy's Wi-Fi or a lab port:** join the Wi-Fi or plug it in;
  ShakerProxy hands it an address with DHCP.
- **Same network (single-arm):** set the device's router (gateway) and DNS to
  ShakerProxy's address, as [single-arm.md](single-arm.md) shows for each
  system, or point your router's DHCP at ShakerProxy.

It appears in **Devices** within a few seconds, with its vendor when the MAC
prefix is known. Give it a name you will recognise, such as "Living room TV".

```bash
curl -s -H "Authorization: Bearer $TOKEN" https://shakerproxy.example:8443/api/v1/devices
```

## 2a. Decrypt its HTTPS

Turn on **Decrypt HTTPS** for the device (device page), or:

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"decrypt_https": true}' \
  "https://shakerproxy.example:8443/api/v1/devices/Living%20room%20TV/controls"
```

The device page asks for the administrator password if you have not
confirmed it in the last 10 minutes. `$TOKEN` needs `lab:write` with its
sensitive-scope acknowledgement (`shakerproxy login` tokens have it).

This does three things for that device only:

- its HTTPS (TCP/443) goes through ShakerProxy's interception proxy; other lab
  devices are not touched;
- QUIC (UDP/443) is blocked so apps that prefer HTTP/3 fall back to HTTPS over
  TCP, which ShakerProxy can decrypt;
- the certificate onboarding page opens on the lab network and over the VPN.

Then make the device trust the ShakerProxy CA. On the device, open
`http://<ShakerProxy lab address>/` (for example `http://10.77.0.1/`), or on a
VPN device `http://<ShakerProxy VPN address>/` (`http://10.89.0.1/` by
default); the Inspect wizard shows the right one as a QR code. The page
shows the certificate fingerprint and install steps for iPhone/iPad, Android,
Mac, Windows and Linux. The same steps are returned by
`GET /api/v1/interception-ca/onboarding` and shown in the UI.

- **iPhone / iPad:** open the page in Safari, install the profile, then turn
  on full trust in Settings → General → About → **Certificate Trust
  Settings**. Installing the profile alone is not enough.
- **Android:** install the `.crt` as a CA certificate in Settings. Since
  Android 7, apps ignore user-installed CAs unless they opt in, so expect
  Chrome to decrypt but most apps to pass through or fail (see pinning below).
  Emulators and rooted devices can use the system-store file on the page.
- **TVs, streaming sticks, cameras and most IoT devices** cannot install a CA.
  Use the certificate validation test instead.

Check the fingerprint on the page matches the one under **DNS & HTTPS →
Install the ShakerProxy certificate** in the web UI before trusting it; the
page is served over plain HTTP on the lab network (over the VPN it travels
inside the encrypted tunnel).

Use the device. In **Traffic**, its requests appear with method, host, path and
status, and TLS events show whether each connection was decrypted, passed
through or failed, with a plain explanation.

Optional policy switches. The web UI does not show these yet: with an
administrator session, read the policy (`GET /api/v1/traffic-policy`), change
the field under `tls_interception`, preview it
(`POST /api/v1/traffic-policy/preview`) and apply it with your password
(`PUT /api/v1/traffic-policy`). Their defaults are in
[TLS interception](tls-interception.md#defaults).

- **Proxy plain HTTP** (`intercept_http`) also sends TCP/80 through the
  proxy, so those requests are recorded like decrypted HTTPS. The packet
  recording shows plain HTTP either way.
- **Allow QUIC** (`allow_quic`) stops blocking UDP/443.
- **Decrypt private destinations** (`intercept_private_destinations`)
  includes LAN, CGNAT and link-local servers. It is off by default because
  local and IoT backends often use self-signed or mutual TLS that breaks when
  intercepted.

## 2b. Test whether it validates certificates

For devices that cannot install a CA, or to test the device's own security:
**do not install the CA**, then turn on Decrypt HTTPS for it.

- A connection that keeps working through ShakerProxy means the device accepted a
  certificate it had no reason to trust. That is a serious finding: anyone on
  the network path could read and change its traffic. ShakerProxy flags it as
  "accepts untrusted certificates".
- A connection that fails is the correct behaviour. It shows up as a TLS
  failure ("the device rejected ShakerProxy's certificate").

Turn decryption off (or bypass the host, below) to restore normal operation.

## 3. Block its internet or a domain

Cut the device off to see how it behaves offline:

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"internet": "BLOCK"}' \
  "https://shakerproxy.example:8443/api/v1/devices/aa:bb:cc:dd:ee:ff/controls"
```

Traffic leaving the lab is dropped; ShakerProxy's DHCP and DNS and other lab
devices still work, like a home router whose uplink has failed. The device is
matched by its MAC address, so it stays blocked if its IP address changes.

Block specific names instead, for example a telemetry or update server:

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"blocked_domains": ["telemetry.example.com", "updates.example.com"]}' \
  "https://shakerproxy.example:8443/api/v1/devices/10.77.0.23/controls"
```

ShakerProxy answers "name does not exist" (NXDOMAIN) for those names and all their
subdomains. To do this it sends the device's DNS to ShakerProxy's DNS forwarder
(the response notes say so), blocks DNS over TLS/QUIC for the device and
refuses it the names of known DNS-over-HTTPS resolvers (and the Firefox and
iCloud Private Relay opt-out names), so it falls back to plain DNS.
An app that reaches a DNS-over-HTTPS resolver by its address, cached answers
or hard-coded IP addresses can still reach a blocked name. **Block encrypted
DNS** (the device panel offers it) also blocks the known resolvers by address,
for the whole lab; **Block internet** rules everything out.

Undo with `{"internet": "ALLOW"}` or `{"blocked_domains": []}`. `GET` on the
same URL shows the current controls, whether they are in effect right now
(`effective`), and notes explaining anything that is not.

## What "certificate pinning" means

An app that pins its certificate accepts only one specific certificate (or
key) for its server, not any certificate from a trusted CA. That protects it
against interception, including ShakerProxy's: even with the ShakerProxy CA installed,
the app refuses the connection. Banking apps, many streaming apps and system
services such as Apple push notifications do this.

When a device that ShakerProxy has decrypted before keeps rejecting ShakerProxy for the
same host, ShakerProxy reports **probable certificate pinning**. Bypass that host
for the device so the app keeps working, from the failure event or with the
API below. If automatic pinning bypass is on in the HTTPS policy, ShakerProxy does
this by itself for phones and TVs listed in the policy's mobile client ranges;
it never does it for desktops or unknown devices.

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"host": "api.example.com", "device": "Living room TV"}' \
  https://shakerproxy.example:8443/api/v1/traffic-policy/bypass
```

Pinned traffic stays readable as metadata (host name, timing, volume) but not
as content. Reading it requires a debuggable build of the app or tooling on the
device itself, which is outside ShakerProxy.

A similar thing happens in the other direction: if the **server's**
certificate is not publicly trusted (self-signed, private CA), ShakerProxy cannot
safely decrypt it, reports "the server's certificate is not publicly trusted",
and passes that host through for the device on the next attempt.

## When something does not work

| You see | What to do |
| --- | --- |
| `network_not_ready` | Connect devices through ShakerProxy: confirm a network plan (Network → Apply), or turn on VPN mode (Network → VPN devices). |
| `interception_ca_missing` | Run `sudo systemctl restart shakerproxy-interception-pki`. |
| `decryption_service_unavailable` | Start the HTTPS decryption service: `sudo systemctl restart shakerproxy-app` with the `mitm` profile enabled. |
| `dns_service_unavailable` | Run `sudo systemctl restart shakerproxy-dnsd`. |
| `effective: false` with "does not know this device's MAC or IP" | Reconnect the device (a new DHCP lease, or its VPN tunnel turned on) so ShakerProxy sees its address, then save its controls again. |
| The onboarding page does not open | Decryption must be on for at least one device; `GET /api/v1/interception-ca/onboarding` says why in `reason` and `reason_code` and lists the addresses it is served on (`urls`: the lab network's and the VPN's). A device opens the one on its own network. `vpn_only` means this gateway serves it on the lab network only: download the certificate from the Inspect wizard's install step instead. |
| Every app fails after installing the CA on Android | Expected on Android 7+: apps ignore user CAs. Use the validation test or an emulator. |

More detail: [tls-interception.md](tls-interception.md) and
[dns-forwarding.md](dns-forwarding.md).
