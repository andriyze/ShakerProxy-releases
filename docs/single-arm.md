# Same network (single-arm)

A single-arm ShakerProxy has **one network port**, on the same network as the
devices you test. It becomes their gateway: each device sends its traffic to
ShakerProxy instead of your router, and ShakerProxy forwards it to the router,
NATed to its own address. Use it on a computer or VM with one port (a mini PC,
a cloud VM, a laptop on your desk) when the device cannot run a VPN app.

Because ShakerProxy shares the network with your router, a device reaches it
only if it is told to. Two ways:

- **Per device:** set the device's router (gateway) and DNS server to
  ShakerProxy's address. Only that device goes through ShakerProxy.
- **For the whole network:** set the gateway and DNS server your router's DHCP
  hands out to ShakerProxy's address. Every device on the network then goes
  through ShakerProxy, and loses the internet whenever ShakerProxy is off.

If neither suits the device, use [VPN mode](vpn-mode.md) for phones, tablets and
laptops, or an [inline bridge](bridge-mode.md) for wired TVs and IoT devices: both
need nothing set on the device and leave no way around ShakerProxy.

## Set up ShakerProxy

1. Start → *How will your device reach ShakerProxy?* → **Same network
   (single-arm)**, or Network → Topology → *One network port*. On a computer
   with one port this is the only plan offered.
2. Pick the port. ShakerProxy keeps its address, route, DNS and MTU exactly as
   they are, and runs no DHCP server of its own.
3. Preview, apply and confirm. Like every network change it rolls back by
   itself if you do not confirm in time.

ShakerProxy's address is the port's existing IPv4 address, shown under Network →
Interfaces and, once the plan is confirmed, in Start's *Connect a device* step.
The steps below call it `192.168.10.177`; use yours.

## Set a device to use ShakerProxy

Keep the device's own address and change only its router and DNS.

**iPhone or iPad**

1. Settings → Wi-Fi → tap (i) next to the network.
2. Configure IP → **Manual**: keep the IP address and subnet mask, set
   **Router** to `192.168.10.177`.
3. Configure DNS → **Manual**: remove the other servers and add `192.168.10.177`.

**Android**

1. Settings → Network & internet → Internet → the gear next to the network →
   Edit (pencil) → Advanced options.
2. IP settings → **Static**: keep the IP address and prefix length, set
   **Gateway** and **DNS 1** to `192.168.10.177`.

**macOS**: System Settings → Network → the network → Details → TCP/IP:
Configure IPv4 *Using DHCP with manual address* (or *Manually*), **Router**
`192.168.10.177`; DNS → replace the servers with `192.168.10.177`.

**Windows**: Settings → Network & internet → the adapter → IP assignment →
Edit → Manual, IPv4 on: keep the address, set **Gateway** and **Preferred
DNS** to `192.168.10.177`.

**Linux (NetworkManager)**:

```bash
nmcli connection modify "<connection>" ipv4.method manual \
  ipv4.addresses <device-address>/24 ipv4.gateway 192.168.10.177 ipv4.dns 192.168.10.177
nmcli connection up "<connection>"
```

**Through your router's DHCP** (every device): set *DHCP default gateway* and
*DNS server* to `192.168.10.177`. On UniFi: Settings → Networks → the network →
DHCP. Devices pick it up when they reconnect.

## Check that it works

The device appears in **Devices** and its traffic in **Traffic** within
seconds. System → *Whose traffic goes through ShakerProxy* (and the banner on
Start and Traffic) names any device on the network whose traffic still goes
straight to the router, with these steps worded for its own address.

## Limits

- ShakerProxy cannot isolate devices on the same network: traffic between two
  devices on it does not pass ShakerProxy and is not recorded.
- A single-arm plan does not route IPv6. Turn IPv6 off on the device (or make
  sure the network has no other IPv6 router), or its IPv6 traffic goes around
  ShakerProxy.
- A device whose settings are reset (a new DHCP lease, a forgotten network)
  goes back to your router; the routing check above shows it.
- The two-port plans and the inline bridge put ShakerProxy in the only path
  and are preferred when the hardware allows. See
  [networking.md](networking.md) for how single-arm is applied and rolled
  back (ICMP redirects off, NAT44, no DHCP server).
