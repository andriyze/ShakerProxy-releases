# Appliance diagnostics

The local `shakerproxy doctor` command and `GET /api/v1/system/diagnostics` return
the same schema-1 report. The API endpoint requires an authenticated local
administrator session. The dashboard refreshes it every 30 seconds in normal
operation and every 60 seconds while CPU, memory, or disk pressure is degraded.

Analyzer broker health is intentionally a separate authenticated report at
`GET /api/v1/analyzers/status`. It reads the internal-only Zeek and Suricata
maintenance brokers without opening a host port, reports fresh idle, actively
scanning, and stale states, and isolates a failed engine behind a generic
unavailable result. The dashboard refreshes this report every 30 seconds and
shows bounded completed-capture/event totals plus Suricata ruleset provenance.
Each snapshot also carries `parsers`, what the analyzer loaded when it
started: the configured and the running analyzer profile and, for Zeek, the
OT parser pack it verified and the ICSNPP plugins Zeek registered from it
([industrial protocols](industrial-protocols.md#what-the-analyzers-report)).

## Analyzer profile

`shakerproxy analyzer profile` prints the configured profile (standard or ot)
and what Zeek and Suricata run; reading what they run needs root, because
their state is root's. `shakerproxy status` shows it on the **Analyzer
profile** line (`ot · parser pack builtin, 3 OT plugins`), with "not applied
to every analyzer" in yellow when an analyzer does not run the configured
profile. `sudo shakerproxy doctor` adds an `analyzer_profile` check after the
host checks: `PASS` when both analyzers run the configured profile, `WARNING`
when one does not or reports a parser problem (the observations say which
and how to apply it again), `FAIL` when the setting file is invalid; without
root it is left out. `GET /api/v1/analyzers/profile` and the System page's
**Analyzer profile** panel show the same and the latest switch. When an
analyzer runs another profile than the configured one, the visibility health
signal of that analyzer is `DEGRADED`.

## Visibility health

`GET /api/v1/visibility-health` answers one question: is ShakerProxy seeing
and storing every device connection right now, and if not, where is the gap?
It measures nothing itself; it collects what the parts already report, one
signal per part of the path from packets to Traffic:

- packet recording: whether the lab (and, in VPN mode, the VPN) is recorded
  and whether capture could start with the gateway, the packets a recording
  lost (kernel and dumpcap; dumpcap reports them only when a recording ends,
  so a running recording's drops are not counted yet and the signal says
  so), and recording files that never reached the analyzers;
- live connection and blocked encrypted-DNS events: whether each runs, its
  kernel buffer overruns and the events the spool could not take;
- live analysis, live Zeek and live Suricata each: whether it follows or is
  restarting, its lag and the records it could not confirm delivered;
- Zeek and Suricata: stopped, segments skipped over the analysis budget,
  segments the recording removed before analysis (missed), and an analyzer
  that runs another analyzer profile than the configured one (the industrial
  parsers did not load); each signal's detail names the profile it runs and,
  for Zeek with the OT profile, its parser pack and plugins, and the report's
  `analyzers` carry `profile`, `configured_profile`, `parser_pack`,
  `ot_plugins` and `parser_error`;
- event storage: drain lag, a paused drain, the database, quarantine
  (with how many of the set-aside records the event database refused and
  can be replayed, and the command, see
  [Set-aside records](#set-aside-records)), and the event database's disk
  (low space, history deleted early, or a disk filled by something else,
  which is a gap);
- device discovery: the device inventory's latest refresh;
- decryption and policy: the decryption service down, emergency bypass, a
  traffic policy that could not start, unfinished startup network recovery,
  an unconfirmed network state.

Each signal is `OK`, `DEGRADED` or `UNKNOWN` (the part did not report). A
loss keeps its signal `DEGRADED` for 15 minutes, then stays in the detail as
"earlier". Recording drops are dated from when the control API first saw
them, because the capture worker counts them for the whole recording; drops
from before the control API started are shown without a time and are not
counted as recent.

The System page shows the report at the top and refreshes it every 15
seconds; `shakerproxy status` prints it after the gateway's state (it needs
`shakerproxy login`); `GET /api/v1/coverage` and the MCP `visibility_coverage`
tool include it as `visibility`, and a finished coverage check keeps the
report from its end, so a probe it missed can be explained by a gap at the
time. The MCP `system_status` limitations name each gap in fixed words.

## Set-aside records

A record the event database refuses (a value it cannot hold, a constraint)
would block every record after it, so ingest sets it aside: it is moved whole
from the spool's `pending/` to `rejected/`, the rest drains, and the record
is not in Traffic. From this release the reason is kept beside it, in
`rejected-reasons/<record>.json` (releases before it ignore that directory).
A newer release may store what an older one could not: 0.1.0-beta.43 replaces
the NUL characters PostgreSQL refuses, which had set aside Suricata mDNS
records. Malformed input is quarantined instead (only a bounded prefix is
kept) and cannot be replayed.

```text
sudo shakerproxy ingest rejected                     # counts by kind, day received and why
sudo shakerproxy ingest rejected replay --kind suricata.mdns
sudo shakerproxy ingest rejected delete --before 2026-10-01
```

`replay` moves the selected records back to `pending/`, at most 256 at a
time and only while fewer than 4,000 records are pending, so they are stored
through this release's write path: Zeek and Suricata records pass their
adapter again (NUL replacement, URL credential masking; the event ID may
change), others have their NUL characters replaced. One refused again is set
aside again with the new reason, and one whose capture or device/time
selection was deleted is removed. `delete` lists what it would remove and
asks for `DELETE` (or `--yes`). `--kind` selects an event kind and
`--before` records received before a time (RFC 3339, or a date). The command
runs `ingestd rejected` inside the ingest container as the container's own
user (`docker compose exec`), so it touches the spool with exactly ingestd's
access. Every run is appended to the spool's audit log,
`/var/lib/shakerproxy/spool/rejected-audit.jsonl` (who ran it, the filter,
what it did), rotated past 1 MiB.

## Host diagnostics

The diagnostics report always contains exactly these checks in stable order:

1. interfaces
2. firewall
3. routes
4. DNS resolver configuration
5. fixed service-port ownership for 53, 443, 853, and 8443
6. kernel forwarding
7. managed DHCPv4 expectation
8. Docker systemd state
9. gateway/capture capability state
10. ShakerProxy's host services
11. disk reserve and inode capacity
12. CPU, memory, and disk resource-pressure stage
13. time synchronization
14. capture session state and recording files that never reached the
    analyzers' queue
15. capture-worker packet drops
16. live connection and blocked encrypted-DNS events: whether each runs, and
    the kernel buffer overruns and events it could not record since gatewayd
    started (a warning for 15 minutes after a loss)

Each check is `PASS`, `WARNING`, `FAIL`, or `UNKNOWN`. Any failure makes the
overall result `FAIL`. Warnings or unavailable evidence make the overall result
`WARNING`; `UNKNOWN` is never treated as success.

dumpcap reports how many packets the kernel and it dropped only when a
capture ends (ring-buffer files carry no interface statistics), so the packet
drops check judges finished captures and lists each running capture whose
drops are not counted yet, with the time it ends. With only running captures
and nothing finished to judge, it is `UNKNOWN`.

The daemon reads only fixed kernel/configuration paths and invokes only fixed
`systemctl is-active` or `timedatectl show` commands with bounded output. It
does not accept a caller-selected path, command, or service. It does not open
the Docker socket, enumerate arbitrary containers, send DNS traffic, restart a
service, or alter the packet path. Docker being stopped therefore degrades the
application-stack check without making the independent forwarding path fail.

The resource-pressure check combines Linux CPU PSI `avg10`, `MemAvailable`, and
the managed capture filesystem reserve. At degraded pressure, the browser
reduces diagnostic polling to 60 seconds. At critical pressure, the host daemon
also refuses new captures. Existing routing, emergency recovery, management,
and already-running capture state are preserved; the evaluator never kills a
process or rewrites network state. Missing `/proc` or filesystem evidence is
`UNKNOWN`, never healthy. These thresholds are conservative safety controls,
not a reference-hardware capacity certification.

`GET /api/v1/system/ports` and `shakerproxy ports` expose the same read-only fixed
port plan. A `systemd-resolved` listener on a loopback address such as
`127.0.0.53` is classified as safe to preserve: a future ShakerProxy resolver must
bind only the selected lab address. Any unrelated owner or wildcard bind is a
conflict requiring review. The planner never stops or reconfigures the owner.

The dashboard's **Run explicit connectivity probe** button and
`shakerproxy probe-connectivity` compare two fixed IPv4 paths: an HTTPS `HEAD /`
request dialed directly to `1.1.1.1:443` with the TLS identity
`one.one.one.one`, and a TCP connect to `1.1.1.1:53`. The probe does not use
DNS, sends no DNS question, accepts no caller-selected destination, has a
seven-second host deadline, and the HTTP endpoint is limited to one run per 15
seconds. `restricted_port_53` means the verified HTTPS path worked while TCP
port 53 did not; it does not prove UDP behavior or a provider policy.

The current report intentionally shows only capture-worker drop counters.
Direct Suricata capture/kernel drops, Zeek packet-loss telemetry, per-interface
byte counters, conntrack utilization, write latency, and container restart
counts remain future observability work and must not be inferred from `PASS` on
another check. Analyzer broker `HEALTHY` likewise means recent broker progress,
not zero packet loss inside either engine.
