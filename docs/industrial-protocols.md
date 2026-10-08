# Industrial protocols (OT)

ShakerProxy shows what industrial devices on the lab network are asked to do
and how they answer: Modbus/TCP, DNP3, EtherNet/IP and CIP, Siemens S7comm and
S7comm-plus, OPC UA Binary, BACnet/IP and IEC 60870-5-104. Each such record
carries an **industrial
projection**: the protocol, the operation, what kind of operation it is,
whether it can change the device or the process, the device's answer, and the
protocol's own identifiers (a Modbus unit and register range, a CIP service
and object, an S7 rack and slot, an OPC UA service and security mode, a BACnet
object and property, an IEC 104 type and cause of transmission). It never
carries process values: no register, coil, tag, I/O, BACnet property or IEC 104
information element value, and no OPC UA variant, is stored.

## What works without the OT profile

Zeek's own Modbus and DNP3 analyzers run on every install. Their records
(`zeek.modbus`, `zeek.dnp3`) get an industrial projection, appear under the
Traffic view's **Industrial** chip, and can be queried with the fields below.
The connection record of a session either analyzer confirmed (Zeek names
DNP3's `dnp3_tcp` or `dnp3_udp` in `conn.log`) is an industrial connection
with `ANALYZER` evidence.
Every other industrial protocol is only a port label without the profile:
traffic to TCP/102, TCP/44818, UDP/47808 or TCP/2404 is shown as `s7comm`,
`enip`, `bacnet` or `iec104` with `PORT_HEURISTIC` evidence and is listed under
Other, not Industrial, because the port alone proves nothing.

Industrial networks are often observed rather than routed: on a [passive
mirror](protocol-support.md#passive-mirror) the mirror port's recording is
analyzed like the lab recording, with the same profile, so its industrial
records and their device attribution (by MAC from ARP, neighbor discovery and
DHCP) appear the same way, without ShakerProxy sending anything to the plant
network.

## The OT analyzer profile

The profile adds the industrial parsers. It is **off by default**, so a lab
without industrial devices runs exactly what it ran before and pays nothing
for it.

| Engine | With the OT profile |
|---|---|
| Zeek | CISA ICSNPP plugins for EtherNet/IP and CIP (`enip`, `cip`, `cip_identity`, `cip_io` logs), S7comm, S7comm-plus and COTP (`s7comm`, `s7comm_plus`, `s7comm_read_szl`, `s7comm_upload_download`, `s7comm_known_devices`, `cotp`) OPC UA Binary (`opcua_binary`, `opcua_binary_opensecure_channel`, `opcua_binary_get_endpoints_description`, `opcua_binary_status_code_detail`) and BACnet/IP on UDP/47808 (`bacnet`, `bacnet_discovery`, `bacnet_property`, `bacnet_device_control`), ICSNPP's Modbus and DNP3 logging (`modbus_detailed`, `modbus_mask_write_register`, `modbus_read_write_multiple_registers`, `modbus_read_device_identification`, `dnp3_control`, `dnp3_objects`), and ShakerProxy's own IEC 60870-5-104 analyzer on TCP/2404 (`iec104`) |
| Suricata | Its Modbus, DNP3 and EtherNet/IP app-layer parsers on their detection ports (502, 20000, 44818), logged to EVE (`suricata.modbus`, `suricata.dnp3`, `suricata.enip`), so rules can use the Modbus, DNP3 and ENIP keywords. Suricata 8 has no BACnet or IEC 60870-5-104 parser; Zeek's records are the only ones for those |

### Switching the profile

```text
shakerproxy analyzer profile            # what is configured, and what each analyzer runs
sudo shakerproxy analyzer profile ot    # turn the industrial parsers on
sudo shakerproxy analyzer profile standard
```

or, on the System page, **Analyzer profile** → **Switch to OT** (it asks for
the administrator password unless you confirmed it in the last 10 minutes),
or `PUT /api/v1/analyzers/profile` with `{"profile": "ot"}` from an
administrator session.

A switch:

1. rewrites `/etc/shakerproxy/analyzer/profile` atomically (a temporary file
   renamed over it), keeping its comments and the package's format, one
   `SHAKERPROXY_ANALYZER_PROFILE=standard|ot` line, root-owned, mode 0644;
2. recreates only the Zeek and Suricata containers
   (`shakerproxy-app restart-analyzers`; nothing else restarts, and the live
   Zeek finishes the segment it is on first);
3. waits, up to four minutes, until both analyzers report that they started
   after the switch and run the new profile, Zeek with its OT plugins
   registered (the parser status below);
4. keeps it, or else writes the previous file back byte for byte, restarts
   the analyzers again, waits for the previous profile, and says why the new
   one did not load (`ROLLED_BACK`). If the previous profile does not come back
   either the result is `ROLLBACK_FAILED`: run `sudo shakerproxy repair`.

Switching to the profile that already runs restarts nothing. Switches take
the appliance configuration lock (category `analyzer`), so they never overlap
an update, a repair or another switch.

The System page cannot restart containers or write `/etc` itself: the control
API queues the switch in `/var/lib/shakerproxy/analyzer-control/requests/`
(its own directory), and `shakerproxy-analyzer-control.path` starts
`shakerproxy-analyzer-control.service` (root, no capabilities, Docker over its
socket only), which reads the request without following links, refuses one
older than ten minutes or already answered, runs the same switch as the
command, and writes the outcome to
`/var/lib/shakerproxy/analyzer-control/results/`, which the control API
mounts read-only. `GET /api/v1/analyzers/profile` returns the configured
profile, what each analyzer runs, the queued switch and the latest outcome.

You can still edit the file by hand and run
`sudo systemctl restart shakerproxy-app.service`; nothing then checks the
result, and `shakerproxy status`, `sudo shakerproxy doctor` and visibility
health show any analyzer that does not run the configured profile. The package
writes the file with `standard` once and never changes it after; a file
holding anything else stops package configuration with a message saying so,
and an analyzer that cannot read it refuses to start. Both the
segment-by-segment analysis and the live Zeek pick it up. Recordings already
analyzed are not analyzed again. For development, the analyzer containers also
read `SHAKERPROXY_ANALYZER_PROFILE=ot` from their environment
(`deploy/compose.dev.yaml` passes it through).

### What the analyzers report

When it starts, each analyzer writes its parser status
(`/var/lib/shakerproxy/zeek/parser-status.json`, and Suricata's beside its
state), which analyzer health returns as `parsers`
(`GET /api/v1/analyzers/status`): the configured profile, the profile it runs,
and for Zeek the OT parser pack it verified, the ICSNPP plugins Zeek
registered from it and the script packages. Zeek gets the plugin list from a
parse-only Zeek, isolated like every parser (its own user ID, no
supplementary groups), that lists the pack's plugins (`zeek -NN`) and loads
the offline and the live policy with `ot.zeek` against it (`zeek -a`), before
it analyzes anything. It does this for the standard profile too, so a pack is
proven loadable before anyone turns the profile on; only the OT profile puts
the pack on Zeek's plugin path for analysis.

A parser problem never stops the analysis of everything else: a pack that
fails verification or does not load is replaced by the built-in pack, and if
the built-in pack does not load either, Zeek runs the standard profile. The
status then says why (`error`), `configured_profile` and `profile` differ, the
**Zeek analysis** signal of visibility health is `DEGRADED` ("industrial
protocols other than Modbus and DNP3 are only port labels"), and doctor warns.
`shakerproxy status` shows the profile on its own line, and the MCP
`system_status` tool reports `profile`, `configured_profile`, `parser_pack` and
`ot_plugins` for each analyzer.

### What the profile keeps out

`apps/analyzer-worker/zeek/ot.zeek` bounds what the parsers write:

- process values never leave Zeek: CIP `io_data`, Modbus request and response
  values and data, the register vectors of Read/Write Multiple Registers and
  the masks of Mask Write Register are excluded from their logs;
- OPC UA certificates and nonces are excluded, and the per-item detail logs
  (node IDs to read, browse results, monitored items, filters) and the value
  logs (variants, read results, writes) are off; status codes are logged only
  when they are not Good;
- cyclic (implicit) CIP I/O, which repeats every few milliseconds, is written
  at most once a minute per I/O connection;
- records another log already carries are not written twice: EtherNet/IP
  SendRRData and SendUnitData headers (the CIP inside is in `cip.log`), COTP
  data, confirm and disconnect PDUs (only the connection request, which names
  the S7 rack and slot, is kept), and Zeek's per-message `modbus.log`, which
  ICSNPP's matched request/response record replaces;
- Zeek's `policy/protocols/modbus/track-memmap.zeek` is not loaded: it keeps
  every register of every device in memory without a bound and logs old and
  new register values.
- BACnet: the property value of every ReadProperty acknowledgement and
  WriteProperty (present values, object names, anything written) and the
  password of ReinitializeDevice and DeviceCommunicationControl are excluded
  from their logs. ICSNPP writes a `bacnet.log` header for every APDU and a
  record of its own for the services it details (Who-Is, I-Am, Who-Has and
  I-Have; ReadProperty, WriteProperty and ReadRange; ReinitializeDevice and
  DeviceCommunicationControl and their answers): the header of a detailed APDU
  is not written, so one APDU is one record, and a refusal is in the same log
  as the request it refuses. An I-Am record gets the device's vendor ID, which
  ICSNPP does not log.
- IEC 60870-5-104: the analyzer reads the APCI and the ASDU's data unit
  identifier and information object addresses and never an information
  element, so no measured value, status, set point, command or qualifier can be
  logged. It holds at most one APDU (255 octets) per direction and lists at
  most 16 object addresses of one (`object_count` says how many there are).

Suricata's Modbus parser uses a 1 MB reassembly depth instead of upstream's
unlimited one, and Suricata cannot leave register and coil values out of its
Modbus records, so ingest drops them (`modbus.request/response.read/write.data`)
before storing the record. Its DNP3 records list every point of every object
(binary states, analog and counter values, set points); ingest drops the
points (`dnp3.application.objects[].points`) and keeps each object's group,
variation, qualifier, range and count, and of a control block (group 12) only
the operation, trip code, timing and status, of an analog output block
(group 41) only the status. Suricata writes those values as raw bytes,
including NUL characters, which PostgreSQL cannot store in JSON; ingest
replaces a NUL in any analyzer record with U+FFFD, where before such a record
was set aside and lost.

### How the parsers are built

The ICSNPP packages are compiled into the Zeek image at build time, from the
commits pinned in `apps/analyzer-worker/zeek/ot-packages.lock`, against the
image's own Zeek, in a builder stage (`Dockerfile.zeek`); the runtime image
gets the built plugins under `/usr/local/shakerproxy/zeek-ot` (the built-in
pack) and never the compiler. `ot.zeek` loads the packages by name
(`@load ICSNPP_Enip/scripts`, `@load icsnpp-modbus`): the analyzer puts the
active pack's `plugins/` and `scripts/` directories on `ZEEKPATH`, after Zeek's
own directories, and its `plugins/` on `ZEEK_PLUGIN_PATH`. The image stays digest-pinned like every other ShakerProxy image.
The build checks that the site policy loads without the plugins, that every
plugin is present on the OT plugin path, and that `ot.zeek` loads after both
the offline and the live policy; `suricata -T` checks `suricata-ot.yaml`.
Plugins are on Zeek's plugin path only with the OT profile: Zeek activates
every plugin it finds there, so without the profile they cannot run at all.
Parsers keep their isolation (their own user ID, no supplementary groups, a
read-only image). The packages are BSD-3-Clause; see
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). Their licence texts ship in
the image under `/usr/local/shakerproxy/zeek-ot/licenses`.

The IEC 60870-5-104 analyzer is ShakerProxy's own Spicy analyzer
(`apps/analyzer-worker/zeek/iec104/`, AGPL-3.0 like the rest of ShakerProxy),
compiled in the same builder stage by the image's own `spicyz` into
`/usr/local/shakerproxy/zeek-spicy/iec104.hlto`. `iec104.zeek`, which only
`ot.zeek` loads, loads it and registers it for TCP/2404 (by port only: no
payload signature enables it elsewhere), so the standard profile never runs it;
the build checks that Zeek without the profile knows no IEC104 analyzer and
that the profile registers it on 2404. It is part of the image, like
`ot.zeek`, not of a parser pack.

### Why ShakerProxy has its own IEC 60870-5-104 analyzer

Every candidate was checked for a licence that allows bundling and for what it
would put into ShakerProxy:

| Candidate | Licence | Why not |
|---|---|---|
| CISA ICSNPP | BSD-3-Clause | There is no ICSNPP IEC 104 package |
| Suricata 8 | GPL-2.0 | No IEC 104 app-layer parser |
| `DINA-community/icsnpp-iec60870-5-104` | BSD-3-Clause | Marked outdated by its authors, who point to cert-lv's |
| `georgemakrakis/zeek-iec104` | BSD-3-Clause | The upstream of cert-lv's, last changed in 2025 |
| `cert-lv/spicy-iec104` | BSD-3-Clause | Maintained (2026). It parses every information element into Zeek events and logs them (measured values, set points, commands), its addresses come only from about 60 per-type events, it does not check that an ASDU's length matches its objects, and its payload signature enables it on any TCP stream that starts with 0x68 (an "h") on any port |

ShakerProxy's analyzer reads only the frame structure, checks the APDU length
(4 to 253) and that an ASDU's length matches its type's object size, count and
structure before it reports any address (`length_valid`; otherwise the record
says how many objects the ASDU claims and lists none), and stops at the first
APDU that does not start with 0x68, which Zeek reports as an analyzer
violation. A run over 23,753 packets of mutated APDUs, truncated streams and
random bytes on TCP/2404 produced no Zeek error.

## Signed parser packs

A signed OT parser pack replaces the built-in parsers without a new image:
the same six ICSNPP packages (the built-in pack's: EtherNet/IP, S7comm, OPC UA
Binary, BACnet, Modbus and DNP3), prebuilt for one Zeek version and one
architecture, signed with the release key like every
[signed content](signed-content.md) bundle (kind `OT_PARSER_PACK`).

```text
sudo shakerproxy analyzer pack preview ot-parser-pack.json   # verify, show packages, commits, compatibility
sudo shakerproxy analyzer pack activate ot-parser-pack.json
sudo shakerproxy analyzer pack rollback                      # the previous pack
sudo shakerproxy analyzer pack rollback --builtin            # the image's own pack
shakerproxy analyzer pack status
```

A pack bundle carries two artifacts, both bound by the signed bundle
manifest: `ot-parser-pack.json`, the pack manifest (each package's name, its
full commit SHA, its kind, plugin name and directory; the Zeek version and
architecture; and the path, size and SHA-256 of every built file), and
`ot-parser-pack.tar`, exactly those files. `go run ./tools/otparserpack build`
turns a built image's `/usr/local/shakerproxy/zeek-ot` into the two artifacts
for the release to sign; it never sees a key.

Activation:

1. **validate**: the release key's signature over the bundle manifest, the
   artifacts' sizes and digests, the pack manifest (exactly the six packages
   `ot.zeek` loads, so a pack built for a release before BACnet is refused, in their fixed directories, at full commits; clean relative
   paths inside them or `licenses/`; every plugin with its marker and shared
   object; at most 512 files, and at most 24 MiB in the bundle), every archived file against its
   digest (an archive holding a link, a device or an unlisted file is
   refused), and the pack's Zeek version and architecture against what the
   analyzer runs. Nothing changes before all of this passes;
2. **stage**: the bundle is stored with the other signed content, and the
   files are written to `/var/lib/shakerproxy/ot-parser-packs/packs/<revision>`
   (directories 0555, files 0444, shared objects 0555, owned by root), checked
   again, and renamed into place complete;
3. **point** the analyzers at it: `active.json` in the pack root names the
   revision and the SHA-256 of its staged manifest;
4. **restart** only the analyzers;
5. **prove** it: Zeek verifies every staged file against the manifest when it
   starts, loads the pack into its parse-only check, and must report that
   pack with exactly its plugins and no parser error;
6. **commit**, or roll back automatically: `active.json` goes back to the last
   known good pack (the built-in one when there is none), the analyzers
   restart again, and the state records `AUTO_ROLLED_BACK` with the reason.

The Zeek container mounts the pack root read-only, and its parsers, under
user IDs of their own, read the packs through their world-readable modes;
nothing in the container can write them. The pack lifecycle keeps its state in
`/var/lib/shakerproxy/rulesets/ot-parser-pack.json` (current, previous,
pending, last result, the last 64 steps), never in signed content's
`state.json`, which releases before this one decode strictly; `rules update`
refuses a pack. A staged file changed on disk is caught the next time Zeek
starts, which then uses the built-in pack and says so. An activation
interrupted by a power loss leaves `pending` set: Zeek still verifies whatever
`active.json` names, and `sudo shakerproxy analyzer pack rollback` returns to
the last known good pack.

**Why prebuilt plugins, not packages built on the appliance**: building ICSNPP
packages with `zkg` at runtime needs a compiler, CMake and Zeek's headers in
the runtime image and network access to the package sources, and it runs
upstream build scripts as root on the appliance; the build result would also
differ from what was reviewed. A prebuilt pack keeps the runtime image free of
compilers, is byte-for-byte what the release built and signed, and is
verified file by file. The cost is that a pack is tied to one Zeek version
and one architecture: each Zeek image needs its own pack (the analyzer refuses
a pack for another Zeek), and a new Zeek release ships a new built-in pack
with its image.

`tests/integration/analyzer-profile.sh` proves this against the real Zeek
image, one container at a time: the worker reports the standard and the OT
profile with the built-in plugins, loads a staged pack made from the image's
own parsers, and falls back to the built-in pack when a staged file is
changed.

## The industrial projection

Stored with the event in `normalized_events.industrial` (a bounded JSON
object, at most 2048 bytes) and returned on every event row as `industrial`
(the `IndustrialProjection` schema in the OpenAPI document). Ingest validates
it before storing it and every reader validates it again; a record that does
not fit is stored without one rather than with a misleading one.

| Field | Meaning |
|---|---|
| `protocol` | `modbus`, `dnp3`, `enip`, `s7comm`, `opcua`, `bacnet` or `iec104` (protocol catalog IDs) |
| `operation` | The analyzer's name for what was asked, in lower snake case: `read_holding_registers`, `get_attributes_single`, `write_variable`, `plc_stop`, `open_secure_channel`, `write_property`, `i_am`, `c_sc_na_1`, `startdt_act` |
| `operation_class` | `read`, `write`, `control` (start, stop, reset, operate), `program` (upload, download, configuration), `diagnostic`, `identity`, `session` (connect, register, secure channel) or `other` |
| `state_changing` | `true` when the operation can change the device or the process, `false` when it cannot, absent when the protocol does not say (a vendor-specific CIP service, an OPC UA method call) |
| `direction` | `request`, `response`, or `exchange` (a request matched with its response in one record) |
| `status`, `exception` | The device's answer when it is not plain success, and whether it refused or failed: a Modbus exception, a CIP general status, an S7 error, an OPC UA status code, a BACnet error, reject or abort, an IEC 104 negative confirmation or unknown type, cause or address |
| `unit_id` | The Modbus unit identifier |
| `modbus` | `function`, `function_code`, `register_start`, `register_count`, `exception` |
| `cip` | `command` (encapsulation), `service`, `service_code`, `class_id`, `class_name`, `instance_id`, `attribute_id`, `status_code`, and `identity` (`vendor_id`, `vendor`, `device_type_id`, `device_type`, `product_code`, `revision`, `serial`, `product_name`) |
| `s7` | `message_type`, `function`, `function_code`, `subfunction`, `subfunction_code`, `plus`, `rack`, `slot`, `block_type`, `block_number`, `module`, `serial` |
| `opcua` | `message_type`, `service`, `security_policy`, `security_mode`, `endpoint_url`, `status_link` (ICSNPP's status code link: on a response, its service result's; on a status record, the one it belongs to), `status_source` (on a status record: `ResponseHeader` or the service whose per-item results it is of, such as `Write`) |
| `dnp3` | `function`, `reply_function`, `iin`, `object_type`, `object_count`, `control`, `sequence` (the application layer sequence number a solicited response repeats from its request; Suricata only) |
| `bacnet` | `service`, `pdu_type`, `invoke_id`, `object_type`, `object_instance`, `property`, `array_index`, `error` (the error code, reject or abort reason), `device_instance`, `vendor_id` and `vendor` (an I-Am), `device_state` (what ReinitializeDevice or DeviceCommunicationControl asks for) |
| `iec104` | `frame` (`I`, `S`, `U`), `u_function`, `type_id` and `type_name` (`C_SC_NA_1`), `cot` and `cot_name` (`act`, `actcon`, `actterm`, `spont`, `inrogen`), `negative`, `test`, `originator_address`, `common_address`, `object_count`, `ioas` (the first 16 information object addresses) |

BACnet services are classified by what they do: reads (ReadProperty,
ReadPropertyMultiple, ReadRange, COV subscriptions and notifications), writes
(WriteProperty, WritePropertyMultiple, list and object changes, time
synchronization), control (ReinitializeDevice, DeviceCommunicationControl,
LifeSafetyOperation), program (AtomicWriteFile; a ReinitializeDevice that
starts a backup or restore), identity (Who-Is, I-Am, Who-Has, I-Have). IEC 104
types: monitor-direction information is a read; single, double and regulating
step commands are control and set points and bitstrings writes, all
state-changing; interrogation and read commands are reads (a counter
interrogation's state change is unknown, since it can freeze and reset
counters); clock synchronization is a write, reset process control, parameters
program; STARTDT and STOPDT are session, TESTFR and test commands diagnostic.
A command's activation (`act`, `deact`) and a read command are requests;
confirmations, terminations and everything the outstation reports are
responses.

`opcua.security_mode` is the mode a client opened a secure channel with
(`none`, `sign`, `sign_and_encrypt`): observed security, which protocol
classification uses instead of assuming it from the port
(`IndustrialProjection.ObservedSecurityMode` in Go). The record's own
`protocol_visibility` is `CLEARTEXT` for `none` and `sign` and
`ENCRYPTED_METADATA` for `sign_and_encrypt`, and protocol discovery and device
reports give the connection record of the same session that visibility
instead of `UNKNOWN` ([protocol discovery](protocol-discovery.md#reading-visibility-and-coverage)).
On a `get_endpoints` record it is what the server offers, not what anyone
used, and changes nothing.

The schema change is additive and keeps the schema version: v0.1.0-beta.42 and
earlier start on the same database after a rollback, read it, and write rows
without the column. When this release starts again it reads those rows, and
the projection backfill (projection version 9; 8 in 0.1.0-beta.44, 7 in
0.1.0-beta.43) fills their industrial projection for the last 30 days.
Releases up to 0.1.0-beta.44 refuse a projection that names BACnet or IEC 104:
a rollback to one of them first clears those projections
(`shakerproxy-app downgrade-industrial-protocols`, in bounded batches; the
records, their payload and classification stay) and leaves the rows at
projection version 8, and the next upgrade's backfill projects them again. Those releases also refuse an OT policy (`ot-policy.json`) naming BACnet
or IEC 104, and with it every OT finding: the same rollback hook
(`shakerproxy-app downgrade-ot-policy`) moves the accepted peers and
acknowledged identities naming them into `ot-policy.rollback.json` next to
the policy, keeping the file's owner and mode, and this release's control
API merges them back into the policy (as it is by then, edits of the older
release included) when it starts again and removes that file. Both steps
are idempotent; an interrupted one completes on the next run. A rollback
across several releases (0.1.0-beta.45 to 0.1.0-beta.42) runs every mapping
the target needs, the industrial ones first, then the protocol value
mapping. The rollback's protocol value mapping
([protocol discovery](protocol-discovery.md#limits)) leaves the column as it
is; the rows it maps are recomputed, industrial projection included, by the
next upgrade's backfill.

## Querying

| Field | Values |
|---|---|
| `ot.protocol` | `modbus`, `dnp3`, `enip`, `s7comm`, `opcua`; `ot.protocol:*` is every industrial record |
| `ot.operation` | An operation name; `*` is a wildcard: `ot.operation:write_*` |
| `ot.operation_class` | `read`, `write`, `control`, `program`, `diagnostic`, `identity`, `session`, `other` |
| `ot.state_changing` | `true`, `false`, or `unknown` (the protocol does not say) |
| `ot.exception` | `true` or `false` |
| `modbus.function`, `cip.service`, `s7.function`, `opcua.service`, `bacnet.service` | The operation of that protocol's records, written in snake case or as the analyzer names it: `cip.service:"Set Attribute Single"`, `s7.function:plc_stop`, `bacnet.service:WriteProperty` |
| `bacnet.object_type` | A BACnet object type: `bacnet.object_type:analog_value`, `"Analog Output"`, `binary_*` |
| `iec104.type_id` | A type identification, by number or name: `iec104.type_id:45`, `iec104.type_id:C_SC_NA_1`, `iec104.type_id:C_*` (every command and control-direction type) |
| `iec104.cot` | A cause of transmission, by number or name: `iec104.cot:7`, `iec104.cot:actcon`, `iec104.cot:spont` |
| `modbus.unit` | A unit identifier, with `>`, `>=`, `<`, `<=` |
| `opcua.security_mode` | `none`, `sign`, `sign_and_encrypt` |
| `opcua.security_policy` | A policy name: `opcua.security_policy:None` |

Examples: `type:industrial AND ot.state_changing:true` (everything that could
change a process), `ot.operation_class:program` (program uploads and
downloads), `opcua.security_mode:none` (unprotected OPC UA channels),
`modbus.unit:1 AND ot.exception:true`, `ot.protocol:bacnet AND
ot.state_changing:true` (BACnet writes, reinitializations, communication
control), `iec104.type_id:C_* AND iec104.cot:actcon AND ot.exception:true`
(refused IEC 104 commands).

The Traffic view's **Industrial** chip is `type:industrial`: industrial
records, and connections an analyzer (not just the port) identified as an
industrial protocol, such as the connection record of an S7 or EtherNet/IP
session ([stream types](traffic-stream-types.md)). Alerts stay under Alerts.
The event drawer shows an **Industrial** section with the projection, and the
MCP traffic tools (`search_traffic`, `device_activity`, `follow_traffic`)
return it as `industrial` on each event, with the same query fields.

## OT policy findings

The industrial projection says what each controller was asked to do; the
**OT policy** says what is expected, and ShakerProxy reports what deviates.
These are policy deviations backed by records, not vulnerabilities: a write
from the engineering laptop is normal when the policy allows the laptop, and
reported when it does not.

A controller here is the responder of an industrial exchange (Zeek's
`id.resp_h`, the record's destination), and a peer is the side that asked.
A broadcast or multicast destination is never a controller: an IPv4 or IPv6
multicast group (`224.0.0.0/4`, `ff00::/8`), the limited broadcast
`255.255.255.255`, and the directed broadcast (and network) address of the
lab's IPv4 prefix, which the control API takes from the network plan and the
gateway's neighbor table. A BACnet discovery message (Who-Is, I-Am, Who-Has,
I-Have) is part of no relationship and no operation whatever its
destination: a Who-Is is evidence about its sender, an I-Am identifies the
device that sent it, so a broadcast Who-Is and the I-Am answers make no
controller of the broadcast address and no peers of the senders.

| Rule | Reported when | Severity |
|---|---|---|
| `ot-program-or-control` | A program or configuration transfer (S7 upload or download, any `program` operation), a start, stop or reset (`control` operations, S7 PLC Stop, CIP Reset, DNP3 operate, BACnet ReinitializeDevice and DeviceCommunicationControl, IEC 104 single, double and regulating step commands and reset process; a DNP3 select alone is not), or Modbus Diagnostics (function 8, which can restart communications) happened outside every maintenance window, or from a source that is not allowed. Always notable: it is quiet only from an allowed source inside a window. | Critical when state-changing from a source that is not allowed; otherwise High |
| `ot-unexpected-state-change` | Any other operation that can change the device or the process (`state_changing: true`: Modbus writes, CIP Set Attribute, S7 Write Var, OPC UA Write, BACnet WriteProperty, IEC 104 set points and clock synchronization) from a source that is not allowed. With *writes need a maintenance window*, also an allowed source's writes outside every window. With no allowed sources configured for the controller, every write is reported (Medium) so you can review them and allow the right sources. | High; Medium without allowed sources or outside a window |
| `ot-new-peer` | A (controller, peer, protocol) relationship first seen after the controller's baseline. The baseline is every relationship seen in the learning period (default 24 hours after the controller's first industrial record), or before the time you accepted the baseline. | High when the new peer changed something; otherwise Medium |
| `ot-identity-changed` | A controller reported a different identity than before: CIP List Identity's vendor, product, revision or serial, S7 module identification, or a BACnet I-Am's vendor (and vendor ID) or device instance (the product, `BACnet device 1077`). A CIP or S7 identity is the responder's; an I-Am identifies the device that sent it, usually to a broadcast address, so its identity is its sender's (the finding's records are `src.ip:` the device's). The finding has the old and new values and when each was seen; *alternating* means the old identity was reported again later (two devices may share the address). | Medium for a revision (firmware) change; High for a different vendor, product or serial |
| `ot-opcua-security-below-policy` | An OPC UA secure channel opened with a weaker security mode than the policy minimum (default Sign). An endpoint a server only offers (GetEndpoints) is not observed security, and a channel whose security was not observed is never a finding. | High for None; Medium for Sign below SignAndEncrypt |

A finding is deduplicated per (controller, peer, rule, operation) and counts
its records; when both Zeek and Suricata decoded the same requests, the
sensor that saw more counts them, once, and a refusal any of them recorded
counts. A response only adds its refusal to the request it answers
(`refused`, and its status `refused_status`): a CIP or S7 answer names its
service, and a DNP3 control's answer, which ICSNPP and Suricata log as a
plain `RESPONSE`, and an OPC UA status record are paired with the request
they answer (below). Each finding carries its controller and
peer (named by the device inventory when it knows them), protocol, operation,
first and last time, count, its first and last record (record ID, kind,
capture session, flow, client and server, which locate the packets in the
recording), a Traffic query for every record, a plain-English explanation and
the policy change that accepts it.

### The policy

`ot-policy.json` in the control API's data directory, a file of its own that
no older release reads. A global part applies to every controller; a
controller's own entry (by device ID, or by IP address for a controller with
no inventory device) adds allowed sources and maintenance windows to the
global ones and can replace the OPC UA minimum and the learning period.

| Setting | Meaning | Default |
|---|---|---|
| Allowed sources | IP addresses, CIDR prefixes or device IDs of the engineering workstations, HMIs and SCADA servers allowed to change controllers (at most 64 per entry) | none |
| Maintenance windows | Weekly (days, start time, duration, IANA time zone) or one-off (start and end, at most 7 days), at most 16 per entry and 64 in all | none |
| Writes need a maintenance window | Also report allowed writes outside every window | off |
| OPC UA minimum | `none`, `sign` or `sign_and_encrypt` | `sign` |
| Learning period | Hours after a controller's first industrial record during which every new relationship joins its baseline (1 to 720) | 24 |
| Notifications | Send each new finding as a SECURITY_ALERT notification of kind `ot.<rule>` | off |

Edit it under **Policy → OT policy** in the web UI, or with the API. Every
finding's accept button applies its own change, which
`POST /api/v1/ot/policy/actions` takes as the finding's `accept` object:

| Action | Change |
|---|---|
| `allow_source` | Add the peer to the controller's allowed sources |
| `accept_peer` | Accept the relationship (peer, and protocol or every protocol) into the controller's baseline |
| `accept_baseline` | Accept every relationship seen so far; ends the learning period early |
| `accept_identity` | Acknowledge the controller's current identity; a later change is reported again |
| `set_opcua_minimum` | Set the controller's OPC UA minimum to the observed mode |

`PUT /api/v1/ot/policy` replaces the whole policy and names the revision it
was edited from (`409` when someone changed it since); the policy is
validated and an invalid one is refused with what to correct. Reading needs
`devices:read`; changing needs an administrator session or `lab:write`.

### Where findings show

- **Device report**: a device that has industrial activity as a controller
  gets an **OT policy** section with its findings, its baseline state and the
  accept buttons, and one summary finding per OT rule among the report's
  findings, so the printable report, the HTML and JSON exports, the Tests
  workspace and run comparisons include them. A report never fails because
  the OT evaluation did; the section then says so.
- **Policy → OT policy** lists the findings of every controller for a window.
- `GET /api/v1/ot/findings?window=24h` (or `start`/`end`; `device=` for one
  controller, with which `session=` also works), `devices:read` and
  `traffic:read`.
- MCP `ot_findings` and `ot_policy`; CLI `shakerproxy ot findings [<ref>]` and
  `shakerproxy ot policy`.
- Notifications: with *Notify about new OT findings* on, each finding of the
  last 15 minutes is a SECURITY_ALERT of kind `ot.<rule>`, delivered by the
  security alert rules (device scope, minimum severity and channels) under
  Integrations → Notifications, once per ten-minute de-duplication window.
  No new notification trigger is added, so an older release reads the
  notification configuration unchanged.

### How it stays fast

ingestd's private `/v1/industrial-activity` aggregation never groups a
plant's polling. Only the notable records (state-changing, control and
program operations, Modbus diagnostics) and OPC UA secure channels are
grouped per controller, peer, sensor, record kind and operation (at most
1,000 groups, state-changing ones first), from a partial index of just those
records; each notable record is checked against the maintenance window
occurrences, and each group's first and last record is read by its exact
time. Relationships come from a `(destination_ip, source_ip, protocol,
occurred_at)` index of industrial records: a bounded walk over every
controller's distinct (peer, protocol) pairs (one index probe each, at most
64 controllers and 256 relationships per controller), and for each its first
record of the whole stored history, its first and last record in the window,
and its requests in the window, counted up to 1,000 ("more than 1,000").
A DNP3 `dnp3_control` or `dnp3_objects` record details a message `dnp3.log`
already records (one per control block or object header), and an
`opcua_binary_opensecure_channel` record the OpenSecureChannel `opcua_binary`
records, so neither is a request of its own: a READ of four data classes is
one request, and so is a secure channel. An OPC UA Acknowledge answers the
Hello. When Zeek and Suricata both decoded a relationship, the analyzer that
counted more requests stands for it (up to 2,001 requests are read, so either
count can pass the cap), as it does for a finding.
A DNP3 SELECT, OPERATE or DIRECT_OPERATE request is paired with its answer:
the first solicited `RESPONSE` after it on the same flow, from the same
sensor and log, within 30 seconds and before the master's next request
(other than a CONFIRM), with the same application sequence number when both
records carry one (Suricata's do; ICSNPP's do not). An unsolicited response
answers nothing. The answer's refusal (a control status such as Not
Authorized) is the request's. The lookup is one probe of the relationship
index per such request.
An OPC UA request's refusal is a status record of its own
(`opcua_binary_status_code_detail`, written only when a status is not Good).
A refused service result is linked to its message (`opcua.status_link`, the
message's `status_code_link_id`); a refused per-item result (`status_source`
the service, such as `Write`) is paired with the latest request of that
service before it on the same connection and sensor, within 30 seconds. A
status the client sent (the status of a value it writes) is not a refusal.
Status records are details, never requests. The group and the finding carry
the refusal's status (`refused_status`: BadUserAccessDenied, Not Authorized,
ILLEGAL_DATA_ADDRESS).
Identities come from a partial index of the few records that carry one, on
the address each identifies (a CIP or S7 answer's responder, a BACnet I-Am's
sender). The three indexes are built by `EnsureEventIndexes`, partition by partition with
`CREATE INDEX CONCURRENTLY`, never in the migration. Every statement has a
3-second limit, and JIT compilation is off for them (compiling the
per-request answer lookup took longer than running it).
`TestPostgresIndustrialActivityOnALargeHistory` times a month of polling from
40 controllers and 60 peers, 2% of it writes, 1% DNP3 direct operates, each
with its answer, and 1% OPC UA writes, one in seven refused by a status
record: with 2,000,000 records (`SHAKERPROXY_OT_PERF_ROWS=2000000`) every
controller over 31 days took 0.98 s (it reaches the 512-relationship bound,
which the findings name), one controller 0.11 s and every controller over 24
hours 0.16 s on a laptop.

### Limits

- Writes are grouped record by record, so a plant whose controllers are
  written cyclically (millions of writes in the window) can exceed the
  3-second budget over 30 days; the request then says to use a shorter window
  or one controller (the device report always asks for one controller).
- At most 64 controllers and 256 (peer, protocol) relationships per
  controller are walked, 512 relationships, 1,000 operation groups and 256
  identity observations are read, 512 maintenance window occurrences are
  checked and 500 findings are listed. A bound is never silent: the findings
  (`GET /api/v1/ot/findings`, the device report's `ot` section, `shakerproxy
  ot findings`, the MCP `ot_findings` tool) carry `partial: true` and
  `capped`, which names each bound reached with its limit (`operations`,
  `controllers`, `peers`, `relationships`, `assets`, `identities`,
  `findings`, `maintenance_ranges`), and `truncated: true` when one left
  something out. A relationship polled more than 1,000 times in the window
  is counted as 1,000 (`requests_capped`, "more than 1,000 requests"): it is
  `capped` as `requests` with the number of such relationships, and makes
  the findings `partial` without `truncated`. Policy → OT, the device report
  and its printed copy show a note saying what was left out.
- A controller's baseline is computed from the stored history: once its
  first records are deleted by retention, its learning period starts at the
  oldest one still stored. Accept the baseline to fix it in time.
- A device report covers the device as a controller, not as the peer: open
  the controller's report, or Policy → OT, for an engineering workstation's
  writes.
- Identity changes need identity records (CIP List Identity, S7 module
  identification, BACnet I-Am); a controller that is never asked who it is
  cannot be checked. The identity index is on the address a record
  identifies (the responder, or an I-Am's sender) and replaces the
  destination-only index of 0.1.0-beta.44, which `EnsureEventIndexes` drops
  once the new one is built. A CIP identity record names the device by the connection's
  responder, so a broadcast List Identity is attributed to whoever answered
  on that connection.
- Maintenance windows in a time zone use the zone's rules embedded in the
  control API; a one-off window is entered in the browser's local time and
  stored in UTC.
- A DNP3 control's answer is paired by order on its flow (and by sequence
  number where Suricata logged one): an answer more than 30 seconds after
  its request, or one the sensor missed while it saw the next request, is
  no request's. ICSNPP writes one `dnp3_control` record per control block,
  so every block of a request is paired with its message's answer, and a
  refusal of one block counts against each block of that message.
- When Zeek and Suricata both decoded a relationship, its request count is
  the larger of the two, not their union: requests that each analyzer saw
  but the other missed are counted only by the one that counted more.
- An OPC UA per-item refusal (a Write result such as BadUserAccessDenied)
  is linked by ICSNPP only to the service's detail log (`opcua_binary_write`
  and the like), which the OT profile does not write because it carries node
  IDs and values, so it is paired by order: with the latest request of that
  service before it on the connection, within 30 seconds. With two writes
  outstanding at once, a refusal of the earlier one counts against the
  later. A status record does not name its secure channel; the connection
  (one secure channel at a time in practice) stands for it. A refused
  service result (`ResponseHeader`) is linked to its message exactly.

## Fixtures and proof

`tests/integration/otfixture` generates synthetic recordings from the protocol
specifications (no real plant or customer data); capture files are never
committed (`go run ./tests/integration/otfixture -pcap-dir DIR` writes them for
Wireshark or `zeek -r`). Each recording is pinned by its SHA-256.

| Recording | What it holds | Proven from packet to event API |
|---|---|---|
| `enip-cip` | RegisterSession, ListIdentity of a made-up Logix controller, a CIP Get_Attribute_Single and a refused Set_Attribute_Single | Zeek (`enip`, `cip`, `cip_identity`) and Suricata (`enip`): session, identity, read, refused write |
| `s7comm` | COTP connect to rack 0 slot 2, setup, Read Var, Write Var, PLC Stop | Zeek (`cotp`, `s7comm`): rack and slot, read, write, control |
| `s7comm-plus` | COTP to a named TSAP (`SIMATIC-ROOT-ES`); a session creation (CreateObject, protocol version 1); then, on a second connection, integrity-protected (version 3) SetMultiVariables, GetMultiVariables, a SetVariable the PLC refuses with an error return value, and DeleteObject | Zeek (`s7comm_plus`, `cotp`): write and read functions and codes, request and response, session end; the version 1 message as an operation `unknown`; no rack or slot from a named TSAP |
| `opcua-binary` | Hello, OpenSecureChannel with security policy None, Read, a Write refused with BadUserAccessDenied, CloseSecureChannel | Zeek (`opcua_binary`, `opcua_binary_opensecure_channel`, `opcua_binary_status_code_detail`): observed security mode, read, write, refusal |
| `modbus` | Read holding registers, write a register, a write refused with an exception | Zeek (`modbus_detailed`) and Suricata (`modbus`): unit, register range, exception |
| `dnp3` | An integrity poll (class 1, 2, 3 and 0 data), select-before-operate of a relay, a direct operate refused (Not Authorized), a cold restart refused with IIN2 "function code not supported", an unsolicited response with a binary input event and its confirm | Zeek (`dnp3`, `dnp3_control`, `dnp3_objects`) and Suricata (`dnp3`): polls read and change nothing, operate and direct operate change state, select does not, the refused control's status, the IIN error as an exception, the unsolicited response; the connection under Industrial |
| `port-collisions` | HTTP to TCP/44818 and TCP/4840, text to TCP/102 | No industrial projection, not under Industrial |
| `dnp3-port-collisions` | Text to TCP/20000 | No DNP3 record, no projection, a port label only (`PORT_HEURISTIC`) |
| `bacnet` | A Who-Is broadcast and the I-Am a made-up air handler controller broadcasts (device 1077, vendor 0), ReadProperty of an analog input's present value and of the device's object name, a WriteProperty the device refuses (property, write-access-denied), a ReinitializeDevice (warm start, with a password) it accepts | Zeek (`bacnet_discovery`, `bacnet_property`, `bacnet_device_control`): identity, object and property, read, refused write, control; no property value or password in any record |
| `iec104` | STARTDT, a general interrogation (C_IC_NA_1) with its activation confirmation, the interrogated single points (SQ, three objects) and its termination, an S-frame, a single command (C_SC_NA_1) the RTU refuses with a negative confirmation, a spontaneous single point, a malformed measured value (its ASDU shorter than its object count), TESTFR | Zeek (`iec104`): frame types, type and cause names, addresses, the command as state-changing control, the negative confirmation as an exception, no address read from the malformed ASDU; the connection under Industrial |
| `bacnet-iec104-port-collisions` | Text to UDP/47808, a line of text starting with "h" (0x68, an IEC 104 start octet) and HTTP to TCP/2404 | No BACnet or IEC 104 record, no projection, port labels only |

- `internal/ingest/testdata/industrial` holds the OT profile's Zeek records
  (`zeek-<recording>-<log>.ndjson`) and Suricata app-layer records
  (`suricata-<protocol>.ndjson`) for those recordings, whose digests
  `tests/integration/otfixture` pins, and the golden projection of each Zeek
  record (`TestIndustrialProjectionOfTheCommittedRecordings`); after changing
  the generator or the parsers, run the profile over the recordings again
  (`zeek -C -r <recording>.pcap LogAscii::use_json=T` with the site policy and
  `ot.zeek` and `ZEEK_PLUGIN_PATH` set, as the Zeek image runs it; Suricata
  with `suricata-ot.yaml`) and update both.
- `TestPostgresIndustrialEventsRoundTripAndQuery` stores them through the
  real write path and checks every query field against the projections;
  `TestPostgresIndustrialColumnSurvivesARollbackToBeta42` applies beta.42's
  schema over this one, reads and writes with beta.42's columns, and migrates
  back.
- `tests/integration/ot-smoke.sh` (`make ot-smoke`, and the CI analyzer job)
  builds both analyzer images, analyzes the recording with the OT profile, and
  checks the industrial fields of the normalized events the event API returns,
  that the port collisions have none, and that the standard profile produces
  no ICSNPP records.

## Limits

- DNP3: a response to SELECT, OPERATE or DIRECT_OPERATE in `dnp3_control`
  (and in Suricata's `dnp3`) is the control's status, not which request it
  answers (both log it as `RESPONSE`); OT policy findings pair it with the
  request it answers on the same flow ([How it stays fast](#how-it-stays-fast)), and in Traffic
  the matched `zeek.dnp3` record names the pair. SELECT is `state_changing:
  false`: it arms a control, and the OPERATE that follows changes the
  process. There is no `dnp3.function` query field; use
  `ot.protocol:dnp3 AND ot.operation:direct_operate`. Internal indications
  are `dnp3.iin` (IIN1 << 8 | IIN2); an IIN2 failure flag (function code not
  supported, object unknown, parameter error, event buffer overflow, already
  executing, configuration corrupt) makes the response an exception with the
  flags as its status.
- S7comm-plus: ICSNPP logs only the message header (protocol version, opcode,
  function), never a return value, so a refused S7comm-plus request is not an
  exception. It reads every header as integrity-protected: a version 1
  message, which has no integrity part (session creation, older S7-1200
  firmware), is misread, recorded with operation `unknown`, and Zeek parses
  nothing more on that connection. CreateObject and DeleteObject (session
  creation and end, and the same functions for other objects) are `session`
  with `state_changing` unknown, because ICSNPP does not log which object.

- OPC UA with `sign_and_encrypt` (or `sign`) hides the service of every
  message after OpenSecureChannel; only the channel and its security are seen.
- S7comm-plus with integrity protection is parsed only as far as ICSNPP does
  (opcodes and functions); S7 rack and slot come from the COTP connection
  request, which other ISO-on-TCP protocols on TCP/102 (IEC 61850 MMS) also
  use; only an S7-style called TSAP (connection type 1 to 3) gives a rack and
  slot.
- PROFINET and other industrial protocols remain port labels.
- BACnet: ICSNPP logs an error's code, not its class, and only the first octet
  of an I-Am's maximum APDU length (1476 arrives as 5), so ShakerProxy records
  neither; a Reject or Abort names no service. BACnet/IP through a BBMD
  (Forwarded-NPDU) is parsed only as far as ICSNPP does, and BACnet over MS/TP
  or Ethernet is not seen. A record to a directed broadcast address of a subnet
  the control API does not know (another subnet on a mirror port) is that
  address's, as for any address, unless it is a discovery message. A BACnet
  relationship whose first 20,000 records are all discovery messages is
  taken for discovery alone.
- IEC 60870-5-104: one analyzer per TCP connection; after the first octets
  that do not start an APDU the rest of the connection is not parsed (Zeek's
  `analyzer.log` names the violation). File transfer (`F_*`) types are
  `other`, with their addresses only when their objects have a fixed size;
  private types (128 to 255) are named `type_<n>`. IEC 104 secured with TLS
  (IEC 62351-3) is opaque. Only TCP/2404 is analyzed.
- A connection record whose only analyzer is `cotp` (ICSNPP confirmed the
  ISO session layer, not S7) is S7 only by its TCP/102 port: it carries
  `CARRIER_AND_PORT` evidence, so it is listed under Other, not Industrial.
  On any other port COTP alone names no protocol.
