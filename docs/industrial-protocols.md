# Industrial protocols (OT)

ShakerProxy shows what industrial devices on the lab network are asked to do
and how they answer: Modbus/TCP, DNP3, EtherNet/IP and CIP, Siemens S7comm and
S7comm-plus, and OPC UA Binary. Each such record carries an **industrial
projection**: the protocol, the operation, what kind of operation it is,
whether it can change the device or the process, the device's answer, and the
protocol's own identifiers (a Modbus unit and register range, a CIP service
and object, an S7 rack and slot, an OPC UA service and security mode). It
never carries process values: no register, coil, tag, I/O or OPC UA variant
value is stored.

## What works without the OT profile

Zeek's own Modbus and DNP3 analyzers run on every install. Their records
(`zeek.modbus`, `zeek.dnp3`) get an industrial projection, appear under the
Traffic view's **Industrial** chip, and can be queried with the fields below.
Every other industrial protocol is only a port label without the profile:
traffic to TCP/102 or TCP/44818 is shown as `s7comm` or `enip` with
`PORT_HEURISTIC` evidence and is listed under Other, not Industrial, because
the port alone proves nothing.

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
| Zeek | CISA ICSNPP plugins for EtherNet/IP and CIP (`enip`, `cip`, `cip_identity`, `cip_io` logs), S7comm, S7comm-plus and COTP (`s7comm`, `s7comm_plus`, `s7comm_read_szl`, `s7comm_upload_download`, `s7comm_known_devices`, `cotp`) and OPC UA Binary (`opcua_binary`, `opcua_binary_opensecure_channel`, `opcua_binary_get_endpoints_description`, `opcua_binary_status_code_detail`), and ICSNPP's Modbus and DNP3 logging (`modbus_detailed`, `modbus_mask_write_register`, `modbus_read_write_multiple_registers`, `modbus_read_device_identification`, `dnp3_control`, `dnp3_objects`) |
| Suricata | Its Modbus, DNP3 and EtherNet/IP app-layer parsers on their detection ports (502, 20000, 44818), logged to EVE (`suricata.modbus`, `suricata.dnp3`, `suricata.enip`), so rules can use the Modbus, DNP3 and ENIP keywords |

Turn it on by editing `/etc/shakerproxy/analyzer/profile`:

```text
SHAKERPROXY_ANALYZER_PROFILE=ot
```

then run `sudo systemctl restart shakerproxy-app.service`. `standard` turns it
off again. The package writes the file with `standard` once and never changes
it after; a file holding anything else stops package configuration with a
message saying so, and an analyzer that cannot read it refuses to start. Both
the segment-by-segment analysis and the live Zeek pick it up. Recordings
already analyzed are not analyzed again. For development, the analyzer
containers also read `SHAKERPROXY_ANALYZER_PROFILE=ot` from their environment
(`deploy/compose.dev.yaml` passes it through).

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

Suricata's Modbus parser uses a 1 MB reassembly depth instead of upstream's
unlimited one, and Suricata cannot leave register and coil values out of its
Modbus records, so ingest drops them (`modbus.request/response.read/write.data`)
before storing the record. Suricata writes those values as raw bytes,
including NUL characters, which PostgreSQL cannot store in JSON; ingest
replaces a NUL in any analyzer record with U+FFFD, where before such a record
was set aside and lost.

### How the parsers are built

The ICSNPP packages are compiled into the Zeek image at build time, from the
commits pinned in `apps/analyzer-worker/zeek/ot-packages.lock`, against the
image's own Zeek, in a builder stage (`Dockerfile.zeek`); the runtime image
gets the built plugins under `/usr/local/shakerproxy/zeek-ot` and never the
compiler. The image stays digest-pinned like every other ShakerProxy image.
The build checks that the site policy loads without the plugins, that every
plugin is present on the OT plugin path, and that `ot.zeek` loads after both
the offline and the live policy; `suricata -T` checks `suricata-ot.yaml`.
Plugins are on Zeek's plugin path only with the OT profile: Zeek activates
every plugin it finds there, so without the profile they cannot run at all.
Parsers keep their isolation (their own user ID, no supplementary groups, a
read-only image). The packages are BSD-3-Clause; see
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). Their licence texts ship in
the image under `/usr/local/shakerproxy/zeek-ot/licenses`.

Loading signed parser packages at runtime, without a new image, is a later
step: it would use [signed content](signed-content.md) bundles verified like
the Suricata ruleset.

## The industrial projection

Stored with the event in `normalized_events.industrial` (a bounded JSON
object, at most 2048 bytes) and returned on every event row as `industrial`
(the `IndustrialProjection` schema in the OpenAPI document). Ingest validates
it before storing it and every reader validates it again; a record that does
not fit is stored without one rather than with a misleading one.

| Field | Meaning |
|---|---|
| `protocol` | `modbus`, `dnp3`, `enip`, `s7comm` or `opcua` (protocol catalog IDs) |
| `operation` | The analyzer's name for what was asked, in lower snake case: `read_holding_registers`, `get_attributes_single`, `write_variable`, `plc_stop`, `open_secure_channel` |
| `operation_class` | `read`, `write`, `control` (start, stop, reset, operate), `program` (upload, download, configuration), `diagnostic`, `identity`, `session` (connect, register, secure channel) or `other` |
| `state_changing` | `true` when the operation can change the device or the process, `false` when it cannot, absent when the protocol does not say (a vendor-specific CIP service, an OPC UA method call) |
| `direction` | `request`, `response`, or `exchange` (a request matched with its response in one record) |
| `status`, `exception` | The device's answer when it is not plain success, and whether it refused or failed: a Modbus exception, a CIP general status, an S7 error, an OPC UA status code |
| `unit_id` | The Modbus unit identifier |
| `modbus` | `function`, `function_code`, `register_start`, `register_count`, `exception` |
| `cip` | `command` (encapsulation), `service`, `service_code`, `class_id`, `class_name`, `instance_id`, `attribute_id`, `status_code`, and `identity` (`vendor_id`, `vendor`, `device_type_id`, `device_type`, `product_code`, `revision`, `serial`, `product_name`) |
| `s7` | `message_type`, `function`, `function_code`, `subfunction`, `subfunction_code`, `plus`, `rack`, `slot`, `block_type`, `block_number`, `module`, `serial` |
| `opcua` | `message_type`, `service`, `security_policy`, `security_mode`, `endpoint_url` |
| `dnp3` | `function`, `reply_function`, `iin`, `object_type`, `object_count`, `control` |

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
the projection backfill (projection version 7) fills their industrial
projection for the last 30 days. The rollback's protocol value mapping
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
| `modbus.function`, `cip.service`, `s7.function`, `opcua.service` | The operation of that protocol's records, written in snake case or as the analyzer names it: `cip.service:"Set Attribute Single"`, `s7.function:plc_stop` |
| `modbus.unit` | A unit identifier, with `>`, `>=`, `<`, `<=` |
| `opcua.security_mode` | `none`, `sign`, `sign_and_encrypt` |
| `opcua.security_policy` | A policy name: `opcua.security_policy:None` |

Examples: `type:industrial AND ot.state_changing:true` (everything that could
change a process), `ot.operation_class:program` (program uploads and
downloads), `opcua.security_mode:none` (unprotected OPC UA channels),
`modbus.unit:1 AND ot.exception:true`.

The Traffic view's **Industrial** chip is `type:industrial`: industrial
records, and connections an analyzer (not just the port) identified as an
industrial protocol, such as the connection record of an S7 or EtherNet/IP
session ([stream types](traffic-stream-types.md)). Alerts stay under Alerts.
The event drawer shows an **Industrial** section with the projection, and the
MCP traffic tools (`search_traffic`, `device_activity`, `follow_traffic`)
return it as `industrial` on each event, with the same query fields.

## Fixtures and proof

`tests/integration/otfixture` generates synthetic recordings from the protocol
specifications (no real plant or customer data): an EtherNet/IP session
(RegisterSession, ListIdentity of a made-up Logix controller, a CIP
Get_Attribute_Single and a refused Set_Attribute_Single), an S7comm session
(COTP connect to rack 0 slot 2, setup, Read Var, Write Var, PLC Stop), an OPC UA
session (Hello, OpenSecureChannel with security policy None, Read, a Write
refused with BadUserAccessDenied, CloseSecureChannel), a Modbus session (read
holding registers, write a register, a write refused with an exception), and
port collisions: HTTP to TCP/44818 and TCP/4840 and text to TCP/102. Capture
files are never committed (`go run ./tests/integration/otfixture -pcap-dir DIR`
writes them for Wireshark or `zeek -r`).

- `internal/ingest/testdata/industrial` holds the OT profile's Zeek records
  for those recordings, whose digests `tests/integration/otfixture` pins, and
  the golden projection of each (`TestIndustrialProjectionOfTheCommittedRecordings`);
  after changing the generator or the parsers, run the profile over the
  recordings again and update both.
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

- OPC UA with `sign_and_encrypt` (or `sign`) hides the service of every
  message after OpenSecureChannel; only the channel and its security are seen.
- S7comm-plus with integrity protection is parsed only as far as ICSNPP does
  (opcodes and functions); S7 rack and slot come from the COTP connection
  request, which other ISO-on-TCP protocols on TCP/102 (IEC 61850 MMS) also
  use; only an S7-style called TSAP (connection type 1 to 3) gives a rack and
  slot.
- BACnet, IEC 60870-5-104, PROFINET and other industrial protocols remain port
  labels.
- A connection record whose only analyzer is `cotp` (ICSNPP confirmed the
  ISO session layer, not S7) is S7 only by its TCP/102 port: it carries
  `CARRIER_AND_PORT` evidence, so it is listed under Other, not Industrial.
  On any other port COTP alone names no protocol.
