# AI agent quick connect

Status: **read-only beta**

ShakerProxy packages a read-only MCP bridge at `/usr/bin/shakerproxy-mcp`. The quickest safe connection is three steps and keeps the API token on the ShakerProxy sensor.

## 1. Create the investigator token in the Web UI

Open **Integrations → AI agents** and choose whether the AI runs on the sensor or another computer.

The wizard creates the token directly after fresh administrator-password verification. It lasts 24 hours unless you pick 7 or 30 days for a longer test campaign. The scopes are exactly:

```text
system:read
devices:read
traffic:read
captures:read
cases:read
```

All five are read scopes and none is sensitive; capture and case access is limited to summaries (no packet bytes, file names or exports).

Tick **Include HTTP content** to add the sensitive `traffic:content` scope, which lets `http_exchange` return the headers and the start of each body of recorded HTTP requests and responses (cookies, authorization and other credentials redacted). Ticking it is the sensitive-scope acknowledgement; without it the token has no sensitive scope.

The wizard does not offer write scopes. The API marks the secret `display-once`; the UI shows it only after successful creation, automatically removes it from the page after ten minutes, and provides an immediate **Hide now** control.

Do not paste the token into an AI prompt, MCP JSON, command-line argument, or shell history.

## 2. Save it on the sensor

Run as the non-root Linux account that will own the MCP bridge:

```bash
/usr/bin/shakerproxy-mcp setup
```

The command prompts for the display-once token, disables terminal echo when possible, and writes the credential atomically to the user's ShakerProxy configuration directory with private permissions. It refuses an unsafe token path or symlink destination.

For an AI client on another workstation, perform setup over an interactive SSH connection to the sensor:

```bash
ssh -t analyst@shakerproxy-sensor /usr/bin/shakerproxy-mcp setup
```

The token stays on the sensor; remote MCP does not require copying the token to the Mac or workstation.

## 3. Verify before connecting the AI

Run:

```bash
/usr/bin/shakerproxy-mcp doctor
```

or remotely:

```bash
ssh -t analyst@shakerproxy-sensor /usr/bin/shakerproxy-mcp doctor
```

Doctor verifies the private token file, management TLS trust, API authentication, and the bounded agent evidence overview, and says when the token expires. A successful connection can still report `EVIDENCE DEGRADED` when ingestion or analyzers are not ready; that is different from an authentication failure.

## Renewing the token

When the token expires or is revoked, every tool answers: *The ShakerProxy API token expired or was revoked. Create a new one in the ShakerProxy web UI under Integrations → AI agents, then run `shakerproxy-mcp setup` on the sensor.* Do exactly that: create a new token in the wizard and run `shakerproxy-mcp setup` again; it replaces the saved token, and the MCP client configuration does not change. `shakerproxy-mcp doctor` shows when the current token expires, so you can renew it before a long run.

Generate secret-free MCP configuration with:

```bash
/usr/bin/shakerproxy-mcp config local
```

or:

```bash
/usr/bin/shakerproxy-mcp config ssh analyst@shakerproxy-sensor
```

The Web UI generates the equivalent JSON interactively and provides copy buttons. The JSON never contains the API token.

## Remote account requirements

For remote MCP, prefer a dedicated or otherwise constrained Linux account that:

- uses SSH public-key authentication;
- has no sudo permission;
- has no Docker socket access;
- owns only its private MCP token file;
- cannot write ShakerProxy binaries, configuration, management CA, or interception CA;
- does not emit login banners to stdout for the MCP restricted command.

Where practical, restrict the SSH key to `/usr/bin/shakerproxy-mcp`.

## What the AI receives

30 read-only tools: `list_devices`, `find_device`, `lab_routing`, `device_report`, `device_activity`, `device_controls`, `compare_runs`, `protocols`, `search_traffic`, `event_detail`, `follow_traffic`, `traffic_summary`, `dns_lookups`, `encrypted_dns`, `tls_issues`, `http_requests`, `http_exchange`, `test_sessions`, `system_status`, `diagnostics`, `dns_visibility`, `visibility_coverage`, `vpn_devices`, `wifi_activity`, `captures`, `cases`, `syslog_collector`, `notifications`, `ot_findings` and `ot_policy` (`shakerproxy-mcp help` lists them from the server itself). `http_exchange` (HTTP requests and responses, credentials redacted) needs the sensitive `traffic:content` scope: tick **Include HTTP content** in the wizard; everything else works with the default investigator token. Devices can be named by friendly name, IP address, MAC address, or device ID, and every result includes plain-language summary lines.

Try asking:

- "What does my TV talk to?" — the agent finds the device and reads its report: domains with the company behind them and what they are for (telemetry, advertising, …).
- "Is the camera secure?" — the report's findings (for example unencrypted HTTP, outdated TLS, telnet, or accepting untrusted certificates), each with evidence and a fix.
- "What changed between firmware 1.2 and 1.3?" — the agent lists test sessions and compares the two runs: new domains, new protocols, new or resolved findings.

For the best answers, run each firmware or app version as a test session (Tests in the Web UI, or `shakerproxy test start <device>`), and record whether the ShakerProxy CA is installed on the device.

Everything it returns is metadata, with one exception: `http_exchange` returns an HTTP event's headers and the start of each body, with cookies, authorization and other credentials redacted, and only to a token that also has the sensitive `traffic:content` scope (the investigator token does not). It never exposes credentials, raw PCAP, TLS key logs, CA private keys, shell commands, network changes, capture mutation, policy mutation, or deletion tools.

Every MCP evidence result labels captured strings as untrusted data rather than instructions.

For the complete protocol, limits, tool schemas, and threat model, see `docs/mcp-agent-integration.md`.
