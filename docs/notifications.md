# Alerts and notifications

ShakerProxy can tell you when something notable happens, instead of waiting for
you to look. It is **off by default**: nothing is delivered until you add a
rule.

## What it can notify about

| Trigger | Fires when |
| --- | --- |
| New device | A device is first seen on the lab network. |
| Bypassing device | A device's traffic does not go through ShakerProxy (so its connections cannot be seen). |
| Cleartext exposure | A device sends a credential or secret in the clear over plaintext HTTP. |
| Flagged domain | A device contacts a domain on the bundled advertising/tracking/telemetry list. |
| Security alert | A Suricata alert or another native detection fires; and, when the OT policy's *Notify about new OT findings* is on, an OT policy finding (kind `ot.<rule>`, see [OT policy findings](industrial-protocols.md#ot-policy-findings)). |

Cleartext exposures, security alerts and flagged domains come from the
recorded traffic: every 30 seconds ShakerProxy reads the detections, Suricata
alerts and flagged names that arrived since the last check (and remembers the
position across restarts), and ignores anything that happened more than 15
minutes ago, so analysing an old capture does not announce it. If recorded
traffic cannot be read, the Integrations page says so.

A notification states **what happened and the subject** — the device, the
destination host, the finding kind. It **never contains a secret value**: the
cleartext finding it is built from keeps only the kind and location. The
device is the one that held the address when it happened, in every mode; a
device ShakerProxy does not know is named by its address, and is still its
own notification.

## Channels

- **In-app** — a bounded list in the web UI (and `shakerproxy alerts`), always
  available.
- **Webhook** — a signed JSON `POST` (HMAC-SHA256 over the body when you set a
  secret). The URL must be `https`, and delivery refuses private, loopback and
  link-local addresses.
- **Slack-compatible** — a Slack incoming-webhook body, which Slack, Mattermost
  and Discord-compatible endpoints accept. A device names itself, so its text is
  shown as written: markup in it (`<!channel>`, `<url|label>`, `@channel`) is
  escaped and pings no one.

A webhook or Slack URL can post on its own, so it is treated like a password:
once saved, the API and UI show only its service (`https://hooks.slack.com/[redacted]`).
A transient delivery failure (a timeout, HTTP 5xx or 429) is retried twice; a
rejected request (another 4xx, a private address) is not.

Webhook and Slack notifications are sent by the forwarder service
(`forwarderd`), the one ShakerProxy service with a route to the internet. The
control API, which decides what to notify, is on an internal network only; it
queues each delivery on the volume the two share, and `forwarderd` sends it.
A queued delivery carries its channel's URL and signing secret until it is sent
or given up, and is dropped when you remove or change the channel. On an
appliance installed with `--profile core` there is no forwarder service, so
only the in-app list works.

Each webhook and Slack channel shows whether its notifications arrive: how many
were delivered, failed (after the retries) or are waiting, when the last one
was delivered, and the last error while it is newer than that. If the forwarder
service has not checked in for two minutes the page says so; check it with
`sudo shakerproxy app status`. **Send test** goes ahead of notifications still
waiting to be sent, and waits up to 25 seconds for the forwarder service's
answer. If the forwarder service is running but still sending another
notification to an endpoint that is slow to answer, the test says the relay is
busy.

## Rules

A rule subscribes a trigger — optionally scoped to one device and to a minimum
severity — to one or more channels. The same trigger for the same subject is
sent **once per 10 minutes**, so a chatty condition is one notification, not a
flood; two different Suricata signatures are two notifications. Turning
notifications on does not announce devices already present, and the evaluator
remembers what it sent across restarts, so an upgrade does not repeat them.

## Where

- **Web UI:** Integrations → *Alerts & notifications*. Add channels and rules,
  send a test to any channel, and read the recent list.
- **CLI:** `shakerproxy alerts` lists recent notifications (`--json` for scripts).
- **API:** `GET/PUT /api/v1/integrations/notifications` (configuration, with
  each webhook and Slack channel's `delivery` status and whether the `relay` is
  running; changes need the administrator password),
  `POST /api/v1/integrations/notifications/test`,
  `GET /api/v1/notifications`, `POST /api/v1/notifications/read`.
- **MCP:** the read-only `notifications` tool lists recent notifications; there
  is no MCP action to change the configuration.
