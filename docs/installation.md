# Installation and release lifecycle

The signed release lifecycle is implemented and remains **experimental** until
the repository publishes a release and the complete clean-VM install, repair,
update, rollback, and uninstall matrix is recorded. The capability registry
is authoritative; source code or a passing
container smoke test is not a release claim.

## Before you start

- A dedicated Ubuntu Server 24.04 or 26.04 machine (amd64) with systemd. Other
  hosts are refused unless you pass `--developer-unsupported`.
- One network port for the uplink and one port (or Wi-Fi) for the devices
  under test.
- At least 20 GiB free under `/var/lib` and 2 GiB under `/opt`. An update of an installed
  appliance needs 4 GiB under `/var/lib` for the new release's images.
- Port 8443 free on the appliance (management HTTPS on loopback).

Docker Engine with Compose v2 is reused when present and installed from the
Ubuntu archive when missing. Snap Docker is refused.

## Quick install

Run as a regular user with sudo rights on the appliance:

```bash
curl -fsSL https://raw.githubusercontent.com/andriyze/ShakerProxy-releases/main/install/index.sh | sh
```

[`install/index.sh`](../install/index.sh) checks the machine (Ubuntu version,
amd64, not a container, systemd), picks the release, downloads its
`bootstrap.sh` and runs it with sudo; the bootstrap and installer verify the
signed release as described below. It installs the newest stable release, or,
while no stable release is published (every release so far is a beta), the
newest beta, and says so. `SHAKERPROXY_DRY_RUN=1`, `SHAKERPROXY_VERSION` (for
example `SHAKERPROXY_VERSION=0.1.0-beta.39`), `SHAKERPROXY_CHANNEL` and
`SHAKERPROXY_OFFLINE_BUNDLE` are listed in [install/README.md](../install/README.md).
Run the same command again to upgrade: it installs the newest release of the
channel the appliance runs, and does nothing when that release is already
installed. To review each step yourself instead, follow the sections below.

Releases, this installer and these guides are published in the public
repository [andriyze/ShakerProxy-releases](https://github.com/andriyze/ShakerProxy-releases);
installing or updating needs no GitHub account or token. ShakerProxy's
development repository is private.

### Appliances on 0.1.0-beta.41 or older

An appliance installed from 0.1.0-beta.41 or earlier looks for updates in the
former repository, which is now private, so `sudo shakerproxy update` there
fails with "could not find a published beta release" (or cannot download the
release). Upgrade it once with the one-line installer above, run on the
appliance:

```bash
curl -fsSL https://raw.githubusercontent.com/andriyze/ShakerProxy-releases/main/install/index.sh | sh
```

It keeps the appliance's channel, profile, configuration and data, like any
update; add `SHAKERPROXY_DRY_RUN=1` before `sh` to check first. From then on
`sudo shakerproxy update` finds new releases again. Releases up to
0.1.0-beta.41 are also on the public repository, but their own `bootstrap.sh`
still downloads from the former repository: install one of them only from a
copied bundle (`SHAKERPROXY_OFFLINE_BUNDLE`, see
[install/README.md](../install/README.md)).

## 1. Download and check the host (changes nothing)

Download the installer of the release you want from its
[release page](https://github.com/andriyze/ShakerProxy-releases/releases), for example
the beta 0.1.0-beta.39:

```bash
curl --proto '=https' --tlsv1.2 -fsSLO \
  https://github.com/andriyze/ShakerProxy-releases/releases/download/v0.1.0-beta.39/install.sh
sudo bash install.sh --dry-run --channel beta --version 0.1.0-beta.39
```

A beta needs both `--channel beta` and `--version`: the 0.1.0-beta.39
installer assumes the stable channel without `--channel`, and no stable
release is published yet.

Once a stable release is published, `releases/latest/download/install.sh` is
the newest stable installer, and `sudo bash install.sh --dry-run` checks that
release.

The dry run checks host support, Docker and Compose, port 8443, free disk,
missing tools, and downloads and verifies the signed release manifest into a
temporary directory. It installs nothing, changes no service, firewall, route,
DNS, DHCP, or RA setting, and writes no installer log. It exits `1` when it
finds a blocking problem. `--dry-run` cannot be combined with `--repair`,
`--rollback`, or `--uninstall`.

From a source checkout, the dry run is the only installer operation that is
safe to run:

```bash
sudo ./packaging/install.sh --dry-run --developer-unsupported
```

## 2. Install

Run the installer with the same options as the dry run, without `--dry-run`:

```bash
sudo bash install.sh --channel beta --version 0.1.0-beta.39
```

For a stable installer from `releases/latest/download`, that is
`sudo bash install.sh`.

Download, review, and then run the installer rather than piping it to root;
see [one-line install](one-line-install.md) for the bootstrap trust chain. The
installer does not trust the transport alone: it restricts downloads to this
repository, pins the ShakerProxy RSA-3072 public-key fingerprint, verifies the
release-manifest signature, and checks the Debian package and Compose-bundle
SHA-256 values before any mutation. Every runtime image is an immutable
`repository@sha256:digest` reference. The release public key is committed at
`packaging/release-public.pem`; the private key is not in the repository (see
[release process](release-process.md)).

| Option | Effect |
| --- | --- |
| `--version 1.2.3` | Install an exact signed release (`1.2.3-beta.1` is a beta) |
| `--channel beta` | Install the newest beta; without `--channel` an update follows the installed release's channel (nightly needs `--version`) |
| `--profile core` | Management services only (`standard` adds traffic analysis; `full`, the default for a new install, also adds HTTPS decryption). Without `--profile`, an update or repair keeps the installed profile |
| `--offline-bundle /media/shakerproxy-release` | Use signed assets copied to the host |
| `--no-docker-install` | Require the Docker Engine and Compose v2 already installed |
| `--http-proxy URL`, `--https-proxy URL` | Proxy for the installer's curl and apt-get downloads |
| `--developer-unsupported` | Allow an unsupported development host |

Proxies apply to the installer's own downloads. Docker image pulls use the
Docker daemon's proxy settings. `--offline-bundle` makes release verification
independent of GitHub, but the bundle does not contain image archives: the
host still needs registry access for first-time image pulls unless those exact
digests are present, so it is not an air-gapped install.

Installation never enables routing, DHCP, DNS enforcement, packet capture, or
interception. ShakerProxy starts in `SETUP_SAFE` and opens only the loopback
management listener; network changes need an explicit, previewed, watchdog-
protected, confirmed plan (see [networking](networking.md)). Once you confirm a
lab plan, DNS forwarding and the automatic lab recording start by default;
HTTPS decryption stays off until you turn it on for a device.

## 3. First login

Management HTTPS listens on the appliance's loopback only; the installer never
opens a firewall port or an external management bind. On the appliance itself,
open `https://127.0.0.1:8443/`. From your workstation, keep an SSH tunnel open:

```bash
ssh -N -L 8443:127.0.0.1:8443 <admin>@<sensor-ip>
```

Open `https://127.0.0.1:8443/`, which matches the locally issued management
certificate ([management TLS](management-tls.md)). If port 8443 is already in
use on your workstation, forward any other local port instead, for example
`ssh -N -L 9443:127.0.0.1:8443 <admin>@<sensor-ip>` and open
`https://127.0.0.1:9443/`; `localhost` and `[::1]` work on any port too.
Create the admin account
with the one-time setup token, then remove its plaintext receipt:

```bash
sudo cat /etc/shakerproxy/setup-token
sudo rm /etc/shakerproxy/setup-token
```

Only the token's SHA-256 verifier is mounted into the control service.
Removing the receipt does not regenerate it on upgrade.

Keep the recovery codes shown at setup; they reset a forgotten password (see
[recover admin access](#recover-admin-access)).

## 4. Use the CLI

Sign the `shakerproxy` CLI in once. It creates a 90-day API token and stores it
in `~/.config/shakerproxy`, readable only by you (with `sudo`, root's token lives
in `/etc/shakerproxy/secrets` instead):

```bash
shakerproxy login
shakerproxy devices
shakerproxy status
```

`status`, `doctor`, `ports` and `capture` use the gateway daemon's socket,
which the `shakerproxy-host` group may open. The installer adds the user who ran it
through sudo to that group; the change applies at their next login, so use
`sudo` until then. Add another administrator with
`sudo usermod -aG shakerproxy-host <user>`.

The group alone is not enough: the daemon also checks who connected (the
kernel's peer credentials). Root and the control API may use every request.
A user listed in `shakerproxy-host` may use what the CLI does without sudo
(status, diagnostics, capture and export, the lab recording, bypass and
`network off`), and gets a "run it with sudo, or use the dashboard" answer for
configuration changes such as network plans, the traffic policy or VPN peers.
A service that only runs in the group (no account listed in it) is refused
everything, so the lab DHCP server (Kea, which runs in its own `_kea` group)
or any other service could never use the socket even if it gained the group.

Run `shakerproxy` for an overview and `shakerproxy help <command>` for examples. The
CLI exits `0` on success, `1` on failure (including `doctor` finding a failed
check), and `2` on wrong usage; add `--json` for scripts.

Network plans are normally built on the **Network** page of the web UI. To
check a plan file from the shell, use `shakerproxy config validate plan.json`
(validation only) or `shakerproxy plan plan.json` (full preview). The file format
is `schemas/network-plan/network-plan.schema.json`. Neither command changes
the host.

## Update, repair, rollback, and removal

```bash
sudo shakerproxy update
sudo shakerproxy update --version <version>
sudo shakerproxy update --channel stable
sudo shakerproxy update --profile <profile>
sudo shakerproxy repair
sudo shakerproxy rollback
sudo shakerproxy app status
sudo shakerproxy network off
sudo shakerproxy uninstall
sudo shakerproxy uninstall --remove-images
sudo shakerproxy uninstall --purge-data
```

`update` follows the channel the appliance was installed from (beta or
stable). `update --version <version>` installs exactly that release, even an
older one, so name a version only to repeat or test a specific release.

`network off` stops routing the lab and restores the host's network as it was
before the running plan was applied (the same restore the watchdog performs).
The web UI does the same with **Turn off lab network** on the Network page.
Uninstall refuses while a lab is routed, so run it first; it is also how you
start over with a different plan.

`update` installs the newest signed release of the channel the appliance runs
(the `channel` in `/opt/shakerproxy/current/release.json`): a beta appliance
gets the newest beta from GitHub's release list, a stable one GitHub's latest
release. It changes nothing when that release, or a newer one, is already
installed. `--version` installs
an exact release instead, and `--channel` switches channel. Without
`--profile` it keeps the installed profile, so a `core` or `standard` host
stays without HTTPS decryption. `sudo shakerproxy update --profile <profile>`
(`core`, `standard` or `full`) switches profile; when the newest release is
already installed, it changes only the profiles. The installed, key-pinned
installer downloads and verifies the release, starts it only after Compose
validation, and counts it healthy only when the dashboard answers and the
gateway, DNS and traffic-policy daemons stay up, the gateway answering as the
new host package. Only the current and previous releases are kept: once the
new release is healthy, the installer removes the other release directories
and the container images only they pinned (by digest; images the kept
releases share, and images ShakerProxy did not pull, stay). Event history,
captures and configuration are not in release directories and are never
removed. Each kept release keeps its signed host package. If the new release fails,
the installer puts back the previous application, its host package and the
`current` and `previous` links, except when the two releases declare
different database or config schema versions and the new one has already
started: it may have migrated the database, which the previous release cannot
read, so the new release stays installed and the installer says so. `repair`
recreates missing runtime directories and validates the
current signed release; if integrity or startup validation fails, it
retrieves that exact signed version and replaces it atomically, restoring
the original directory if the repair fails.

Once, when updating from v0.1.0-beta.39 or earlier: `update` runs the
installer already on the host. Those older installers look only for stable
releases, so `update` fails while only betas exist, and they choose `full`
when no `--profile` is given. Update such a host once with the one-line
installer, which runs the new release's signed installer, and name its
profile:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/andriyze/ShakerProxy-releases/releases/download/v<version>/bootstrap.sh \
  | sudo bash -s -- --release <version> --channel beta --profile standard
```

From then on `update` follows its channel and profile. For a stable release,
download `releases/latest/download/bootstrap.sh` and leave out `--release` and
`--channel`. A host that an older `update` already moved to `full` goes back
with the same command: installing the version it already runs with another
`--profile` changes only its profiles.

`rollback` swaps `current` and `previous`, reinstalls the previous release's
host package when that release kept one (releases installed before host
packages were kept move the application only, and say so), validates the
target, and restores the original links and host package on failure. It
refuses rollback when the two releases declare different config or database
schema versions; ShakerProxy does not claim reversible database migrations.

Analyzer state is not rolled back. The record of segments skipped over their
per-segment analysis budget is kept in files of its own
(`status-over-budget.json`, and `<capture>.over-budget.json` beside each
checkpoint and active progress file) that 0.1.0-beta.39 ignores, so after a
`rollback` or a failed `update` its analyzers start and carry on from the
state the newer release left.

An update that moves Zeek or Suricata to another version keeps the analyzer
state too: the analyzers log `analyzer engine upgraded from X to Y` once,
record the new version in `status.json`, and carry on without analyzing
again what the previous version analyzed. A signed OT parser pack built for
the previous Zeek is refused by the new one, and the analyzer loads its
built-in parsers until a pack for the new Zeek is activated
([industrial protocols](industrial-protocols.md)). Up to 0.1.0-beta.46 an
analyzer stopped on state that named another engine version, so the update
to 0.1.0-beta.46 (Suricata 8.0.6 to 8.0.7, Zeek 8.2.1 to 9.0.0) failed and
was put back on every appliance with analyzer state; update straight to a
later release. Those releases cannot be changed, so a `rollback` (or a failed
`update` that puts one back) from 0.1.0-beta.47 or later first sets the
engine versions in `/var/lib/shakerproxy/zeek/status.json` and
`/var/lib/shakerproxy/suricata/status.json` to the ones the older release
runs (`shakerproxy-app downgrade-analyzer-state`, read from its compose
file). A rollback whose state cannot be rewritten is refused and leaves the
current release running.

Before rolling back to 0.1.0-beta.39 or earlier, delete any saved view that
filters on router logs (`source:NETWORK_GEAR`) or a flow (`flow.id`): those
releases cannot read such a view, so their Saved views list fails and the view
cannot be deleted there. If that already happened, `update` back to this
release, delete the view, then roll back again.

`uninstall` acquires the configuration lock and refuses to remove the host
package while routed state, an unresolved network transaction, or a degraded
network status exists. VPN mode needs no lab and is not refused: once
gatewayd is stopped, `uninstall` removes the `wg-lab` interface and the
`SHAKERPROXY-VPN-*` chains, so no VPN device keeps routing through the host
unrecorded (its settings stay in `/var/lib/shakerproxy`). It preserves
pre-existing Docker and unrelated firewall state, and keeps `/etc/shakerproxy`
and `/var/lib/shakerproxy`. Container images stay unless you pass
`--remove-images`, which removes the images the installed releases pinned.
`--purge-data` also deletes those ShakerProxy-owned paths and the images after
you type `PURGE` (add `--yes` for automation); it is not guaranteed secure
erasure on SSD or copy-on-write storage.

`shakerproxy doctor` (and the System page) warns when the host package and the
application are different releases, which an update or rollback that stopped
half-way leaves. The warning names the command that puts them back in step:
`sudo shakerproxy update --version <release> --channel <channel>` installs the
application's release again, host package included. `sudo shakerproxy repair`
does the same without a download, from the host package the release kept
(it downloads the signed release only when that copy is missing or does not
start); a host package older than this repair leaves its own package alone,
so use the update there.

Releases live under `/opt/shakerproxy/releases/<version>`, with atomically
replaced `/opt/shakerproxy/current` and `/opt/shakerproxy/previous` symlinks.
`shakerproxy-app.service` validates the signed manifest, pinned key, release
metadata, exact image set, and every extracted bundle file before it invokes
fixed Docker Compose arguments with `--pull never`. Re-running the same release
is idempotent; a same-version collision with different content fails closed.
Immediately before its first mutation, the installer acquires the appliance-
wide configuration lock and rejects unresolved network transactions (see
[configuration lock](configuration-lock.md)).

## Recover admin access

A forgotten administrator password is reset in the web UI with one of the
recovery codes shown at setup (`POST /api/v1/auth/recover`). Without a code,
reset the account from the appliance:

```bash
sudo shakerproxy admin reset
```

After you type `RESET`, the control service clears the administrator and every
session and writes a new one-time setup token to
`/var/lib/shakerproxy/control-api/setup-token`; the command prints it. Complete
setup again in the web UI and run `shakerproxy login`. An admin reset does not
revoke API tokens unless you add `--revoke-api-tokens`
(`sudo shakerproxy admin reset --revoke-api-tokens`, after a suspected
compromise); otherwise review them in the web UI or with
`shakerproxy token list` and revoke any you no longer trust with
`shakerproxy token revoke`. A recovery code can do the same (tick **Also revoke
all API tokens**), and a signed-in administrator can change the password on
the Integrations page, which signs out every other session. See
[the threat model](threat-model.md#administrator-sessions-and-password-confirmation).

## Diagnose problems

```bash
sudo shakerproxy doctor
sudo shakerproxy logs
sudo shakerproxy logs gatewayd -f
sudo shakerproxy logs control-api
```

`doctor` returns the same bounded, read-only diagnostic report as the
dashboard. An unavailable probe is `UNKNOWN`, never silently healthy; the
command does not apply networking, restart services, or modify capture state.
See [diagnostics](diagnostics.md).

A real install, update, repair, or rollback appends its output to
`/var/log/shakerproxy/install.log`. A failed one also creates a mode-`0640`
`/var/log/shakerproxy/install-failure-<timestamp>-<pid>.tar.gz` containing only
that log and a bounded host summary (OS, kernel, interface names, Docker
versions, failed unit names, and `shakerproxy doctor`). When the failed
release's containers had started, it also holds, under `containers/`, the
last 200 log lines and the state with recent health check output
(`docker inspect` `.State`) of each application container that had exited or
was not healthy, recorded before the previous release replaced them. It never collects
environment variables, configuration files, enrollment tokens, service
credentials, packet data, TLS keys, or CA private keys.

When Ubuntu's automatic updates (apt-daily, unattended-upgrades) are
installing packages, the installer logs that it is waiting for another package
run and waits up to 10 minutes for the package lock. If the lock is still held
after that, it stops with `Could not get lock` and a failure bundle, as for
any failed step; let the other run finish (`systemctl status unattended-upgrades apt-daily.service`)
and run the same command again.

## Runtime data and credentials

The Debian post-install hook idempotently provisions every host path and
secret used by production Compose and records the numeric capture and
HTTPS-edge groups in `/etc/shakerproxy/compose.env`. Upgrading a valid legacy file
that contains only the capture group preserves it and atomically adds the edge
group; unknown keys or mismatched values fail closed. Service credentials are
independent mode-`0400` files below the root-traversable-only
`/etc/shakerproxy/secrets` directory. Token collisions, symbolic links, malformed
values, and a PostgreSQL password/URL mismatch stop package configuration
rather than rotating credentials silently. A `systemd-tmpfiles` rule creates
the volatile `/run/lock/shakerproxy` configuration-lock directory, and
OpenSSH's `/run/sshd` (`0755 root:root`): under Ubuntu's default `ssh.socket`
activation that directory appears only after the first SSH login, and without
it `sshd -T`, which the SSH lockout guard reads, fails and host inspection
stops. The hook creates it too when OpenSSH is installed and it is missing.

The hook also writes the event retention setting once, to
`/etc/shakerproxy/ingestd/event-retention`: 30 days on a new install, and 0
(keep every event until disk space runs low) on an install that already held
a database, so updating from beta.40 or earlier deletes no history. Updates,
repairs, and rollbacks keep the file as it is; it is not part of
`compose.env`, which older host packages require to hold only the group IDs.
To change the retention, edit the number and run
`sudo systemctl restart shakerproxy-app.service`; see
[event retention](capture-and-storage.md#event-retention). The installer's
closing summary shows the retention in effect.

The package also creates the `shakerproxy-edge` group and provisions management
PKI before the application starts. `shakerproxy repair` refuses corrupt,
incomplete, or purpose-confused PKI material instead of replacing the trust
root. `shakerproxy management-ca status` and `shakerproxy management-ca export
<destination>` inspect and export the public management CA; export never
copies private material and never overwrites a destination.

## Test local DNS forwarding

DNS forwarding needs no setup. Once a lab plan is confirmed, **Force plain DNS
through ShakerProxy** is on by default: every lab device's plain DNS, to any
resolver, is answered by ShakerProxy and forwarded to the host's own resolvers
(or the upstreams you set on **DNS & HTTPS**). **Block encrypted DNS** is off by
default; turn it on there or with `shakerproxy dns block-encrypted on` to make
devices fall back to plain DNS. Check the switches with `shakerproxy dns`, then
verify UDP and TCP from a lab device with `dig`. Full commands, failure
behavior, and limitations are in
[DNS forwarding and encrypted-DNS policy](dns-forwarding.md).

## Current Ubuntu 26.04 evidence

The [shared-VPS safe-runtime exercise](testing/evidence/foundation/UBU2604-001/README.md)
proves package installation/upgrade, hardened daemon startup, the development
observation stack, authenticated requests, restart-safe native detections,
database fault recovery, analyzers, and isolated Linux packet-path laboratories
on Ubuntu 26.04. It is intentionally not described as a clean-host, gateway,
reboot, or interception certification. Those remain release gates.
