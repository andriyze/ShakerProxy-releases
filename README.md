# ShakerProxy

ShakerProxy turns a dedicated Ubuntu Server machine into a test gateway for
the devices your team is responsible for: phones, smart TVs, cameras, IoT
sensors and industrial controllers. Connect a device to it (over its VPN, an
inline bridge, its Wi-Fi, a lab port, or as the gateway on your network) and
ShakerProxy shows every connection the device makes, decrypts its HTTPS when
you install the ShakerProxy CA on it, records packets, flags security problems
with evidence, and lets you block the internet or single domains. Everything
runs on the appliance.

This repository publishes ShakerProxy's signed releases, the one-line
installer and the documentation. Development happens in a private repository;
the files on this branch are replaced by every release.

## Install

On a dedicated Ubuntu Server 24.04 or 26.04 amd64 machine, as a regular user
with sudo rights:

```bash
curl -fsSL https://raw.githubusercontent.com/andriyze/ShakerProxy-releases/main/install/index.sh | sh
```

It checks the machine, verifies the signed release and starts ShakerProxy in a
safe setup mode that changes no networking. No GitHub account or token is
needed. Run it again, or `sudo shakerproxy update`, to upgrade. Add
`SHAKERPROXY_DRY_RUN=1` before `sh` to check without installing.

An appliance installed from 0.1.0-beta.41 or earlier looks for updates in the
former repository, which is now private: upgrade it once with the command
above. The [installation guide](https://github.com/andriyze/ShakerProxy-releases/blob/main/docs/installation.md)
has the details, and [docs/](https://github.com/andriyze/ShakerProxy-releases/tree/main/docs)
holds every guide.

## Verify a release

The installer does all of this itself before anything changes. To check a
release by hand, download its `manifest.json`, `manifest.json.sig`,
`release-public.pem`, `install.sh`, `shakerproxy-host.deb` and
`compose-bundle.tar.zst` from the
[release page](https://github.com/andriyze/ShakerProxy-releases/releases), then:

```bash
# 1. The public key is ShakerProxy's release key. This must print
#    e8c3c965ed4859f55e69af55ccb03d20d297843104b611f0a754072694dafdcb
openssl pkey -pubin -in release-public.pem -outform DER | openssl dgst -sha256

# 2. The manifest is signed by that key ("Verified OK").
openssl dgst -sha256 -verify release-public.pem -signature manifest.json.sig manifest.json

# 3. Every file matches the checksum in the signed manifest.
jq -r '"\(.installer.sha256)  install.sh", "\(.host_package.sha256)  shakerproxy-host.deb",
       "\(.compose_bundle.sha256)  compose-bundle.tar.zst"' manifest.json | sha256sum --check
```

The manifest also pins every application image by digest (`images`), so the
containers the appliance runs are part of the signed release too.

## Source code

ShakerProxy is free software under the GNU Affero General Public License,
version 3 (`AGPL-3.0-only`); third-party components keep their own licenses
(see `LICENSE` and `docs/licenses/`). Every release carries the complete source
of the commit it was built from as `shakerproxy-<version>-source.tar.gz`, and
its release notes give the archive's SHA-256. Download it from the
[release page](https://github.com/andriyze/ShakerProxy-releases/releases).
