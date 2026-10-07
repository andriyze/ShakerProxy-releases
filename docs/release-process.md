# Signed release process

ShakerProxy releases bind host code, Compose configuration, and all runtime images
to one signed manifest. The implementation is experimental until published
artifacts pass the declared clean-VM matrix.

## Trust and key custody

`packaging/release-public.pem` is the sole release trust root. Its PKIX DER
SHA-256 fingerprint is:

```text
e8c3c965ed4859f55e69af55ccb03d20d297843104b611f0a754072694dafdcb
```

The matching private RSA-3072 key must be held outside the repository. GitHub
Actions expects its base64 encoding only in the protected `release`
environment secret `SHAKERPROXY_RELEASE_SIGNING_KEY_B64`. Require reviewer approval
for that environment, restrict tag creation, and keep the secret unavailable to
pull-request workflows. Never print, upload, cache, or package the private key.

The earlier development key (fingerprint `3ff54cdd…434a`) was retired on
2026-09-30, before any release was published; nothing signed with it is
trusted.

Key rotation is a source release: commit a new public key and fingerprint,
review every pinned-fingerprint location, ship the new installer through an
already trusted channel, and document the old key's retirement. Replacing a
GitHub secret alone cannot rotate trust.

## Automated publication

`.github/workflows/release.yml` pins every third-party action to an exact commit.
Its default token only reads, no checkout keeps a token in `.git/config`, and
the work is split so that the signing key and a token that can change a GitHub
release never share a job with third-party build code:

1. `verified` (no secret) refuses a commit that is not on `main` and waits for
   every `verify` push run of that commit (up to 90 minutes). One failed run
   stops the release; re-run or fix it, then re-run the release. A cancelled
   run counts neither way.
2. `identity` resolves the version and channel and refuses one already
   released.
3. `checks` runs the complete repository verification (`make verify`, the
   history audit and the release regressions) with a read-only token.
4. `build` (may push packages, nothing else) builds the Debian host package,
   publishes six first-party linux/amd64 images to GHCR with provenance and
   SBOM attestations, records their digests, and assembles the unsigned
   release, which it hands on as a workflow artifact. The pinned upstream
   PostgreSQL digest is the seventh image.
5. `sign-and-publish` (the `release` environment, may write releases) checks
   out the same commit afresh and runs only the reviewed scripts with the
   runner's `openssl`, `jq`, `tar`, `zstd`, `python3` and `gh`. It rebuilds the
   installer, bootstrap, trust root, Compose bundle and manifest and compares
   each byte for byte with the build job's; any difference stops the release
   unsigned. It then signs, destroys the key before anything else runs, runs
   the tamper and clean-Ubuntu verification smokes, and uploads the assets.
   The host package and the image digests cannot be rebuilt there; they are
   the build job's, bound by the signed manifest.
6. Still in `sign-and-publish`, the release goes public (see below).

## Public releases repository

The development repository is private; installs and updates read the public
repository [andriyze/ShakerProxy-releases](https://github.com/andriyze/ShakerProxy-releases),
which holds nothing but releases and the files on its `main` branch
(`install/index.sh`, a README from `packaging/public-repo/README.md`, `docs/`,
`LICENSE` and `THIRD_PARTY_NOTICES.md`). After the signed release is published
here, two more steps of `sign-and-publish` run
`scripts/publish-public-release.sh`:

- `fetch`, with this repository's own token, downloads the release just
  published, checks that it has exactly the signed assets, that the key is the
  pinned one, the manifest signature, every checksum the manifest lists, that
  `images.json` equals the signed image digests, that `bootstrap.sh`,
  `install.sh` and `release-public.pem` are the commit's source, and that each
  file equals what the job signed. It writes `git archive` of the commit as
  `shakerproxy-<version>-source.tar.gz` (the AGPL source).
- `publish` is the only step with `RELEASES_REPO_TOKEN`, a fine-grained token
  with Contents read/write on the public repository only, stored in the
  `release` environment. It fails at once when the token is missing, cannot
  read the repository, or cannot push, and when the repository is not public.
  It updates `main` (unless a newer release is already there), then creates the
  release on the same tag with the same assets, title, notes and prerelease
  flag, plus the source archive and its SHA-256 in the notes, and publishes it
  only after reading back every asset's checksum.

Re-running is safe. `publish` updates an existing public release instead of
failing: identical assets are skipped, others replaced by the verified files,
stray assets removed. If the public step fails, use "Re-run failed jobs": the
re-run of `sign-and-publish` signs the same files again (the signature is
deterministic), finds its own release already published here with exactly
those assets, leaves it alone and retries only the public publication. Any
other existing release of that version still stops the job.

To publish an existing release by hand (for example one released before the
public repository existed), from a checkout with the tag and `gh` logged in
with access to both repositories:

```bash
git fetch --tags origin
scripts/publish-public-release.sh all --tag v0.1.0-beta.41 --main-from origin/main
```

`--main-from` names the commit whose installer, README and docs go on `main`
(releases before the public repository have no public README and an
installer that points at the private repository, so the helper refuses
them); pass `--skip-main` to leave `main` alone once it exists.
`scripts/publish-public-release.sh verify --assets <dir> --version <version>`
checks a downloaded release without changing anything.

Releases are reproducible where the tools allow it: the host package and the
Compose bundle are byte-identical for the same commit (sorted names, owner
0:0, every time set to the commit time, `SOURCE_DATE_EPOCH`), and images are
built with `SOURCE_DATE_EPOCH` and `rewrite-timestamp`, so their layers and
configuration repeat; the pushed image index also holds provenance, whose
build times differ. Each image is stamped with the release version (its
`org.opencontainers.image.version` label; the control API compares its own with
the host package's in the diagnostics the System page and API show). The manifest is checked against
`packaging/release-manifest.schema.json` and against the installer's own
rules before it is signed, again by the bundle smoke, and at install.

GitHub immutable releases and build-provenance attestations for the release
assets are repository settings and steps that are not enabled yet.

An install, an update (with its pruning of old releases and the disk check)
and an update whose health check fails are proven by hermetic tests that
replace systemd, apt and Docker (`tests/security`), and by hand on a real
host; no CI job runs them under real systemd yet. GitHub's KVM runners could
(the Wi-Fi proofs in `verify.yml` boot a VM there), but such a job has to
build two releases with all their images, sign them with a test key the
installer copy trusts, and serve them from a registry the VM can pull from.

A stable tag is `v<semver>`. A tag containing a prerelease suffix becomes a
beta release. Manual runs require an explicit version and channel. Stable
publication is not complete until an independent operator downloads every
asset from GitHub, verifies the signature and checksums, and records the
clean-VM acceptance evidence.

Required release assets are:

- `bootstrap.sh` and `install.sh`
- `manifest.json` and `manifest.json.sig`
- `release-public.pem`
- `shakerproxy-host.deb`
- `compose-bundle.tar.zst`
- `images.json` for operator inspection

The bundle contains `bundle-files.sha256`; runtime startup rechecks every listed
file. The signed manifest declares supported Ubuntu versions, architecture,
profiles, config and database schemas, minimum resources, artifact hashes, and
the exact seven image digests.

## Local candidate build

The local signing key path below is an example and must remain ignored:

```bash
make package-smoke PACKAGE_VERSION=1.2.3-beta.1
make release-bundle-smoke \
  PACKAGE_VERSION=1.2.3-beta.1 \
  SIGNING_KEY=/secure/path/release-signing-key.pem \
  IMAGES_JSON=/secure/path/published-images.json
```

`packaging/build-push-images.sh` is intentionally push-only. It refuses a
non-GHCR repository and emits image references only after Buildx reports a
digest and registry inspection succeeds. Do not substitute mutable tags in a
manifest.

## Release acceptance and failure rules

A candidate is not stable merely because the workflow is green. Record at
least clean installs on Ubuntu 24.04 and 26.04, same-version idempotency,
repair of a deliberately corrupted bundle file, update from the prior stable
version, schema-compatible rollback, service and host reboot, uninstall with
preserved data, purge behavior, Docker restart, low-disk failure, interrupted
download, bad signature, bad artifact hash, and unavailable registry behavior.

No release may claim air-gapped support until the bundle includes verified OCI
archives. No release may claim rollback across a schema change until an
explicit backward-compatibility contract and migration evidence exist.
