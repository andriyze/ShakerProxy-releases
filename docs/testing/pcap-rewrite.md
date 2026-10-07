# PCAP sanitize/rewrite verification

Run the bounded parser, rewrite, capture-store, and analyzer trust-boundary suite
with the pinned Go toolchain:

```bash
docker run --rm -v "$PWD:/src" -w /src \
  golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 \
  sh -c 'go test -race ./internal/pcapng ./internal/capture ./internal/analyzer'
```

The tests prove that selection is canonical and deterministic, time windows are
half-open, only matched packet blocks disappear, retained output is independently
parsed and hashed, and unsupported or truncated packet populations fail closed.
The store tests exercise separate staging, reserve-capacity checking, original
hash verification, rollback-link preservation, atomic rename, manifest rebinding,
durable provenance, staging cleanup, idempotent completed requests, and a failed
rewrite that leaves the only source and its manifest unchanged. Fuzz seeds drive
arbitrary PCAPNG through both inspection and rewrite parsers.

This suite validates the artifact engine. A public sanitize deletion is not
complete until its caller also clears and rebuilds every configured derived
index and verifies those acknowledgements.
