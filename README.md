# AAAP v0.4 — Hardened Post-Release Challenge

AAAP v0.3 at commit
`e0fca96651b30c76d0a29bf867cdd14cdc38db00` is preserved as an immutable,
reproducibly vulnerable historical release. This repository candidate is its
hardened successor.

The v0.4 packet preserves the v0.3 `chain.jsonl`, `artifacts/`, and
`attestation.json` byte-for-byte. It regenerates the human/verification layer
and signs manifest schema v2 with the same anchored production identity. The
chain head and public key therefore remain:

- head: `14d14281170d89f6f8b918daf6541f81e7e13549dd4c66f5b085304ff6a61724`
- pubkey: `e7fb4aad8b0e0246eb6569f49d301ad88a0b54333e3de8bb57e02e118fd3716c`

Start with [CHALLENGE.md](CHALLENGE.md). The complete v0.3 reproducer and
machine results are under `security/`; the post-release finding ledger is
[docs/AAAP_POST_RELEASE_SECURITY.md](docs/AAAP_POST_RELEASE_SECURITY.md).

## Verify

Requirements: Python 3.10+ and either the Python `cryptography` package or an
OpenSSL build with Ed25519 `pkeyutl -rawin` support.

```bash
cd packet
python3 verify_packet.py . \
  --expected-head 14d14281170d89f6f8b918daf6541f81e7e13549dd4c66f5b085304ff6a61724 \
  --expected-pubkey e7fb4aad8b0e0246eb6569f49d301ad88a0b54333e3de8bb57e02e118fd3716c
```

For registry-policy verification, independently acquire both exact registry
snapshots and use `--packet-name demo/packet`. Both repositories are controlled
by `github.com/cjchanh`: they are two Git histories, not two administrative or
custodial trust origins.

## Narrow claim

A PASS authenticates the checked bytes, canonical envelope semantics, ordering,
manifest policy, and signatures under the supplied anchor. It does not prove
world truth, signing time, Keychain custody, operator ownership, verifier/host
benevolence, registry freshness, or independent origin.

Hardening source: local working commit in the operator's private
workspace; the published lineage is `e0fca96` -> `8f5ba31f` -> `c06b163`.
