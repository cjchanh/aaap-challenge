# AAAP — Authenticated Artifact Packet challenge

A sealed evidence packet and a fail-closed verifier. Clone this repository,
check the packet against the published chain head and public key, then try
to break it.

**Needs:** Python 3.10+ and either the Python `cryptography` package or an
OpenSSL build with Ed25519 `pkeyutl -rawin` support.

**Refuses:** extra files at packet root, duplicate JSON keys, non-finite
numbers, symlinks and hardlinks, missing anchors when `--require-anchors` is
set, and any mismatch against a supplied head or public key. A packet-only
PASS is a structural check, not authorship.

Start with [CHALLENGE.md](CHALLENGE.md). AAAP v0.3 at commit
`e0fca96651b30c76d0a29bf867cdd14cdc38db00` is preserved as an immutable,
reproducibly vulnerable historical release. Attack evidence is under
`security/` and `EVIDENCE/`; the finding ledger is
[docs/AAAP_POST_RELEASE_SECURITY.md](docs/AAAP_POST_RELEASE_SECURITY.md).

## Verify

`anchors.json` at the repository root publishes the chain head and public
key. Use those published values out-of-band:

```bash
python3 packet/verify_packet.py packet \
  --expected-head 14d14281170d89f6f8b918daf6541f81e7e13549dd4c66f5b085304ff6a61724 \
  --expected-pubkey e7fb4aad8b0e0246eb6569f49d301ad88a0b54333e3de8bb57e02e118fd3716c
```

Unanchored (structural only — not authorship or freshness):

```bash
python3 packet/verify_packet.py packet
```

Packet-only PASS is not anchored — supply `--expected-head` and
`--expected-pubkey` from an out-of-band source to verify authorship and
freshness. `--require-anchors` makes the packet-only case exit 3 with
`FAIL: anchors required`.

`--anchor-registry` requires exactly two independently acquired, byte-identical
registry files; a single `anchors.json` argument is rejected. For
registry-policy verification, independently acquire both exact registry
snapshots and use `--packet-name demo/packet`:

```bash
python3 packet/verify_packet.py packet \
  --anchor-registry /path/to/independently-acquired/anchors.json \
  --anchor-registry /path/to/second-independently-acquired/anchors.json \
  --packet-name demo/packet
```

Both registries are the same GitHub account (`github.com/cjchanh`): two Git
histories, not two administrative or custodial trust origins.

## Challenge terms

Daybreak and Daybreak II were commissioned by the author. They are not
outside breaks. The success condition of this challenge is a reproducible
break by someone who was not commissioned or paid by Centennial Defense
Systems.

The v0.4 packet preserves the v0.3 `chain.jsonl`, `artifacts/`, and
`attestation.json` byte-for-byte. It regenerates the human/verification layer
and signs manifest schema v2 with the same anchored production identity. The
chain head and public key therefore remain:

- head: `14d14281170d89f6f8b918daf6541f81e7e13549dd4c66f5b085304ff6a61724`
- pubkey: `e7fb4aad8b0e0246eb6569f49d301ad88a0b54333e3de8bb57e02e118fd3716c`

## Narrow claim

A PASS authenticates the checked bytes, canonical envelope semantics, ordering,
manifest policy, and signatures under the supplied anchor. It does not prove
world truth, signing time, Keychain custody, author ownership, verifier/host
benevolence, registry freshness, or independent origin.

Hardening source: local working commit in the author's private
workspace; the published lineage is `e0fca96` -> `8f5ba31f` -> `c06b163` ->
`939b1e7` -> `9655a65` -> `06a3982` (current).

How this packet fits a larger protocol: [docs/WHERE_THIS_FITS.md](docs/WHERE_THIS_FITS.md).
