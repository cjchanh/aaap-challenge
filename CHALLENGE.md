# The AAAP Challenge — Verify It, Then Try to Break It

Treat this packet and its verifier as hostile input. Review `verify_packet.py`
or run it in a disposable least-privilege environment. Hash-pinning detects a
post-build verifier swap; it does not prove producer-supplied code is benign.

## Requirements

- Python 3.10+; and
- either the Python `cryptography` package or an OpenSSL build with Ed25519
  `pkeyutl -rawin` support.

Apple's stock `/usr/bin/openssl` did not provide the needed engine in the
Daybreak clean-environment test. The verifier failed closed. Use
`cryptography` or an Ed25519-capable OpenSSL build; do not interpret an
installed `openssl` command as sufficient.

## Verify packet integrity

```bash
cd packet
python3 verify_packet.py .
```

Exit 0 verifies canonical chain meaning, exact artifact and derived-file bytes,
the full manifest v2 control body, and every present signature under the engine
set named in `verify.json`. JSON whitespace is not sealed. Duplicate keys,
non-finite numbers, symlinks, hardlinks, special files, and extra artifact-tree
entries are rejected.

## Verify current identity and revocation policy

Acquire `anchors.json` separately from both repository snapshots, record their
commit SHAs through a trusted channel, then run:

```bash
python3 verify_packet.py . \
  --anchor-registry ../anchors.json \
  --anchor-registry /path/to/aaap-anchors/anchors.json \
  --packet-name demo/packet
```

The files must be distinct and byte-identical. The selected identity must be
active and valid on the packet's declared sealing date. This checks file
agreement; it cannot prove independent acquisition or independent repository
control.

For forensic verification of an exact historic packet, use a trusted head and
pubkey together with `--expected-head` and `--expected-pubkey`. That mode
intentionally does not consult later revocation state.

## What a PASS proves

1. Sealed artifact and derived-file bytes match their authenticated hashes.
2. Canonical envelope meaning and order reach the attested chain head.
3. Every manifest policy field is authenticated, including live verification.
4. Each present signature verifies under the packet identity.
5. Anchored mode selects the expected exact packet and key; registry mode also
   enforces the revocation and validity policy in the supplied registry bytes.

## What a PASS does not prove

- world truth, product quality, or model reasoning;
- when a signature occurred or that it occurred inside the claimed execution
  path rather than later under the same key;
- Keychain, hardware, or other private-key custody;
- that the operator label truly owns the key without trusting anchor acquisition;
- a stable directory after verification; reverify preserved hashes before use;
- a benign verifier or uncompromised host;
- independent origin: both public repositories currently share the
  `github.com/cjchanh` account.
- registry freshness: two agreeing old snapshots cannot reveal a later
  revocation; freshness must come from the acquisition channel.
- availability against oversized input; apply OS CPU, memory, file-size, and
  process limits when verifying an untrusted packet.

## Break criteria

A reproducible break is a changed authenticated meaning or byte payload that
still passes, an unsafe filesystem side effect, an anchor/revocation mismatch
that passes the corresponding mode, or a reported engine agreement that did not
occur. A documented external boundary is a limitation, not a cryptographic fix.

The v0.3 post-release breaks and v0.4 remediations are documented in
`../docs/AAAP_POST_RELEASE_SECURITY.md`.
