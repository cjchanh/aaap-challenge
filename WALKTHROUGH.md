# AAAP v0.4 Clean-Room Walkthrough

## 1. Freeze what you received

```bash
git rev-parse HEAD
git ls-tree -r HEAD
```

Keep the commit SHA from the challenge repository and the commit SHA from the
anchor repository. A SHA is a content pin, not an author signature.

## 2. Inspect or sandbox the verifier

`verify_packet.py` is Python supplied by the producer. Read it, compare its
SHA-256 with `manifest.json`, and run it in a disposable least-privilege
environment. The manifest proves which verifier was sealed; it does not prove
that verifier is safe.

## 3. Verify packet integrity

```bash
cd packet
python3 verify_packet.py .
```

The command exits 0 only if all authenticated packet structure, artifact bytes,
derived-file bytes, manifest controls, and signatures pass. `verify.json` lists
the actual common engine set. A machine with no Ed25519-capable engine fails
closed.

## 4. Verify identity policy

```bash
python3 verify_packet.py . \
  --anchor-registry ../anchors.json \
  --anchor-registry /path/to/separately-acquired/anchors.json \
  --packet-name demo/packet
```

The verifier rejects disagreement, revocation, duplicate identities, unknown
identity references, and declared validity-window violations. Two files alone
do not prove two independent origins; both current repositories share one
GitHub account. Nor do two agreeing files prove freshness: an old registry
snapshot cannot reveal a later revocation.

## 5. Attack copies

Try byte edits, chain reorder/truncation, duplicate JSON keys, `NaN`, manifest
policy deletion, output symlinks, derived-file symlinks, dangling artifact
links, extra directories, anchor disagreement, and revocation. Each must exit
nonzero without modifying data outside the packet.

## 6. Interpret the result narrowly

PASS means the checked bytes and canonical meanings match signatures and any
supplied anchors. It does not prove world truth, signature time, signing-path
causality, key custody, operator ownership, verifier benevolence, or future
immutability of the directory.
