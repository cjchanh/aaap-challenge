# AAAP Repository Instructions

## Scope

These rules apply to the entire AAAP challenge repository. Global operator and
runtime rules remain authoritative and take precedence.

## Security Invariants

- Treat published commits, signed manifests, anchors, and preserved attack
  evidence as immutable. Never rewrite or erase them.
- Preserve `packet/chain.jsonl`, `packet/attestation.json`, and
  `packet/artifacts/` unless the operator explicitly authorizes a new sealed
  core.
- Never access an identity key without an exact operator authorization naming
  the key source and intended signature.
- Reject ambiguity, parser disagreement, missing trust inputs, unsafe file
  types, verifier disagreement, and unavailable signature engines by default.
- Do not weaken identity, signature, canonicalization, ordering, replay,
  anchor, revocation, or fail-closed guarantees to make a test pass.
- A second anchor path is not an independent trust origin unless custody and
  administrative control are actually independent.
- Pushes, tags, releases, and publication require a fresh `OPERATOR COMMIT:`.

## Change Discipline

- Security fixes require a minimal reproducer, the smallest durable repair,
  and a regression that fails on the vulnerable behavior.
- Claim limitations honestly when the trust model cannot prove a stronger
  statement.
- Keep generated caches, temporary attack packets, and secrets out of the
  repository.

## Verification

Run from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
ruff check packet/verify_packet.py tests/test_verify_packet_hardening.py
git diff --check
```

For release candidates, also verify the untouched packet with explicit trusted
anchors and rerun the preserved hostile batteries from a clean clone. A clean
baseline must PASS before a mutation can count as a caught attack.
