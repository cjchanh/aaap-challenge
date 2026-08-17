# Attested After-Action Packet v0.4

Key model: **persistent-identity** — the same anchored Ed25519 identity as the immutable v0.3 packet.

Self-contained evidence package for one governed Builder Foundry run.

Verify with nothing but this directory:

    python3 verify_packet.py .

Exit 0 and verify.json verdict PASS = canonical chain semantics intact,
artifact and derived-file bytes intact, every manifest control field
authenticated, and attestation valid under the engines named in output.
JSON whitespace is not sealed; duplicate keys and non-finite numbers are
rejected. Verification assumes a stable local filesystem for the run.

Contents: chain.jsonl (envelopes, spec in ENVELOPE.md), attestation.json
(chain-head signature), manifest.json (signature over its full control
body), artifacts/ (raw sealed copies), replay.json
(builder recomputation, scope stated inside), report.md (human report),
verify_packet.py (standalone verifier — its own hash is sealed in
manifest.json so you can diff it against an independently published
copy), verify.json (latest verification output; regenerated per run,
not part of the seal).

## What this packet does NOT prove

- Signing key: a persistent Ed25519 identity. Packets are attributable
  to one publishable pubkey only through a trusted paired head+pubkey
  or an active agreed registry. A signature does not prove custody or
  signing time. Key compromise remains a documented boundary.
- It does not detect a full re-forge (entire chain rebuilt and
  re-signed with a fresh key) — compare the chain head and pubkey
  against an out-of-band published copy to close that boundary.
- It does not attest timestamps — they are producer-claimed.
- Registry policy is only as fresh and independently acquired as the
  registry bytes supplied by the reviewer.
- It does not promise availability for oversized hostile input; use
  OS resource limits in the verification sandbox.
- It does not vouch for product quality — guard green/red is
  structural; this packet testifies to the run record itself.
- It is evidence-level verification, not execution or model replay
  (see replay.json scope).
