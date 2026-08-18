# Attested After-Action Packet v0.2

Key model: **persistent-identity** — persistent Ed25519 identity key; all packets from this operator share one publishable, anchor-checkable pubkey.

Self-contained evidence package for one governed Builder Foundry run.

Verify with nothing but this directory:

    python3 verify_packet.py .

Exit 0 and verify.json verdict PASS = chain intact, artifacts complete
and intact, derived layer sealed by manifest.json, attestation valid
(verified by every Ed25519 engine available). Any modification to any
sealed file — including this README and report.md — breaks it.

Contents: chain.jsonl (envelopes, spec in ENVELOPE.md), attestation.json
(chain-head signature), manifest.json (derived-file signature,
key_model recorded), artifacts/ (raw sealed copies), replay.json
(builder recomputation, scope stated inside), report.md (human report),
verify_packet.py (standalone verifier — its own hash is sealed in
manifest.json so you can diff it against an independently published
copy), verify.json (latest verification output; regenerated per run,
not part of the seal).

## What this packet does NOT prove

- Signing key: a persistent Ed25519 identity. Packets are attributable
  to one publishable pubkey; verify against it out-of-band with
  --expected-pubkey. Compromise of that key remains a documented
  boundary (rotate + re-publish to recover).
- It does not detect a full re-forge (entire chain rebuilt and
  re-signed with a fresh key) — compare the chain head and pubkey
  against an out-of-band published copy to close that boundary.
- It does not attest timestamps — they are producer-claimed.
- It does not vouch for product quality — guard green/red is
  structural; this packet testifies to the run record itself.
- It is evidence-level verification, not execution or model replay
  (see replay.json scope).
