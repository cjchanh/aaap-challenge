# After-Action Report — Attested Evidence Packet v0.1

Generated: 2026-08-17T21:17:23Z

## What happened

- Campaign run finished in state **handed-off** (exit code 0, stop reason: provider-unknown).
- Engine: luna (model gpt-5.6-luna, 0 engine calls).
- External effects performed by the driver: None.
- Anti-fabrication posture: engines do the creative work; run only re-runs the guard between steps and never writes ledgers to satisfy it.

## What the agent attempted

- 3 recorded steps (0 passed, 2 failed, 0 timed out).

| step | command | outcome | exit |
|---|---|---|---|
| guard-1 | `` | FAILED | None |
| capability-luna | `` | FAILED — provider-unknown | None |
| guard-final | `` | FAILED | None |

## What was allowed

- 22 sealed envelopes; every artifact copy hash-matches its sealed sha256.
- Evidence rows verified against declared hashes: 7 / 7.

## What was blocked / held

- Open blockers at packet time: 0.
- Held envelopes: 0.
- Evidence drift (declared hash != recomputed): 0.

## Whether the record was modified

Run the standalone verifier: `python3 verify_packet.py .` from this directory.
- Chain head: `14d14281170d89f6f8b918daf6541f81e7e13549dd4c66f5b085304ff6a61724`
- Attestation: deponent-attestation/v1, operator `cds/aaap-id-2f28c662cb4b30c1`, Ed25519 (ephemeral build key — integrity, not persistent identity).

## Limits (stated, not hidden)

- Ephemeral signing key: proves packet integrity, not a persistent operator identity.
- A full re-forge (entire chain rebuilt + re-signed) is only detectable against an out-of-band copy of the chain head.
- Guard green/red is structural; this packet testifies to the run record, not to product quality.
