# AAAP Threat Model v0.1

Assets: (A1) the sealed run record (chain + artifacts), (A2) the derived
human layer (report/spec/README), (A3) the attestation signatures,
(A4) the verifier itself.

Adversaries: (E1) the supervised agent or a downstream editor wanting to
rewrite history after the fact; (E2) a forger constructing a favorable packet
from scratch; (E3) a courier swapping packets between build and review;
(E4) a subverted verification environment.

## Detected (verification fails, check named)

| Attack | Caught by |
|---|---|
| Edit any byte of any sealed artifact copy | envelope artifact hash |
| Edit any envelope field (incl. re-sealing the hash) | receipt_hash recompute |
| Insert / delete / reorder any chain entry | chain_prev link check |
| Truncate the tail of the chain | attestation head binding |
| Edit report.md, replay.json, PACKET.md, ENVELOPE.md | manifest digest map |
| Swap or edit verify_packet.py | manifest digest map |
| Forged / replaced attestation signature | Ed25519 verify (dual engine) |
| Forge the manifest over altered derived files | manifest signature + digests |
| Reference a path outside the packet | path-escape check |
| Smuggle an unreferenced file into artifacts/ | completeness check |
| Single crypto-library bug/subversion | dual-engine agreement (fail-closed on disagreement) |
| Missing manifest / missing attestation / empty chain | structure checks (absent ≠ valid) |

## Not detected (stated boundaries)

| Boundary | Why | Mitigation |
|---|---|---|
| Full re-forge: rebuild chain + derived files + re-sign with a fresh key | anyone can generate a key; the packet carries an ephemeral key by design | compare chain head + pubkey against an out-of-band published copy (the demo package publishes them); persistent identity keys are separately gated future work |
| Producer-true-but-false records | if the governed run lied into its own ledger at capture time, sealing cannot correct it — sealing proves integrity of the record, not the truth of the world | pair with verification-oriented capture (gates that check outputs before recording), which is the governed layer's job upstream of the packet |
| Timestamps | builder wall clock, not attested | treat all times as producer-claimed ordering hints |
| Cryptographic-lib + CLI collusion | both engines subverted identically | out-of-band verifier diff (manifest seals the verifier hash) |

## Key handling

Build generates an ephemeral Ed25519 keypair in memory; the private key never
touches disk and is destroyed at build exit. The public key is embedded in
attestation.json and manifest.json. There is no key store, no rotation, no
transport — v0.1 deliberately has no key lifecycle to attack. The signing
construction is deponent `operator_attest/v1`, imported unmodified; the
openssl CLI is used only as an independent verifier of the same signature.

## Honest scope statement

AAAP v0.1 is tamper-evidence and verifiable integrity for an autonomous
run's record — a flight data recorder, not a court. It converts "trust the
agent's summary" into "verify the sealed record, and know exactly which
questions it cannot answer."
