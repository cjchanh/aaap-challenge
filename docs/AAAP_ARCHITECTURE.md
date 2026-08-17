# AAAP Architecture — v0.4

## Producer path

1. Copy each governed source artifact into `artifacts/` and hash its exact bytes.
2. Emit one strict canonical envelope per artifact and link it to the prior hash.
3. Sign the final chain head with the selected Ed25519 identity.
4. If a live ledger is supplied, verify its chain and per-entry signatures,
   copy both streams into artifacts, and place length/head/path policy in `live`.
5. Generate report, replay scope, packet guide, envelope spec, and verifier.
6. Sign manifest schema v2 over every control field except the signature itself:
   schema, exact derived-file map, key model, operator id, public key, and the
   complete live object or explicit null.
7. Run the shipped verifier as a fresh process; refuse the packet if it fails.

## Third-party verifier path

1. Require the exact packet-root allowlist and plain regular inputs; reject
   unsealed root claims, symlinks, hardlinks, special files, and unreferenced
   artifact directories or entries.
2. Parse JSON with duplicate-key and non-finite-number rejection.
3. Recompute every envelope hash, position, link, signal/artifact digest
   binding, artifact hash, and the attested head.
4. Validate exact attestation fields and signature.
5. Validate exact manifest v2 fields, derived-file allowlist, and signature over
   the full manifest control body.
6. Recompute live ledger order/head and every per-entry signature when `live`
   is present.
7. Intersect actual verifier engines across every signature check; disagreement
   or inconsistent coverage fails.
8. Optionally require a paired exact anchor, or two distinct byte-identical
   active registries.
9. Reject an unsafe `verify.json` target and write results atomically.

## Trust boundaries

- The signing key may be persistent, but a signature proves use, not custody.
- Per-entry signatures bind content and index, not wall-clock or causal timing.
- The verifier is executable producer code; audit or sandbox it.
- Verification assumes a stable filesystem snapshot for the duration of a run.
- Two repositories under one GitHub account are not independent custody.
