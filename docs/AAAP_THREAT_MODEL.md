# AAAP Threat Model v0.4

Assets are the sealed artifact bytes, canonical envelope chain, derived files,
attestation, full manifest control body, live-signature stream, verifier, and
anchor registry. The attacker may edit or repackage the directory, supply
malformed JSON, reorder content, substitute anchors, or exploit filesystem
objects. The host and acquisition channel are separate trust boundaries.

## Detected by the hardened verifier

| Attack | Enforcement |
|---|---|
| Artifact or derived-file byte change | envelope/manifest SHA-256 |
| Envelope edit, insertion, deletion, reorder, or truncation | canonical hash, links, attested head |
| Duplicate JSON keys or `NaN`/`Infinity` | strict JSON parser |
| Manifest live policy, key model, schema, or operator edit | v2 full-control-body signature |
| Missing live policy | exact v2 manifest fields; `live` is signed object or signed null |
| Attestation schema edit or unsigned extra claim | exact fields plus schema check |
| Symlink, hardlink, special file, or unreferenced artifacts entry | plain-file and complete-tree checks |
| Unsafe `verify.json` output symlink/hardlink | pre-write rejection plus atomic replacement |
| Anchor head/pubkey mismatch | paired anchor check |
| Two registry snapshots disagree | byte-for-byte comparison; trust neither |
| Revoked, duplicate, unknown, or out-of-window identity | registry policy validation |
| Crypto-engine disagreement on a checked signature | fail-closed signature verdict |

## Boundaries

| Boundary | Consequence | Required mitigation |
|---|---|---|
| Producer records false data | false content is sealed faithfully | upstream gates and independent evidence |
| Same key signs later or signs conflicting history | signature timing and uniqueness are not proven | protected signing policy, rotation, external witnesses |
| Fresh-key full re-forge | standalone packet verifies | trusted exact head + pubkey |
| Shipped verifier is malicious | executing it can lie or harm the host | audit/diff and sandbox; pin verifier hash externally |
| Verification host is subverted | all local checks can be forged | independent host/implementation |
| Packet mutates concurrently | PASS describes reads during one call, not future state | stable snapshot or immutable archive, then reverify |
| Both GitHub repos share one account | account compromise can rewrite both | neutral host/witness and signed releases |
| Both supplied registries are stale | later revocation is invisible | trusted freshness channel or transparency witness |
| Stock macOS lacks an Ed25519-capable engine | verification fails closed | `cryptography` or an Ed25519-capable OpenSSL build |
| Oversized packet consumes time, disk, or memory | availability can be exhausted without a verification bypass | least-privilege sandbox plus OS resource limits |

The current protocol provides tamper evidence and exact anchored identity under
these assumptions. It is not a timestamp authority, custody attestation,
transparency log, notarization system, or proof of world truth.
