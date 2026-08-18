# Evidence Envelope — Field Specification (v1.0 + chain extension)

The canonical envelope is sovereign-root `contracts/EVIDENCE_ENVELOPE.md`
v1.0 with two documented extensions. Every field, its producer, and how a
third party recomputes it:

| field | producer | recompute |
|---|---|---|
| envelope_id | packet builder (UUID) | not recomputable — identifier only |
| signal_sha256 | sha256 of the sealed source artifact at seal time | sha256 of the copy in artifacts/ |
| timestamp_utc | builder wall clock | NOT verified — producer-claimed time, not attested time |
| source_system | "builder-foundry" (v1.0 enum extension, documented here) | literal |
| action_class | builder classification of the sealed source | literal |
| route_selected | "packet-builder/seal" | literal |
| policy_decision | APPROVE, or HOLD when a check failed (e.g. evidence drift) | see replay.json summary |
| execution_result | artifact path + sha256 + source path + per-class extras | artifact hash recompute |
| receipt_hash | canonicalization digest below | recompute (below) |
| chain_index (ext) | envelope ordinal, 0-based | position in chain.jsonl |
| chain_prev (ext) | prior envelope receipt_hash, "" for first | prior line's receipt_hash |

## Canonicalization (exact)

1. copy the envelope object; set `receipt_hash` to the empty string
2. serialize with recursively sorted keys, compact separators (`,` `:`),
   `ensure_ascii=true`, and non-finite numbers disabled
3. sha256 over the UTF-8 bytes, lowercase hex

Input JSON must contain exactly the documented top-level fields. Duplicate
keys and `NaN`/`Infinity` are rejected before canonicalization.

## Extensions (documented, do not alter v1.0 semantics)

- `source_system` adds "builder-foundry" to the v1.0 enum.
- `chain_index` / `chain_prev` turn the envelope sequence into a hash chain:
  envelope i's canonical bytes include envelope i-1's receipt_hash.

## Determinism

Verification is deterministic for the same stable packet snapshot, supported
Python semantics, and crypto-engine behavior. Construction is NOT deterministic: envelope ids and
timestamps differ per build, so rebuilding the same campaign produces a
different (equally valid) chain head. Determinism claims apply to
verification only.

## Missing evidence rows

A manifest row whose file is absent from the campaign records as drift in
replay.json (summary + findings) but seals no envelope — there are no bytes
to seal. Present-but-drifting rows seal a HOLD envelope.
