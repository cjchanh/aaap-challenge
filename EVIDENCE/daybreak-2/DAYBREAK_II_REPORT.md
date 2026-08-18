# AAAP Daybreak II — Pre-Fix Report

**Verdict: BROKEN.** Target `a8b9d15c6b80100eaf52be02abbc1b3322ac3234` contains the same verifier bytes as parent `c06b1638ec2942e0d481a967391e88d6532837dc`; the one-commit public diff is documentation-only. Anchors were pinned at `9deae6c211843544d8d4d5143f0ee266e36caab2`.

## Reproduced violations

1. **HIGH — pre-validation Python import shadowing.** Plain invocation places the hostile packet directory first on `sys.path`. An unsealed `cryptography` package executed before packet-root inventory while the manifest-pinned verifier hash remained exact. A stable packet wrote outside itself before returning `FAIL`, meeting the challenge's unsafe-side-effect break criterion. A self-removing variant also changed signed `manifest.key_model` and returned anchored `PASS`; real engines rejected the identical mutation.

2. **MEDIUM — exponent overflow accepted as non-finite.** Both byte-identical registries used JSON token `1e9999`; Python materialized positive infinity and registry-mode verification returned `PASS`. This violates the verifier's explicit non-finite-number rejection contract. The reproduced field was unused custody metadata, so this is not claimed as a revocation or key-selection bypass.

## What held

The clean 32-case matrix rejected artifact edits, truncation, traversal, manifest policy edits, duplicate keys, literal `NaN`, invalid UTF-8, malformed deep JSON, filesystem links/special files, unsafe output targets, archive traversal payloads, registry disagreement/substitution, revocation/window violations, engine disagreement, and missing engines. No archive was extracted and both output-link sentinels remained unchanged.

Not counted as exploits: documented hostile-host/crypto-engine behavior, registry staleness and rollback, concurrent mutation/TOCTOU, and unbounded availability. An unpaired surrogate in unused registry metadata is recorded only as a hardening gap.

## Reproduction

Exact executed commands:

```bash
python3 <SCRUBBED-TMP-PATH>
python3 <SCRUBBED-TMP-PATH>
python3 <SCRUBBED-TMP-PATH>
python3 <SCRUBBED-TMP-PATH>
```

Per-case CLI commands, stdout, stderr, packets, and JSON verdicts are preserved under `reproducers/`. The consolidated matrix is `reproducers/hostile-suite-before-v3/RESULTS.json`.

This report and `DAYBREAK_II_VERDICT.json` were written before any successor-clone fix.
