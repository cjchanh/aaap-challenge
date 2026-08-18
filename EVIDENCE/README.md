# AAAP Adversarial Evidence — All Commissioned Passes

Three commissioned adversarial passes under the same operator boundary —
NOT independent third parties. Every pass is labeled as commissioned. Truly
external attack remains invited and credited: see ../CHALLENGE.md.

| Pass | Cases | Target | Verdict |
|---|---|---|---|
| Daybreak I (2026-08-17) | 11 mutation classes | v0.3 `e0fca96` | BROKEN — fixed in v0.4, credited |
| Daybreak II (2026-08-17) | 33 hostile cases | v0.4-lineage `a8b9d15` | BROKEN — fixed in v0.5, credited |
| GLM pass (2026-08-18) | 10 novel classes | v0.5 `9655a65` | SURVIVED — 2 model limits documented |

Contents: verdicts, reports, batteries, and minimal reproducers for each
pass. Byte-level attack snapshots were reduced to final form; intermediate
generations (before/v2/v3 full-packet copies) were dropped as redundant.

Sanitization: host paths, session paths, and emails mechanically scrubbed
to placeholders (`<SCRUBBED-*>`). The keychain service name
(`cds-aaap-identity`) appears in preserved packet docs and is already
public in the repository's own documentation; no secret material, private
keys, or account credentials exist in this tree (private key is Keychain-
held and never leaves it).

Reproduction: each battery runs against a clean clone of its stated target
commit. Expected outcomes are declared per case; any "unexpected PASS" in a
results file was a real finding at the time (see each pass's report).
