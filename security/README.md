# Security evidence

- `aaap_v03_reproducers.py` attacks disposable clones of the exact immutable
  v0.3 commit and refuses a dirty or differently pinned source clone.
- `V03_REPRO_RESULTS.json` records 11 authenticated or filesystem violations
  that the anchored v0.3 verifier incorrectly returned PASS for.
- `V04_ATTACK_RESULTS.json` is the hostile pass against the production-signed
  v0.4 packet in this candidate. Every attack is caught; baseline passes.
- `V04_LEGACY_ATTACK_RESULTS.json` is the pre-existing 21-case suite rerun
  against that same production-signed packet.

The additional malicious-test-signer semantic cases and source-CLI regression
were produced in the operator's local hardening workspace (not a
published commit); published lineage: `e0fca96` -> `8f5ba31f` -> `c06b163`.

These files are audit evidence, not an independent witness. The code, release,
and both GitHub repositories remain under the same operator/account boundary.
