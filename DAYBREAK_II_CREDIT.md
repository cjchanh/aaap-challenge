# Daybreak II Break Credit — 2026-08-17

The named-credit promise applies to every turn. This is the second.

## The break

A second commissioned adversarial pass ("Daybreak II", fresh session under
the same operator — not an independent third party) found the public HEAD
(`a8b9d15`, which already contained the v0.4 hardening) **BROKEN**:

- 33-case hostile suite across new classes: TOCTOU races, resource
  exhaustion, archive extraction, Unicode/parser differentials, hostile
  crypto binaries, rollback/freshness, revocation timing, filesystem
  races, verifier substitution
- Two exploit-grade findings plus hardening regressions; full verdict,
  matrix, and minimal reproducers preserved in the Daybreak II evidence
  set (verdict JSON: `aaap-daybreak-ii-verdict/1`, `BROKEN`, pre-fix)

**Credit: Daybreak II.**

## The fix

v0.5 (`939b1e7` -> `797f8ee`): verifier import isolation, float/exponent
overflow rejection, anchor-registry verification mode (two-registry
agreement), and a clean-anchored-PASS regression — plus this repository's
own security rules (AGENTS.md). Sealed core unchanged: same chain head
(`14d14281…`), same identity, same attestation; only the verifier and the
production-signed manifest (aaap-manifest/2, one authorized Keychain
retrieval) changed.

Post-fix: 5/5 regressions, 11/11 legacy Daybreak battery, 33/33 Daybreak II
cases matched, OpenSSL-only anchored PASS, governance gates PASS.

## The loop, honestly stated

Two commissioned passes found real breaks that 261 internal tests and a
21-attack internal exercise did not. Both are credited here by name. The
attack surface is public, the batteries are permanent regressions, and the
next row in this file should belong to someone we have never met.
