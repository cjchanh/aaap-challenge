# Daybreak Break Credit — 2026-08-17

The public challenge promised: *"Report it and it becomes a row in the
exercise with your name on it."* This page keeps that promise.

## The break

A commissioned "Daybreak" adversarial evaluation (separate session under
the same operator — not an independent third party) found **11 mutation classes that returned
anchored PASS** against the v0.3 release (`e0fca96`), all reproduced by the
operator's second audit and confirmed real:

1. Unsigned manifest sections — deleting the `live` capture-time anchors
   still verified (the digest map didn't cover them)
2. `key_model` tampering passed (unsigned field)
3. Manifest schema tampering passed
4. NaN injection into signed structures
5. Attestation schema tampering passed
6. Unsigned claims added to attestation.json
7. Duplicate JSON keys confusing the parser (last-wins divergence between
   engines)
8. `verify.json` symlink write-through overwriting the sealed report
9. Dangling symlinks in artifacts/ passing completeness
10. Unsealed files at packet root passing (completeness covered artifacts/ only)
11. Derived-file symlink escape

Per the challenge's own definition ("a mutation of any sealed content that
still verifies"), these are genuine breaks. **Credit: Daybreak.**

## The fix

v0.4 (`8f5ba31f`) — same sealed core, byte-identical chain/artifacts/
attestation; whole-manifest signing (aaap-manifest/2), strict JSON with
duplicate-key rejection, exact-key validation, symlink/plain-file rejection,
packet-root validation, and built-in cross-origin anchor agreement. All 11
classes now fail closed; the v0.3 attack scripts are preserved in the
Daybreak report and re-run as regression cases.

## What this proves about the model

The release strategy was ship → invite attack → fix named findings →
reship. This page is the second turn of that loop. The first commissioned
adversarial pass found in one pass what 21 internal attacks and 261 tests
did not. Truly external attack remains invited — this page will credit it.
That is the system working, and it is why the challenge exists.
