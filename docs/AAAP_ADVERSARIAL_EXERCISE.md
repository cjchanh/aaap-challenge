# AAAP Adversarial Exercise — Historical v0.3 Results and Post-Release Breaks

**Current status: the original PASS verdict is withdrawn.** The 21-case suite
below passed, but it did not attack unsigned manifest policy, strict parser
agreement, output-path side effects, or non-regular package entries. Daybreak
reproduced those violations against public commit `e0fca96651b30c76d0a29bf867cdd14cdc38db00`.

Subject: demo/packet (chain head `2191ca7bbd33…454787b56`, operator key
published out-of-band in the exercise output `ANCHORS.md`).
Attacker: `scripts/aaap_attack.py` — 16 single-mutation attacks across six
classes; every verdict from the SHIPPED verifier run as a fresh subprocess.
The attacker code shares nothing with the verifier.

## Scoreboard (actual results, 2026-08-17)

| id | class | attack | result |
|---|---|---|---|
| A01 | modify contents | byte-flip sealed artifact | **caught** (envelope hash) |
| A02 | modify contents | edit report.md post-build | **caught** (manifest) |
| A03 | modify contents | edit ENVELOPE.md spec | **caught** (manifest) |
| A04 | modify contents | fabricate zero-drift replay summary | **caught** (manifest) |
| A05 | verifier | backdoored always-PASS verifier | swapped verifier lies (expected); **caught by out-of-band pristine verifier** (manifest seals the verifier hash) |
| A06 | verifier | artifact swap from donor packet | **caught** (envelope hash) |
| A07 | chain | delete middle entry | **caught** (chain link) |
| A08 | chain | truncate tail | **caught** (attestation head binding) |
| A09 | chain | reorder entries | **caught** (chain link) |
| A10 | forgery | zeroed signature | **caught** (dual-engine Ed25519) |
| A11 | forgery | re-sign manifest over altered digest | **caught** (anchor-pubkey via manifest signature) |
| A12 | forgery | re-sign intact chain with attacker's own valid key | boundary: packet-alone passes; **anchor-detectable** (`--expected-pubkey`) |
| A13 | fabrication | fully self-consistent fabricated GREEN run, real packet built from it | boundary: packet verifies; **anchor-detectable** (head+pubkey differ from published anchors) |
| A14 | incomplete | delete an artifact | **caught** (completeness) |
| A15 | incomplete | smuggle unreferenced "audit approval" file | **caught** (completeness) |
| A16 | incomplete | remove manifest | **caught** (structure) |

Historical exercise verdict: **SUPERSEDED**. Every attack the suite attempted
was classified as expected, but the suite did not cover the post-release break
classes and therefore did not justify a release PASS.

## Daybreak post-release additions

| id | class | attack against v0.3 | v0.3 result | v0.4 regression |
|---|---|---|---|---|
| A22 | policy | remove manifest `live` verification policy | **PASS (break)** | fail |
| A23 | claims | rewrite manifest key model/schema | **PASS (break)** | fail |
| A24 | claims | rewrite attestation schema/add custody claim | **PASS (break)** | fail |
| A25 | parser | duplicate chain key with conflicting first value | **PASS (break)** | fail |
| A26 | parser | non-standard `NaN` in manifest | **PASS (break)** | fail |
| A27 | filesystem | `verify.json` symlink overwrites sealed report | **PASS + overwrite (break)** | fail before write |
| A28 | packaging | dangling artifact symlink | **PASS (break)** | fail |
| A29 | packaging | derived-file symlink escape | **PASS (break)** | fail |
| A30 | anchors | same-file/disagreeing/revoked registry path | not enforced | fail |
| A31 | claims | signing-time, custody, portability, independent-origin language | overstated | corrected |

See `AAAP_POST_RELEASE_SECURITY.md` and
`security/aaap_v03_reproducers.py` for evidence and reproduction.

## What the exercise got wrong on its first run (and why that matters)

The first execution FAILED its own gate on two attacks — and both failures
were informative:

1. **A04 first passed** because the "attack" rewrote a JSON field to the
   value it already had — a byte-identical no-op. Lesson recorded: a
   mutation attack must be verified to actually mutate (the suite now flips
   values to impossible ones).
2. **A05 first passed** and was misclassified must-catch. A swapped verifier
   that renders FAIL as PASS will always "pass" itself — no packet-internal
   check can be reported honestly by a compromised reporter. The designed
   defense is exactly what the manifest already provides: the verifier's
   hash is sealed, so an independently published pristine verifier catches
   the swap. The exercise now demonstrates both halves: the lie (expected)
   and the out-of-band catch.

An exercise that cannot fail is theater. This one failed, diagnosed, and
re-ran to a verdict earned rather than declared.

## Boundaries, stated the same way twice

- **Re-sign with a fresh key (A12)** and **fabricated-but-consistent runs
  (A13)** produce packets that verify standalone. Sealing proves integrity
  of a record, not truth of the world, and anyone can generate a key. The
  mechanical closure is the published anchor: `verify_packet.py <packet>
  --expected-head <sha256> --expected-pubkey <hex>` fails closed on any
  re-forge whose head or key differs from the independently published ones.
- **A lying verifier** is only caught by a verifier you did not get from
  the packet. That is why the manifest pins the verifier hash and the
  walkthrough instructs every third party to diff against the published
  copy.

Reproduce: `python3 scripts/aaap_attack.py --packet demo/packet --out <dir>`
(exit 0 = same verdict as this report).
