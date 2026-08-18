# GLM 5.3 Adversarial Pass — 2026-08-18

Commissioned same-operator pass 3 (cross-engine: v0.4/v0.5 authored by Codex;
attacker = GLM 5.3, the engine that authored v0.3). NOT an independent third
party. Target: aaap-challenge@9655a65, white-box.

## Verdict: SURVIVED — 10 novel attack classes, 0 breaks

Cases targeted seams uncovered by Daybreak I (11) + II (33): registry
distinctness/acquisition, registry trust semantics, strict-parser edges,
positional type binding.

| id | attack | result |
|---|---|---|
| G01 | same registry twice via symlink alias | caught (plain-file + inode checks) |
| G02 | two byte-identical copies of one registry | **documented model limit confirmed** — agreement is necessary, not proof of independent acquisition |
| G03 | disagreeing registries | caught (byte-compare, trust neither) |
| G04 | symlinked/dangling registry | caught |
| G05 | packet anchored to revoked identity | caught |
| G06 | hostile registry re-anchors real packet to attacker identity | caught at anchor-pubkey — signature binding holds even when registry semantics are poisoned |
| G07 | duplicate packet names | caught |
| G08 | UTF-8 BOM registry | caught |
| G09 | chain_index as float (type confusion) | caught (strict int-not-bool position check) |
| G10 | homoglyph packet-name | caught (unknown name) |

## Findings (documented, none sealed-core)

1. **G02 vacuous agreement**: two-file agreement cannot distinguish
   independent acquisition from one file copied twice. Operational fix lives
   in instructions, not code: registries must be fetched over the network
   from the two published origins (CHALLENGE.md already instructs this);
   never accept a locally-provided file pair.
2. **G06 nuance**: registry mode will activate ANY identity the registry
   lists; the security boundary is the signature binding, not registry
   hygiene. Worth one clarifying line in AAAP_TRUST_ROOT.md.

## What this pass does NOT prove

Same-operator, same-machine, single-engine-family attack. It raises
confidence in the specific seams tested; it does not substitute for external
attack, which remains invited and credited.
