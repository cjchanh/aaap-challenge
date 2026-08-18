# Security Policy

This repository is an adversarial cryptographic-verification challenge, not
a product. This file is a lab notebook entry, not a marketing page.

## Supported version

**v0.5** (current `main`) is the only supported target. It has absorbed
fixes from Daybreak I, Daybreak II, and a GLM pass — see `EVIDENCE/`.

Earlier releases are preserved as immutable, reproducibly vulnerable
history, not supported:
- v0.3 (`e0fca96`) — 11 mutation classes break it; see `DAYBREAK_CREDIT.md`
  and `docs/AAAP_POST_RELEASE_SECURITY.md`.
- pre-v0.5 v0.4 lineage (`a8b9d15`) — 33 hostile cases break it; see
  `DAYBREAK_II_CREDIT.md`.

Do not report against a frozen historical commit; its breaks are already
documented and fixed forward.

## Where to attack

Start at `CHALLENGE.md` for the exact break criteria (changed authenticated
meaning/bytes that still verifies, an unsafe filesystem side effect, an
anchor/revocation mismatch that passes the corresponding mode, or a reported
engine agreement that did not occur). `EVIDENCE/` holds all 54 published
attack cases across the three commissioned passes to date — read it before
re-deriving a known class.

## Verify the sealed packet (anchored mode)

```bash
cd packet
python3 verify_packet.py . \
  --expected-head 14d14281170d89f6f8b918daf6541f81e7e13549dd4c66f5b085304ff6a61724 \
  --expected-pubkey e7fb4aad8b0e0246eb6569f49d301ad88a0b54333e3de8bb57e02e118fd3716c
```

The verifier is hardened against hostile packet input (import isolation,
strict JSON, non-finite-number and symlink rejection), but treat it as
untrusted producer-supplied code per `CHALLENGE.md`: read it first, then run
it least-privilege in a disposable environment.

## Reporting a break

No dedicated disclosure channel exists yet. Open a GitHub issue on this
repository with a minimal reproducer: target commit, exact mutation, exact
command, expected vs. observed verifier exit code. Describe an exploit in
the issue text rather than attaching a runnable payload.

## Credit policy

A reproducible break against the published challenge, per the criteria in
`CHALLENGE.md`, gets named public credit in a `DAYBREAK_*_CREDIT.md`-style
file in this repository — already done twice. Commissioned passes are
labeled as commissioned, not independent, in their own credit files. Truly
external, uncommissioned breaks are invited and will be credited the same
way.
