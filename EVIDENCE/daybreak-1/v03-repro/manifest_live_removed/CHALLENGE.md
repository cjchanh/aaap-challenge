# The AAAP Challenge — Verify It, Then Try to Break It

You have never met us. You should not trust us. This artifact asks you to do
two things: verify a sealed record of an autonomous agent run using nothing
but your own machine, and then attack that record. If you break it in a way
we said was impossible, you found a vulnerability. If you break it in a way
we documented, you confirmed the boundary.

## What you need

- Any macOS/Linux box with Python 3.10+ and EITHER the `cryptography`
  package OR the `openssl` CLI (preinstalled almost everywhere).
  No network. No other downloads. No trust in us required.

## Step 1 — Verify the packet (2 minutes)

```
cd packet
python3 verify_packet.py .
```

Expected exit 0:

```
PASS: chain intact, artifacts complete and intact, derived layer sealed by manifest, attestation valid [engines: cryptography, openssl]
```

Every check the verifier ran is listed in `verify.json` — nothing is
aggregated away. On a machine without the `cryptography` package the
openssl CLI carries verification alone (engine list will show it).

## Step 2 — Verify IDENTITY, not just integrity (1 minute)

Step 1 proves the packet is internally consistent — but anyone can build a
consistent packet with their own key (that is boundary A21 below). The
pubkey and chain head WE claim are published out-of-band in `anchors.json`
(check them against our git history too). Verify against them:

```
python3 verify_packet.py . --expected-head <anchors.json packets[0].chain_head> \
                           --expected-pubkey <anchors.json identities[0].pubkey>
```

Exit 0 = this packet came from the identity we published. That is the whole
trust model: packets prove integrity, published anchors decide identity.

## Step 3 — Attack it

Copy the packet and mutate it. Some attacks to try, all caught:

```
cp -R packet f && echo x >> f/report.md                       # edit the human report
cp -R packet f && printf ' ' >> f/artifacts/live/ledger.jsonl # edit sealed bytes
cp -R packet f && python3 -c "from pathlib import Path;L=Path('f/chain.jsonl').read_text().splitlines();del L[2];Path('f/chain.jsonl').write_text('\n'.join(L))"
cp -R packet f && echo fake >> f/artifacts/EXTRA.txt          # smuggle a file
```

Run `python3 f/verify_packet.py f` after each. Every one exits 1 and names
the broken check. The interesting attack: rewrite a ledger entry AND
recompute the entire hash chain consistently — the capture-time signatures
still catch it without any anchors (exercise attack A19).

## What this packet proves

1. Every sealed byte of the run record is unchanged since build.
2. The record's order is unchanged (no insert/delete/reorder anywhere).
3. The human-readable report cannot be edited without detection.
4. The governed run's ledger entries were each signed BY THE IDENTITY KEY
   AT THE MOMENT THEY HAPPENED (capture-time signatures) — including the
   action that was BLOCKED. Refusals testify too.
5. The signature verified under two independent Ed25519 implementations
   (when both are available on your machine).

## Known limitations — read before claiming a break

- **Re-forge with a fresh key** (A21): anyone can run the tools and produce
  a perfectly verifying packet signed by their own identity. That is why
  Step 2 exists: identity comes from published anchors, never from the
  packet itself.
- **Swapped verifier** (A05): a tampered verifier can lie about its own
  verification. The manifest seals the verifier's hash — diff
  `verify_packet.py` against a copy from an independent source before
  trusting a PASS.
- **World-truth**: if the governed system recorded a false statement at
  capture time, the packet seals the false statement. This is a flight data
  recorder, not a lie detector.
- **Time**: timestamps are producer-claimed ordering, not attested.
- **Layout**: content is sealed, not byte layout — re-serializing chain.jsonl
  with different whitespace still verifies (documented, attack A17).
- **Custody**: the signing identity is currently a Stage-0 key
  (permission-enforced file — see docs/AAAP_KEY_CUSTODY.md). The demo
  threat model assumes no targeted same-user compromise.

The full 21-attack adversarial exercise (including the two attacks that
initially got PAST our own expectations and what they taught) is in
`docs/AAAP_ADVERSARIAL_EXERCISE.md`.

## What counts as a break

A mutation of any sealed content that still verifies, OR an anchor-mismatch
that passes Step 2, OR a verifier disagreement we reported as PASS. Report
it and it becomes a row in the exercise with your name on it. Boundaries
listed above are confirmations, not breaks.
