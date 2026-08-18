# AAAP — Attested After-Action Packet: Public Challenge

**A sealed, capture-time-signed evidence record of an autonomous agent run.
It doesn't answer. It testifies. Verify it yourself — then try to break it.**

- Start here: **[CHALLENGE.md](CHALLENGE.md)** — verify in 2 minutes with
  nothing but Python 3.10+ and the `openssl` CLI (no other dependencies,
  no network, no trust in us required).
- Identity anchors: **[anchors.json](anchors.json)** — mirrored at a second
  origin: https://github.com/cjchanh/aaap-anchors (compare both; they must
  agree).
- What it proves / does not prove: [docs/AAAP_PROVES.md](docs/AAAP_PROVES.md)
- Threat model: [docs/AAAP_THREAT_MODEL.md](docs/AAAP_THREAT_MODEL.md)
- Our own 21-attack exercise (including two attacks that initially got past
  us): [docs/AAAP_ADVERSARIAL_EXERCISE.md](docs/AAAP_ADVERSARIAL_EXERCISE.md)
- Step-by-step walkthrough: [WALKTHROUGH.md](WALKTHROUGH.md)

## The one-paragraph version

Every governed action in the sealed run — including the action that was
**BLOCKED** — was signed by an Ed25519 identity key **at the moment it
happened**, inside the run's execution path. The packet proves: bytes
unchanged since build, order unchanged, report un-editable, signatures valid
under independent implementations. It does not prove: world truth, time, or
that a fresh-key re-forge is impossible (that is what the anchors are for).
Every boundary is stated in the packet itself.

## Verify (zero installs beyond Python; openssl carries it alone)

```
git clone https://github.com/cjchanh/aaap-challenge
cd aaap-challenge/packet
python3 verify_packet.py .
```

With anchors (identity, not just integrity) — fetch the mirrored anchors and
check agreement first:

```
git clone https://github.com/cjchanh/aaap-anchors /tmp/anchors
diff anchors.json /tmp/anchors/anchors.json        # must be identical
HEAD=$(python3 -c "import json;print(json.load(open('/tmp/anchors/anchors.json'))['packets'][0]['chain_head'])")
PUB=$(python3  -c "import json;print(json.load(open('/tmp/anchors/anchors.json'))['identities'][0]['pubkey'])")
python3 verify_packet.py . --expected-head "$HEAD" --expected-pubkey "$PUB"
```

## Attack it

Mutation attacks (all caught, each named): see CHALLENGE.md step 3. What
counts as a break is defined there. Boundaries we already document are
confirmations, not breaks — finding a NEW one past them is the game.

Operator: Centennial Defense Systems. Production signing identity:
`aaap-id-2f28c662cb4b30c1` (Keychain custody; see
[docs/AAAP_IDENTITY_TRANSITION.md](docs/AAAP_IDENTITY_TRANSITION.md)).
