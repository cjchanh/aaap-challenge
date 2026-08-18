# AAAP Trust Root — Anchor Format, Registry, and the Proof/Trust Split

Status: v1 design, implemented by `demo/anchors.json` + the verifier's
`--expected-head` / `--expected-pubkey` flags. Nothing here changes what a
packet proves; it defines how a stranger decides *whose* packet to trust.

## The split (the one sentence)

A packet PROVES integrity internally (bytes, order, capture-time signatures);
IDENTITY trust — that this pubkey belongs to the operator it claims — can
only come from OUT-of-band publication. The anchor registry is that
out-of-band surface. Neither substitutes for the other.

## Anchor format (`aaap-anchors/1`)

```json
{
  "schema": "aaap-anchors/1",
  "identities": [
    {
      "identity_id": "aaap-id-ef9eef6cb68a8850",
      "algorithm": "ed25519",
      "pubkey": "<64-byte hex>",
      "operator": "Centennial Defense Systems",
      "valid_from": "2026-08-17",
      "revoked": false
    }
  ],
  "packets": [
    {
      "name": "demo/packet",
      "chain_head": "<sha256 of chain.jsonl tail envelope>",
      "pubkey_identity": "aaap-id-ef9eef6cb68a8850",
      "sealed_at": "2026-08-17"
    }
  ]
}
```

Verification against anchors:

```bash
python3 verify_packet.py <packet> --expected-head <chain_head> --expected-pubkey <pubkey>
```

Both flags fail closed on mismatch. A packet that verifies standalone but
fails its anchor is internally honest history from the WRONG signer —
exactly what attack A21 in the adversarial exercise demonstrates.

## Registry design

Current (v1, honest): the anchors file lives in this repository, committed
with the packets it covers. This binds packet identity to git history —
tamper-evident via commits, but same-origin as the packets.

Evolution path (not yet built, by design):
1. **Cross-origin publication** — anchors mirrored to a second origin the
   packet producer does not control (separate repo/org, signed git tag).
   Defeats same-origin registry rewrite.
2. **Append-only + signed registry** — each anchors release signed by the
   identity key; revocations are explicit rows, never deletions.
3. **Registry independence** — a neutral host (standards body or multi-party
   mirror) so compromise requires attacking the registry AND the key.

Until (1) lands, the honest claim is: anchors bind packets to git history in
this repository, which is stronger than packet-self-assertion and weaker
than cross-origin publication. State it that way.

## What anchors do NOT do

- They do not make a packet's contents true (world-truth stays out of scope).
- They do not attest time.
- They do not detect a compromised identity key that signs two conflicting
  histories — that requires key rotation + revocation semantics (v2).
