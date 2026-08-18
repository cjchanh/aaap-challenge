# AAAP Trust Root — Current Reality

Packet cryptography proves integrity under a public key. It does not prove who
owns that key. The actual trust root is how the verifier obtained the exact
chain head, public key, verifier code, and revocation state.

## Current public topology

- `github.com/cjchanh/aaap-challenge`
- `github.com/cjchanh/aaap-anchors`

These are separate repositories with separate Git object histories, but both
are controlled by the same GitHub account and the published v0.3 root commits
are unsigned. The split can expose an accidental edit or a compromise scoped
to one repository. It does not resist account-owner action, account compromise,
GitHub control-plane compromise, or coordinated rewrite.

Calling the second repository an independent origin is inaccurate. The precise
claim is **two same-account repository histories**. An exact commit SHA supplied
through a separate trusted channel is a content pin, not an author signature.

## Hardened verification modes

Historical exact pin:

```bash
python3 verify_packet.py packet \
  --expected-head <trusted-64-hex-head> \
  --expected-pubkey <trusted-64-hex-pubkey>
```

Both values are mandatory together. This proves an exact historic packet even
if the identity is later revoked; it does not consult current policy.

Current registry policy:

```bash
python3 verify_packet.py packet \
  --anchor-registry /independently/acquired/challenge/anchors.json \
  --anchor-registry /independently/acquired/anchor-repo/anchors.json \
  --packet-name packet
```

The verifier requires two distinct, byte-identical files and rejects revoked,
unknown, duplicate, or out-of-window identities. It cannot prove that the two
files came from independent origins or that they are the newest published
state. Acquisition and freshness remain the reviewer's duty; two matching old
snapshots cannot reveal a later revocation.

## Required next trust upgrade

Publish the same registry and release hashes through a neutral account or host,
sign releases with a separately protected release key, and retain append-only
history in an externally witnessed transparency surface. Until then, the
same-account boundary must remain explicit.

## Vacuous agreement limit (GLM pass G02, 2026-08-18)

Two byte-identical copies of ONE registry file pass the two-registry
agreement check — agreement is necessary, not proof of independent
acquisition. Operational rule (already the CHALLENGE.md instruction):
fetch each registry over the network from its own published origin and
never accept a locally-provided pair. The verifier cannot distinguish
acquisition provenance; the operator instructions must.
