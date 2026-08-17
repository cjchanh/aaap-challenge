# AAAP Production Identity Transition — 2026-08-17

> Historical operational record. Its original security conclusion is
> superseded by `AAAP_POST_RELEASE_SECURITY.md`. Key-generation and deletion
> statements below are operator-reported events, not packet-verifiable facts.

## Decision

The operator reports that production AAAP signing identity
**aaap-id-2f28c662cb4b30c1** (Ed25519, pubkey
`e7fb4aad…8fd3716c`) was generated in memory and stored directly into the
macOS user Keychain (service `cds-aaap-identity`, account `production`). The
packet cannot prove that generation path or exclude prior raw-file exposure.
Custody stage 1 is an operational classification per
`docs/AAAP_KEY_CUSTODY.md`.

The predecessor identity **aaap-id-ef9eef6cb68a8850** is **RETIRED** and
marked revoked in `demo/anchors.json` (its pubkey is retained there so
third parties can positively identify and reject its packets).

## Why the public identity was not preserved

Preservation required proving the S0 key was never copied while it lived as
a raw file (one day, 0600). No-leak is unprovable after raw-file exposure —
therefore, per the migration rule ("preserve only if proven safe"), the
identity was transitioned, not migrated. Nothing signed by the old identity
was ever published externally, so no external consumer is affected.

## Old-key disposition

- `~/.config/cds/aaap-identity/aaap-signing-key.pem` deleted.
- Honest APFS caveat: block-level erasure of the deleted extents is not
  guaranteed (snapshot/backup residue is possible). Mitigation: the retired
  identity is no longer a trust root anywhere — recovery of its bytes
  yields a key that anchors mark revoked.
- Old public half retained (`aaap-signing-key.pub.hex`) — public material,
  needed for revocation checks.

## What this changes and does not change

- Packet/manifest/live-signature formats: unchanged. No new cryptography.
  Signing now loads the key from the Keychain (`--identity-key
  keychain:production`); retrieval failure remains fail-closed.
- The migration's original 21-attack exercise passed, but that conclusion is
  withdrawn for v0.3: the post-release review found reproducible violations
  outside that suite. See `AAAP_POST_RELEASE_SECURITY.md`.
- Known residual (unchanged from the custody roadmap): a compromised host
  with an unlocked user keychain can still invoke the signing oracle;
  hardware-key custody (S2) is the documented next stage, deliberately not
  built now.
