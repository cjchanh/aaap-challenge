# AAAP Daybreak Post-Release Security Report

## Verdict

**DAYBREAK POST-RELEASE VERDICT: HARDENED**

The immutable public AAAP v0.3 release is reproducibly broken. A locally
committed, production-signed v0.4 successor survived the final detached-clone
attack pass. Per operator authority, it was not pushed or published.

## Frozen inputs and outputs

| Object | Hash |
|---|---|
| vulnerable challenge commit | `e0fca96651b30c76d0a29bf867cdd14cdc38db00` |
| vulnerable challenge tree | `1d58103aba8f3830b52639b85f6c2b7c2ec12d1a` |
| anchor commit | `9deae6c211843544d8d4d5143f0ee266e36caab2` |
| anchor tree | `f7758dfefc17ee49e7bee1208134586a5975c771` |
| hardening source commit | `539e70c28c9c23f680408a8eb3c51f37978876e5` |
| hardening source tree | `7886d1da55462fc9a1273024765ea8594f372084` |
| local v0.4 successor commit | `8f5ba31fb2d9e6b98659fabcef9f63e25c6e7f3f` |
| local v0.4 successor tree | `ed0df0217a68d1e38847e51a9cf79e2cbf592b35` |
| packet Git tree | `9e637e89927f7dba780c54d558fd86d20a104ec0` |
| artifacts Git tree | `c8647953ce319f6ee80fcd54c408ff17ee660dec` |
| manifest SHA-256 | `964d21c3c9a596bd8c58f45637a23a487a2ccba88ed1cad478b2bc37a8a42775` |
| verifier SHA-256 | `b7177c7607f3af7ff5de4453089045e27213943510d3d2bff10377f47c912641` |
| release ZIP SHA-256 | `e64a0111772ecefc5670545dbe460537a089345786174436a97b709ed0b47b56` |
| anchors.json SHA-256 | `5089761115f55649c16a7d68ae97e6636ab880a6fb1589e7d1ba392776eb28e1` |

The v0.4 chain and attestation SHA-256 values remain exactly equal to v0.3:

- `chain.jsonl`: `65bbcda8147756a83a5398922f1c78f2d598d36827bd7cc6acea4fa00221fe68`
- `attestation.json`: `c7b5fb877639a0a0598e363ceaf83aeb38025cd0d42bd41fffe8c54fd36bf093`

## Reproducible public v0.3 violations

All 11 cases returned exit 0 under the published head and pubkey.

| Break | Root cause | Remediation |
|---|---|---|
| remove `manifest.live` and skip capture-signature verification | manifest v1 signed only the derived-file digest | manifest v2 signs every control field; `live` must be object or explicit null |
| rewrite manifest key model | unsigned control metadata | full-control-body signature plus exact field set |
| rewrite manifest schema | schema not authenticated or enforced | exact authenticated v2 schema |
| inject non-standard `NaN` | permissive Python JSON parser | reject duplicate keys and all non-finite numbers |
| rewrite attestation schema | schema value not checked | exact attestation schema and fields |
| add false custody claim to attestation | unknown unsigned fields accepted | reject every extra attestation field |
| conflicting duplicate chain key | last-key-wins parsing creates verifier disagreement | recursive duplicate-key rejection |
| `verify.json` symlink overwrites sealed `report.md` while command returns PASS | post-check result write followed attacker path | unsafe-target rejection and atomic replacement in both verifier entry points |
| dangling artifact symlink passes | completeness considered only resolved regular files | lstat-based exact tree/type inventory |
| add plausible unsealed root approval file | packet root had no exact inventory | exact root allowlist; only optional unsealed output is `verify.json` |
| derived file symlink escapes packet | verifier followed fixed-name symlinks | require single-link regular files resolving inside packet |

Adjacent source-release findings were also fixed: tracked `.tmp/` receipts were
eligible for the deterministic ZIP, and the source `evidence_packet.py verify`
entry point shared the output-symlink flaw. These were source/package breaks,
not files present in the public challenge commit.

Defense-in-depth regression also rejects a correctly re-signed envelope whose
`chain_index` conflicts with its physical position or whose `signal_sha256`
conflicts with its artifact digest. That test uses a disposable test signer; it
does not claim an outsider recovered the production key.

## Claims changed

- “second origin” is withdrawn. The repositories are two Git histories under
  one `github.com/cjchanh` account, not independent administration or custody.
- “signed at the moment it happened” is withdrawn. Signatures bind indexed
  content; they do not prove wall-clock time or causal placement.
- Keychain custody and “never existed as a raw file” are operator-reported
  operational claims, not packet-verifiable facts.
- “zero installs / OpenSSL preinstalled almost everywhere” is withdrawn.
  Stock macOS without a capable engine failed closed.
- “no trust in us required” is narrowed: the shipped verifier is
  producer-supplied executable Python and must be audited or sandboxed.
- Registry mode enforces only the supplied bytes. Two matching stale snapshots
  cannot reveal a later revocation.
- Persistent identity wording replaces the contradictory v0.3 report text that
  called the production signer ephemeral.
- Commit SHAs are described as content pins, not signatures. Both original
  public root commits and the local successor commit are unsigned.

## Verification performed

- source suite: `283 tests`, `OK`, `3 skipped`;
- source package verifier: PASS;
- source Python compile and `git diff --check`: PASS;
- legacy 21-case adversarial exercise: every must-catch caught; documented
  full-reforge/layout boundaries remained anchor-detectable or explicit;
- final v0.4 hostile battery: 17/17 expected outcomes, including baseline PASS;
- malicious disposable-signer semantic battery: 19/19 expected outcomes;
- explicit head/pubkey verification: PASS with `cryptography, openssl`;
- two-registry active/revocation verification: PASS with exact anchor commit;
- stock macOS-style no-engine lane: exit 1, FAIL closed;
- clean detached successor clone remained Git-clean after the attack harness;
- original challenge and anchor clones remained Git-clean.

## Remaining trust assumptions and limitations

1. SHA-256 and Ed25519 remain cryptographically sound.
2. At least one available signature engine and the host runtime are honest; if
   both engines are present, both must agree.
3. Shipped Python, Python itself, OpenSSL/cryptography, kernel, and filesystem
   are not subverted. Run hostile packets with least privilege.
4. The packet directory and anchor files remain stable during one verification
   call. Concurrent hostile filesystem mutation is outside the guarantee.
5. Anchor acquisition and freshness are external trust decisions. Exact
   historic mode intentionally ignores later revocation; registry mode knows
   only the registry bytes supplied.
6. The same GitHub account controls both repositories. A compromise scoped to
   one repository may be exposed by comparison; account-wide or coordinated
   action is not resisted. A separately conveyed exact SHA still pins content.
7. Production-key compromise or an authorized signing oracle can sign false or
   conflicting records. A packet signature does not prove Keychain custody.
8. Timestamps, world truth, product quality, and signing-path causality are not
   proven. JSON whitespace/layout is intentionally not sealed.
9. The verifier does not promise availability bounds for oversized hostile
   inputs; apply OS CPU, memory, file-size, and process limits.
10. The local successor Git commit is a content pin, not a signed release
    commit. The manifest is production-key signed. No push/publication occurred.

## Exact clean-room commands

```bash
git clone https://github.com/cjchanh/aaap-challenge aaap-v03
git -C aaap-v03 checkout --detach e0fca96651b30c76d0a29bf867cdd14cdc38db00
git clone https://github.com/cjchanh/aaap-anchors aaap-anchors
git -C aaap-anchors checkout --detach 9deae6c211843544d8d4d5143f0ee266e36caab2

python3 <SCRUBBED-TMP-PATH> \
  --challenge "$PWD/aaap-v03" \
  --out "$PWD/v03-reproductions"

git clone --no-hardlinks \
  <SCRUBBED-TMP-PATH> aaap-v04
git -C aaap-v04 checkout --detach 8f5ba31fb2d9e6b98659fabcef9f63e25c6e7f3f

python3 aaap-v04/packet/verify_packet.py aaap-v04/packet \
  --expected-head 14d14281170d89f6f8b918daf6541f81e7e13549dd4c66f5b085304ff6a61724 \
  --expected-pubkey e7fb4aad8b0e0246eb6569f49d301ad88a0b54333e3de8bb57e02e118fd3716c

python3 aaap-v04/packet/verify_packet.py aaap-v04/packet \
  --anchor-registry aaap-v04/anchors.json \
  --anchor-registry aaap-anchors/anchors.json \
  --packet-name demo/packet

python3 <SCRUBBED-TMP-PATH> \
  --packet "$PWD/aaap-v04/packet" \
  --out "$PWD/v04-legacy-attacks"

python3 <SCRUBBED-TMP-PATH> \
  --packet "$PWD/aaap-v04/packet" \
  --out "$PWD/v04-daybreak-attacks"

shasum -a 256 \
  <SCRUBBED-TMP-PATH>
```
