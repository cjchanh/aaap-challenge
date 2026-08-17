# AAAP v0.3 Post-Release Security Review

Frozen vulnerable challenge commit:
`e0fca96651b30c76d0a29bf867cdd14cdc38db00`

Frozen anchor commit:
`9deae6c211843544d8d4d5143f0ee266e36caab2`

The original evidence remains immutable. `security/aaap_v03_reproducers.py`
creates disposable clones and reproduced every row below with the original
anchored verifier returning exit 0.

| Finding | Root cause | v0.4 remediation |
|---|---|---|
| Live-signature verification could be removed | v1 manifest signed only `files`; `live` was unsigned and optional | v2 signs every manifest control field and requires explicit live object or null |
| Key model and manifest schema could be rewritten | unsigned manifest metadata | exact v2 fields inside the signature |
| Attestation schema and arbitrary custody claim could be rewritten | actual schema was not checked; extra fields allowed | exact attestation fields and schema validation |
| Duplicate-key chain produced verifier disagreement | permissive last-key-wins JSON | duplicate-key rejection for every JSON surface |
| `NaN` manifest still passed | Python's non-standard JSON constants were accepted | non-finite-number rejection |
| `verify.json` symlink overwrote sealed `report.md`, then exited PASS in both verifier entry points | result writes followed attacker-controlled symlinks after checks | shared unsafe-target rejection and atomic write in shipped and source CLIs |
| Dangling artifact symlink and extra directory passed completeness | inventory counted only `is_file()` results | lstat-based exact tree inventory; reject symlink/hardlink/special/extra entries |
| Derived file could escape by symlink | fixed manifest paths used following `is_file()` and hashing | plain regular in-packet file requirement |
| Attacker could add a plausible unsealed root claim while anchored verification returned PASS | packet root had no exact inventory | exact root allowlist; `verify.json` is the only unsealed optional entry |
| Public anchor command ignored disagreement and revocation semantics | manual array-index extraction passed only head/pubkey | two-registry mode with exact agreement, active identity, uniqueness, and validity checks |
| Deterministic source ZIP admitted tracked `.tmp/` receipts | package selectors excluded `tmp/` but not `.tmp/` | both package selectors now exclude `.tmp/`; ignore policy prevents recurrence |
| Portability, custody, timing, and origin claims exceeded evidence | stale v0.1/v0.2 prose and conflated operational assertions with cryptographic proof | claim set rewritten to explicit byte/semantic/trust boundaries |

The v0.4 regression lane also gives a test signer the packet key. It proves the
verifier rejects a correctly re-signed envelope whose `chain_index` conflicts
with its actual position or whose `signal_sha256` conflicts with the copied
artifact digest. These are semantic cross-binding checks, not claims that an
outsider can recover the production private key or bypass the published v0.3
head.

The current two repositories remain under one GitHub account. They are two
histories, not independent custody. A neutral witness remains future work.
