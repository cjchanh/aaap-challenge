# AAAP Verifier Walkthrough — 10 Minutes, Zero Trust Required

You are the third party. You need nothing except this directory, Python 3.10+,
the `cryptography` package, and optionally the `openssl` CLI. You do not need
to trust the producer, the builder repo, or any claim in the report.

## The packet you are holding (1 min)

An autonomous-agent campaign ran under governance. The packet is the sealed
record of that run:

```
chain.jsonl        16 evidence envelopes, hash-chained (spec: ENVELOPE.md)
attestation.json   Ed25519 signature over the chain head
manifest.json      Ed25519 signature over the derived-file digest map
artifacts/         raw byte-for-byte copies of every sealed source
replay.json        builder-side recomputation + run summary (scope stated)
report.md          human-readable after-action report
verify_packet.py   the standalone verifier you are about to run
verify.json        output of the last verification (regenerated per run)
```

## Verify it (2 min)

```bash
cd packet
python3 verify_packet.py .
```

Expected:

```
PASS: chain intact, artifacts complete and intact, derived layer sealed by manifest, attestation valid [engines: cryptography, openssl]
verify.json written: .../verify.json
```

Exit code 0. Two independent Ed25519 implementations (`cryptography` Python
library and the `openssl` CLI) both verified the same signature; disagreement
would be a hard FAIL. Inspect `verify.json` — every check the verifier ran is
listed with pass/fail, nothing is aggregated away.

## Read what the run actually did (3 min)

```bash
cat report.md
```

This packet records an honest blocked run: the driver ran the guard twice
(red both times — the ledgers were empty, which is the truthful state),
probed the engine lane, could not verify the provider identity, and STOPPED
rather than fabricate progress (`engine_calls: 0`, stop reason
`provider-unknown`). The packet refuses to beautify this. That refusal is
the product.

`replay.json` → `summary.run` holds the same facts machine-readably.

## Try to forge it (3 min)

Copy the packet, edit one byte of the human report, re-verify:

```bash
cp -R packet forged && echo "sneaky edit" >> forged/report.md
python3 forged/verify_packet.py forged     # exit 1: manifest-report.md FAILED
```

Other one-byte forgeries to try, each caught and named:

```bash
# edit a sealed artifact copy
python3 -c "from pathlib import Path; p=Path('forged/artifacts/.builder-foundry__run_receipt.json'); p.write_text(p.read_text()+' ')"
# delete a middle chain entry
python3 -c "from pathlib import Path; L=Path('forged/chain.jsonl').read_text().splitlines(); del L[2]; Path('forged/chain.jsonl').write_text('\n'.join(L)+'\n')"
# replace the attestation signature
python3 -c "import json; from pathlib import Path; a=json.loads(Path('forged/attestation.json').read_text()); a['signature']='00'*64; Path('forged/attestation.json').write_text(json.dumps(a))"
python3 forged/verify_packet.py forged     # exit 1 each time, check named
```

Every modification you can make without the (destroyed) private key breaks
verification, including edits to this README and the report.

## Check the verifier itself (1 min)

The manifest seals `verify_packet.py`'s own sha256. Read it out:

```bash
python3 -c "import json,hashlib; m=json.load(open('manifest.json')); print(m['files']['verify_packet.py'] == hashlib.sha256(open('verify_packet.py','rb').read()).hexdigest())"
shasum -a 256 verify_packet.py   # compare manually
```

If you want independence from the shipped copy, obtain `packet_verifier.py`
from the published source, diff it against `verify_packet.py`, and run the
published one against this directory. The packet has no say in the matter.

## What you may conclude

If verification passed and you did the forgery steps: the sealed record is
byte-intact since build, the derived report cannot be edited, and the
signature covers exactly the bytes you were shown. What the record *means*
is documented in `docs/AAAP_PROVES.md` — including the boundaries (ephemeral
key, full-re-forge, producer-claimed timestamps). The packet states its own
limits; that is why you can trust the parts it does claim.
