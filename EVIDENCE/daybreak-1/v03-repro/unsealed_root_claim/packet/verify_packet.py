#!/usr/bin/env python3
"""Standalone verifier for Attested After-Action Packets (AAAP v0.1).

Exit 0 = packet verified. Exit 1 = verification failed (fail-closed).
No network. Writes only <packet>/verify.json.

Verification is independent recompute, never trust:
  1. structure: chain.jsonl, attestation.json, manifest.json, artifacts/
  2. every artifact copy hashes to the sha256 sealed in its envelope
  3. every envelope receipt_hash matches canonical recompute
     (EVIDENCE_ENVELOPE v1.0 canonicalization: blank receipt_hash, recursively
     sorted keys, compact JSON separators, sha256 over UTF-8)
  4. chain links hold (envelope i seals envelope i-1's receipt_hash)
  5. completeness: artifacts/ contains exactly the referenced set — nothing
     smuggled in, nothing missing
  6. manifest: signature over the derived-file digest map, and every derived
     file (report.md, replay.json, PACKET.md, ENVELOPE.md, verify_packet.py)
     hashes to its manifest entry — the human-readable layer cannot be edited
  7. attestation: Ed25519 signature over the recomputed chain head
  8. dual-engine: when the openssl CLI supports Ed25519, the signature is
     verified by BOTH the `cryptography` library and openssl; disagreement
     is a hard FAIL, single-engine runs are recorded as such

What this is NOT: model-level replay (agent outputs are not regenerated) and
NOT execution replay (no sealed code is re-run). It is verification by
recompute at the evidence level.

Vendored into each packet so a third party needs only the packet + Python
3.10+ (+ `cryptography`; openssl CLI optional second engine). The manifest
seals this file's own sha256 so a third party can diff it against an
independently published copy.

Construction mirrors deponent operator_attest.py v1; no novel cryptography.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    _CRYPTO_OK = True
except Exception:
    _CRYPTO_OK = False

ATTEST_SCHEMA = "deponent-attestation/v1"
MANIFEST_SCHEMA = "aaap-manifest/1"
MANIFEST_FILES = ["PACKET.md", "ENVELOPE.md", "report.md", "replay.json",
                  "verify_packet.py"]
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def canonical_bytes(envelope: dict) -> bytes:
    sealed = dict(envelope)
    sealed["receipt_hash"] = ""
    return json.dumps(sealed, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_sha256(envelope: dict) -> str:
    return hashlib.sha256(canonical_bytes(envelope)).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def files_digest(files: dict[str, str]) -> str:
    """sha256 over the canonical JSON of the {name: sha256} map. This is the
    digest the manifest signature covers (via the attestation construction)."""
    payload = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _signed_bytes(operator_id: str, head: str) -> bytes:
    return json.dumps({"schema": ATTEST_SCHEMA, "operator_id": operator_id,
                       "chain_head": head}, sort_keys=True).encode("utf-8")


def _openssl_verify(pubkey_hex: str, message: bytes, signature: bytes) -> bool | None:
    """Independent Ed25519 verification via the openssl CLI.
    Returns True/False verdicts, or None when openssl cannot run the check
    (absent binary, no Ed25519 support). None never passes or fails a packet."""
    openssl = shutil.which("openssl")
    if not openssl:
        return None
    try:
        key_der = _ED25519_SPKI_PREFIX + bytes.fromhex(pubkey_hex)
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            (tmpdir / "pub.der").write_bytes(key_der)
            pub_pem = subprocess.run(
                [openssl, "pkey", "-pubin", "-inform", "DER",
                 "-in", str(tmpdir / "pub.der"), "-out", str(tmpdir / "pub.pem")],
                capture_output=True, timeout=30)
            if pub_pem.returncode != 0:
                return None
            (tmpdir / "msg.bin").write_bytes(message)
            (tmpdir / "sig.bin").write_bytes(signature)
            result = subprocess.run(
                [openssl, "pkeyutl", "-verify", "-pubin",
                 "-inkey", str(tmpdir / "pub.pem"), "-rawin",
                 "-in", str(tmpdir / "msg.bin"),
                 "-sigfile", str(tmpdir / "sig.bin")],
                capture_output=True, text=True, timeout=30)
            if "not supported" in result.stderr.lower() or "unknown option" in result.stderr.lower():
                return None
            return result.returncode == 0
    except (subprocess.SubprocessError, OSError, ValueError):
        return None


def _verify_ed25519(pubkey_hex: str, message: bytes, signature: bytes) -> tuple[bool, list[str], str]:
    """Dual-engine Ed25519 verification. Returns (ok, engines, reason).
    - both engines present: both must verify (disagreement = fail)
    - one engine present: it is sufficient (minimal-dependency third parties)
    - zero engines: fail-closed"""
    engines: list[str] = []
    crypto_ok: bool | None = None
    openssl_ok: bool | None = _openssl_verify(pubkey_hex, message, signature)
    if _CRYPTO_OK:
        engines.append("cryptography")
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
            pub.verify(signature, message)
            crypto_ok = True
        except (InvalidSignature, ValueError):
            crypto_ok = False
    if openssl_ok is not None:
        engines.append("openssl")
    verdicts = [v for v in (crypto_ok, openssl_ok) if v is not None]
    if not verdicts:
        return False, [], "no Ed25519 engine available (need the cryptography lib or the openssl CLI)"
    if False in verdicts:
        return False, engines, "signature invalid (engine disagreement counts as invalid)"
    return True, engines, "ok"


def verify_packet(packet_dir: Path, require_manifest: bool = True,
                  expected_head: str | None = None,
                  expected_pubkey: str | None = None) -> dict:
    """Recompute everything from the packet alone. Returns the verdict dict.

    Optional out-of-band anchors (defense against full re-forge): when the
    chain head and/or signing pubkey have been published independently,
    pass them here — a packet whose recomputed head or pubkey differs fails
    closed even if it is internally perfectly consistent."""
    checks: list[dict] = []
    engines: list[str] = []

    def check(name: str, ok: bool, detail: str) -> bool:
        checks.append({"check": name, "passed": ok, "detail": detail})
        return ok

    def fail(reason: str) -> dict:
        return {"schema": "aaap-verify/1", "verdict": "FAIL", "reason": reason,
                "engines": engines, "checks": checks}

    packet_dir = packet_dir.resolve()
    chain_path = packet_dir / "chain.jsonl"
    attest_path = packet_dir / "attestation.json"
    manifest_path = packet_dir / "manifest.json"
    artifacts_dir = packet_dir / "artifacts"

    if not check("packet-structure", chain_path.is_file() and attest_path.is_file()
                 and artifacts_dir.is_dir(), "chain.jsonl, attestation.json, artifacts/ present"):
        return fail("packet structure incomplete")
    if require_manifest and not check("manifest-present", manifest_path.is_file(),
                                      "manifest.json seals the derived layer"):
        return fail("manifest.json missing — derived files (report/replay/spec) are unsigned")

    try:
        envelopes = [json.loads(line) for line in
                     chain_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return fail(f"chain.jsonl unparseable: {exc}")
    if not check("chain-nonempty", len(envelopes) > 0, f"{len(envelopes)} envelopes"):
        return fail("empty chain is not a run")

    if not check("sig-engine-available", _CRYPTO_OK or shutil.which("openssl") is not None,
                 "at least one Ed25519 engine (cryptography lib or openssl CLI)"):
        return fail("no Ed25519 engine available: cannot verify signatures")

    referenced: set[str] = set()
    prev_hash = ""
    head = ""
    for index, envelope in enumerate(envelopes):
        recomputed = canonical_sha256(envelope)
        if not check(f"envelope-{index:03d}-hash",
                     recomputed == envelope.get("receipt_hash", ""),
                     f"receipt_hash recompute {envelope.get('envelope_id', '?')}"):
            return fail(f"envelope {index} receipt_hash mismatch (record modified)")
        if not check(f"envelope-{index:03d}-link",
                     envelope.get("chain_prev", "") == prev_hash,
                     "chain link to prior envelope"):
            return fail(f"envelope {index} chain link broken (entry inserted, deleted, or reordered)")
        artifact_rel = envelope.get("execution_result", {}).get("artifact")
        if artifact_rel is not None:
            artifact_path = (packet_dir / artifact_rel).resolve()
            try:
                artifact_path.relative_to(packet_dir)
            except ValueError:
                return fail(f"envelope {index} references path outside packet: {artifact_rel}")
            if not artifact_path.is_file():
                return fail(f"envelope {index} artifact missing: {artifact_rel}")
            if not check(f"envelope-{index:03d}-artifact",
                         sha256_file(artifact_path) == envelope["execution_result"].get("sha256", ""),
                         f"artifact hash {artifact_rel}"):
                return fail(f"artifact {artifact_rel} hash mismatch (record modified)")
            referenced.add(artifact_path.relative_to(packet_dir).as_posix())
        prev_hash = envelope["receipt_hash"]
        head = prev_hash

    on_disk = {p.relative_to(packet_dir).as_posix()
               for p in artifacts_dir.rglob("*") if p.is_file()}
    if not check("artifacts-complete",
                 on_disk == referenced,
                 f"artifacts/ holds exactly the referenced set "
                 f"({len(referenced)} referenced, {len(on_disk)} present)"):
        stray = sorted(on_disk - referenced)[:3]
        missing = sorted(referenced - on_disk)[:3]
        return fail(f"artifacts/ completeness broken (stray: {stray or 'none'}; "
                    f"missing: {missing or 'none'})")

    try:
        attestation = json.loads(attest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return fail(f"attestation.json unparseable: {exc}")

    if not check("attestation-head-binding",
                 attestation.get("chain_head") == head,
                 "attestation bound to recomputed chain head"):
        return fail("attestation head mismatch (chain truncated or re-forged)")

    if expected_head is not None and not check(
            "anchor-chain-head", head == expected_head,
            "recomputed head matches independently published anchor"):
        return fail("chain head does not match the published anchor "
                    "(possible full re-forge)")
    if expected_pubkey is not None and not check(
            "anchor-pubkey", attestation.get("pubkey", "") == expected_pubkey,
            "signing key matches independently published anchor"):
        return fail("signing pubkey does not match the published anchor "
                    "(possible re-signed re-forge)")

    try:
        pubkey_hex = attestation["pubkey"]
        signature = bytes.fromhex(attestation["signature"])
        operator_id = attestation["operator_id"]
    except (KeyError, ValueError, TypeError):
        return fail("attestation malformed")

    message = _signed_bytes(operator_id, attestation["chain_head"])
    sig_ok, sig_engines, sig_reason = _verify_ed25519(pubkey_hex, message, signature)
    engines.extend(sig_engines)
    if not check("attestation-signature", sig_ok,
                 f"Ed25519 ok ({', '.join(sig_engines)}) for operator_id={operator_id}"):
        return fail(f"attestation signature invalid ({sig_reason})")

    if require_manifest:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return fail(f"manifest.json unparseable: {exc}")
        files = manifest.get("files", {})
        if not check("manifest-files-complete",
                     all(name in files for name in MANIFEST_FILES),
                     f"manifest covers {MANIFEST_FILES}"):
            return fail("manifest.json does not seal all derived files")
        for name in MANIFEST_FILES:
            target = packet_dir / name
            if not target.is_file() or not check(
                    f"manifest-{name}", sha256_file(target) == files.get(name),
                    "derived file hash matches manifest"):
                return fail(f"derived file {name} modified after build (or missing)")
        manifest_message = _signed_bytes(manifest.get("operator_id", ""),
                                        files_digest(files))
        m_ok, m_engines, m_reason = _verify_ed25519(
            manifest["pubkey"], manifest_message, bytes.fromhex(manifest["signature"]))
        if not m_ok:
            return fail(f"manifest signature invalid ({m_reason})")
        check("manifest-signature", True,
              f"Ed25519 ok over derived-file digest map ({', '.join(m_engines)})")

        if not check("identity-single-key",
                     manifest.get("pubkey") == attestation.get("pubkey"),
                     "packet seal and manifest share one identity key"):
            return fail("manifest and attestation pubkeys differ (mixed keys)")

        live = manifest.get("live")
        if live is not None:
            ledger_path = packet_dir / live.get("ledger", "")
            sigs_path = packet_dir / live.get("sigs", "")
            if not check("live-files-present", ledger_path.is_file() and sigs_path.is_file(),
                         "sealed live ledger + sig stream present"):
                return fail("live section references missing files")
            try:
                entries = [json.loads(line) for line in
                           ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]
                sigs = [json.loads(line) for line in
                        sigs_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                return fail(f"live artifacts unparseable: {exc}")
            if not check("live-length-anchor",
                         len(entries) == live.get("entries"),
                         f"ledger length {len(entries)} == signed manifest anchor "
                         f"{live.get('entries')} (consistent truncation detected here)"):
                return fail("ledger truncated/extended relative to the signed "
                            "manifest length anchor")
            prev = "GENESIS"
            chain_ok = True
            for i, entry in enumerate(entries):
                payload = {k: entry[k] for k in entry
                           if k not in ("prev_hash", "entry_hash")}
                import hashlib as _h
                body = json.dumps(payload, sort_keys=True, ensure_ascii=False)
                expected = _h.sha256(f"{prev}\n{body}".encode("utf-8")).hexdigest()
                if entry.get("prev_hash") != prev or entry.get("entry_hash") != expected:
                    chain_ok = False
                    break
                prev = entry["entry_hash"]
            if not check("live-ledger-chain", chain_ok,
                         "ledger chain recomputes (mirrored deponent algorithm)"):
                return fail("live ledger chain broken (entry rewritten after capture)")
            if not check("live-head-anchor", prev == live.get("head"),
                         "ledger head matches signed manifest anchor"):
                return fail("live ledger head differs from the signed manifest anchor")
            if len(sigs) != len(entries):
                return fail(f"sig count {len(sigs)} != entry count {len(entries)}")
            live_ok = True
            live_detail = ""
            for i, record in enumerate(sigs):
                if record.get("idx") != i or record.get("entry_hash") != entries[i].get("entry_hash"):
                    live_ok, live_detail = False, f"sig {i} idx/hash binding broken"
                    break
                msg_i = json.dumps({"schema": "aaap-live-sig/1", "idx": i,
                                    "entry_hash": entries[i]["entry_hash"]},
                                   sort_keys=True, separators=(",", ":")).encode("utf-8")
                ok_i, _, reason_i = _verify_ed25519(attestation["pubkey"], msg_i,
                                                    bytes.fromhex(record["signature"]))
                if not ok_i:
                    live_ok, live_detail = False, f"sig {i} invalid ({reason_i})"
                    break
            if not check("live-capture-signatures", live_ok,
                         live_detail or f"all {len(sigs)} capture-time signatures verify "
                         "against the packet identity key"):
                return fail(f"capture-time signature failure: {live_detail}")

    return {
        "schema": "aaap-verify/1",
        "verdict": "PASS",
        "reason": "chain intact, artifacts complete and intact, derived layer "
                  "sealed by manifest, attestation valid",
        "engines": engines,
        "checks": checks,
        "chain_head": head,
        "envelope_count": len(envelopes),
    }


def main(argv: list[str]) -> int:
    args_ok = len(argv) in (2, 3, 4) and not argv[1].startswith("--")
    anchors = {}
    rest = argv[1:]
    packet_arg = None
    i = 0
    while i < len(rest):
        if rest[i] == "--expected-head":
            anchors["head"] = rest[i + 1]
            i += 2
        elif rest[i] == "--expected-pubkey":
            anchors["pubkey"] = rest[i + 1]
            i += 2
        else:
            packet_arg = rest[i]
            i += 1
    if packet_arg is None:
        print("usage: verify_packet.py <packet-dir> "
              "[--expected-head SHA256] [--expected-pubkey HEX]", file=sys.stderr)
        return 1
    packet_dir = Path(packet_arg).expanduser().resolve()
    result = verify_packet(packet_dir,
                           expected_head=anchors.get("head"),
                           expected_pubkey=anchors.get("pubkey"))
    result_path = packet_dir / "verify.json"
    result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"{result['verdict']}: {result.get('reason', '')}"
          + (f" [engines: {', '.join(result.get('engines', []))}]"
             if result.get("engines") else ""))
    for entry in result.get("checks", []):
        if not entry["passed"]:
            print(f"  FAILED: {entry['check']} — {entry['detail']}")
    print(f"verify.json written: {result_path}")
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
