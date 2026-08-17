#!/usr/bin/env python3
# ruff: noqa: E402
"""Standalone verifier for Attested After-Action Packets (AAAP v0.4).

Exit 0 = packet verified. Exit 1 = verification failed (fail-closed).
No network. Refuses unsafe output targets and atomically writes
<packet>/verify.json.

Verification is independent recompute, never trust:
  1. structure: chain.jsonl, attestation.json, manifest.json, artifacts/
  2. every artifact copy hashes to the sha256 sealed in its envelope
  3. every envelope receipt_hash matches canonical recompute
     (EVIDENCE_ENVELOPE v1.0 canonicalization: blank receipt_hash, recursively
     sorted keys, compact JSON separators, sha256 over UTF-8)
  4. chain links hold (envelope i seals envelope i-1's receipt_hash)
  5. completeness: artifacts/ contains exactly plain referenced files and
     required parent directories — no symlink/hardlink/special entries
  6. manifest v2: signature over every control field and exact derived-file
     map; each derived file hashes to its authenticated manifest entry
  7. attestation: Ed25519 signature over the recomputed chain head
  8. engine agreement: every checked signature must share the reported
     verifying engine set; any engine disagreement is a hard FAIL

What this is NOT: model-level replay (agent outputs are not regenerated) and
NOT execution replay (no sealed code is re-run). It is verification by
recompute at the evidence level.

Vendored into each packet. It still executes producer-supplied Python: audit or
sandbox it. Verification requires Python 3.10+ and either `cryptography` or an
OpenSSL build with Ed25519 support. The manifest seals this file's SHA-256 but
does not prove the code is benign.

Construction mirrors deponent operator_attest.py v1; no novel cryptography.
"""
from __future__ import annotations

import sys

# Direct script execution prepends this hostile packet directory to sys.path.
# Remove it before any non-built-in import so unsealed packet modules cannot
# shadow the standard library or cryptography ahead of root inventory.
_packet_import_root = sys.path[0] if sys.path else None
if __name__ == "__main__":
    sys.path[:] = [
        entry for entry in sys.path
        if entry and entry != _packet_import_root
    ]
del _packet_import_root

import argparse
import hashlib
import json
import math
import os
import shutil
import stat
import subprocess
import tempfile
from datetime import date
from pathlib import Path, PurePosixPath

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    _CRYPTO_OK = True
except Exception:
    _CRYPTO_OK = False

ATTEST_SCHEMA = "deponent-attestation/v1"
MANIFEST_SCHEMA = "aaap-manifest/2"
MANIFEST_FILES = ["PACKET.md", "ENVELOPE.md", "report.md", "replay.json",
                  "verify_packet.py"]
_PACKET_BASE_FILES = {"chain.jsonl", "attestation.json"}
_PACKET_SEALED_FILES = {"manifest.json", *MANIFEST_FILES}
_PACKET_OPTIONAL_FILES = {"verify.json"}
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_ENVELOPE_KEYS = {
    "envelope_id", "signal_sha256", "timestamp_utc", "source_system",
    "action_class", "route_selected", "policy_decision", "execution_result",
    "receipt_hash", "chain_index", "chain_prev",
}
_ATTESTATION_KEYS = {"schema", "operator_id", "chain_head", "pubkey", "signature"}
_MANIFEST_KEYS = {
    "schema", "files", "key_model", "operator_id", "pubkey", "live", "signature",
}
_LIVE_KEYS = {"ledger", "sigs", "entries", "head", "key_model", "verified_at_build"}
_LIVE_SIG_KEYS = {"schema", "idx", "entry_hash", "signature"}


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _parse_finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(f"non-finite JSON number: {token}")
    return value


def strict_json_loads(text: str, source: str = "JSON"):
    """Parse interoperable JSON: no duplicate keys or non-finite numbers."""
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_parse_finite_float,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {token}")
            ),
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"{source} unparseable: {exc}") from exc


def _require_exact_keys(value, expected: set[str], source: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{source} must be a JSON object")
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{source} fields differ (missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)})"
        )
    return value


def _is_plain_file(path: Path, root: Path | None = None) -> bool:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            return False
        if root is not None:
            path.resolve(strict=True).relative_to(root)
        return True
    except (OSError, ValueError):
        return False


def _is_plain_dir(path: Path) -> bool:
    try:
        return stat.S_ISDIR(path.lstat().st_mode)
    except OSError:
        return False


def _validate_packet_root(packet_dir: Path, require_manifest: bool) -> None:
    """Reject unsealed or unsafe packet-root entries."""
    required_files = set(_PACKET_BASE_FILES)
    if require_manifest:
        required_files.update(_PACKET_SEALED_FILES)
    allowed_files = required_files | _PACKET_OPTIONAL_FILES
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    try:
        entries = list(packet_dir.iterdir())
    except OSError as exc:
        raise ValueError(f"packet root unreadable: {exc}") from exc
    for entry in entries:
        if entry.name == "artifacts":
            if not _is_plain_dir(entry):
                raise ValueError("packet root artifacts entry is not a plain directory")
            actual_directories.add(entry.name)
        elif entry.name in allowed_files:
            if not _is_plain_file(entry, packet_dir):
                raise ValueError(f"packet root contains an unsafe file: {entry.name}")
            actual_files.add(entry.name)
        else:
            raise ValueError(f"packet root contains an unsealed entry: {entry.name}")
    missing = sorted(required_files - actual_files)
    if missing or actual_directories != {"artifacts"}:
        raise ValueError(
            f"packet root inventory incomplete (missing={missing}; "
            f"directories={sorted(actual_directories)})"
        )


def _hex64(value, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{label} must be 32-byte lowercase hex")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be 32-byte lowercase hex") from exc
    if len(decoded) != 32 or decoded.hex() != value:
        raise ValueError(f"{label} must be 32-byte lowercase hex")
    return value


def manifest_signed_bytes(manifest: dict) -> bytes:
    """Canonical v2 bytes signed by the packet identity.

    Every verifier control field is covered. The signature field is the sole
    excluded field because a signature cannot contain itself.
    """
    _require_exact_keys(manifest, _MANIFEST_KEYS, "manifest")
    payload = {key: manifest[key] for key in sorted(_MANIFEST_KEYS - {"signature"})}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def canonical_bytes(envelope: dict) -> bytes:
    sealed = dict(envelope)
    sealed["receipt_hash"] = ""
    return json.dumps(
        sealed,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


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


def _artifact_inventory(artifacts_dir: Path, packet_dir: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    for current, dirnames, filenames in os.walk(artifacts_dir, followlinks=False):
        current_path = Path(current)
        for name in list(dirnames):
            path = current_path / name
            if not _is_plain_dir(path):
                raise ValueError(f"artifacts contains a symlink or special directory: {path.name}")
            directories.add(path.relative_to(packet_dir).as_posix())
        for name in filenames:
            path = current_path / name
            if not _is_plain_file(path, packet_dir):
                raise ValueError(f"artifacts contains a symlink, hardlink, or special file: {path.name}")
            files.add(path.relative_to(packet_dir).as_posix())
    return files, directories


def _expected_artifact_directories(referenced: set[str]) -> set[str]:
    expected: set[str] = set()
    for item in referenced:
        parent = PurePosixPath(item).parent
        while parent.as_posix() not in (".", "artifacts"):
            expected.add(parent.as_posix())
            parent = parent.parent
    return expected


def load_agreed_anchors(paths: list[Path], packet_name: str) -> tuple[str, str, str]:
    """Load two byte-identical registries and return an active packet anchor."""
    if len(paths) != 2:
        raise ValueError("exactly two anchor registries are required")
    payloads = []
    resolved_paths = []
    file_ids = []
    for path in paths:
        path = Path(path).expanduser()
        if not _is_plain_file(path):
            raise ValueError(f"anchor registry is not a plain regular file: {path}")
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        resolved_paths.append(resolved)
        file_ids.append((metadata.st_dev, metadata.st_ino))
        payloads.append(path.read_bytes())
    if len(set(resolved_paths)) != 2 or len(set(file_ids)) != 2:
        raise ValueError("anchor registries must be two distinct files")
    if payloads[0] != payloads[1]:
        raise ValueError("anchor registries disagree byte-for-byte; trust neither")
    registry = strict_json_loads(payloads[0].decode("utf-8"), "anchor registry")
    _require_exact_keys(registry, {"schema", "identities", "packets"}, "anchor registry")
    if registry["schema"] != "aaap-anchors/1":
        raise ValueError(f"unsupported anchor schema: {registry['schema']!r}")
    if not isinstance(registry["identities"], list) or not isinstance(registry["packets"], list):
        raise ValueError("anchor identities and packets must be arrays")

    identities = {}
    public_keys = set()
    allowed_identity = {
        "identity_id", "algorithm", "pubkey", "operator", "valid_from",
        "valid_until", "revoked", "revocation_reason", "custody_stage",
    }
    required_identity = {
        "identity_id", "algorithm", "pubkey", "operator", "valid_from", "revoked",
    }
    for index, identity in enumerate(registry["identities"]):
        if not isinstance(identity, dict):
            raise ValueError(f"identity {index} must be an object")
        keys = set(identity)
        if not required_identity <= keys or not keys <= allowed_identity:
            raise ValueError(f"identity {index} has missing or unknown fields")
        identity_id = identity["identity_id"]
        if not isinstance(identity_id, str) or identity_id in identities:
            raise ValueError(f"identity {index} has invalid or duplicate identity_id")
        if identity["algorithm"] != "ed25519" or not isinstance(identity["revoked"], bool):
            raise ValueError(f"identity {identity_id} has invalid algorithm or revocation state")
        _hex64(identity["pubkey"], f"identity {identity_id} pubkey")
        if identity["pubkey"] in public_keys:
            raise ValueError(f"duplicate identity pubkey: {identity_id}")
        try:
            date.fromisoformat(identity["valid_from"])
            if "valid_until" in identity:
                date.fromisoformat(identity["valid_until"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"identity {identity_id} has invalid validity date") from exc
        identities[identity_id] = identity
        public_keys.add(identity["pubkey"])

    packets = {}
    packet_keys = {"name", "chain_head", "pubkey_identity", "sealed_at"}
    for index, packet in enumerate(registry["packets"]):
        _require_exact_keys(packet, packet_keys, f"packet anchor {index}")
        name = packet["name"]
        if not isinstance(name, str) or name in packets:
            raise ValueError(f"packet anchor {index} has invalid or duplicate name")
        _hex64(packet["chain_head"], f"packet {name} chain head")
        packets[name] = packet

    if packet_name not in packets:
        raise ValueError(f"packet anchor not found: {packet_name}")
    packet = packets[packet_name]
    identity_id = packet["pubkey_identity"]
    if identity_id not in identities:
        raise ValueError(f"packet references unknown identity: {identity_id}")
    identity = identities[identity_id]
    if identity["revoked"]:
        raise ValueError(f"packet identity is revoked: {identity_id}")
    try:
        sealed_at = date.fromisoformat(packet["sealed_at"])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"packet {packet_name} has invalid sealed_at date") from exc
    if sealed_at < date.fromisoformat(identity["valid_from"]):
        raise ValueError(f"packet predates identity validity: {identity_id}")
    if "valid_until" in identity and sealed_at > date.fromisoformat(identity["valid_until"]):
        raise ValueError(f"packet falls outside identity validity: {identity_id}")
    return packet["chain_head"], identity["pubkey"], identity_id


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

    if (expected_head is None) != (expected_pubkey is None):
        return fail("anchor pair incomplete: chain head and pubkey are both required")
    try:
        if expected_head is not None:
            _hex64(expected_head, "expected chain head")
            _hex64(expected_pubkey, "expected pubkey")
    except ValueError as exc:
        return fail(str(exc))

    if not check("packet-structure", _is_plain_file(chain_path, packet_dir)
                 and _is_plain_file(attest_path, packet_dir)
                 and _is_plain_dir(artifacts_dir),
                 "plain chain.jsonl, attestation.json, artifacts/ present"):
        return fail("packet structure incomplete")
    if require_manifest and not check("manifest-present", _is_plain_file(manifest_path, packet_dir),
                                      "manifest.json seals the derived layer"):
        return fail("manifest.json missing — derived files (report/replay/spec) are unsigned")
    try:
        _validate_packet_root(packet_dir, require_manifest)
    except ValueError as exc:
        return fail(str(exc))
    check("packet-root-inventory", True,
          "root contains only the exact sealed packet set plus optional verify.json")

    try:
        envelopes = []
        for line_number, line in enumerate(
                chain_path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            envelope = strict_json_loads(line, f"chain.jsonl line {line_number}")
            _require_exact_keys(envelope, _ENVELOPE_KEYS,
                                f"chain.jsonl line {line_number}")
            envelopes.append(envelope)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return fail(f"chain.jsonl rejected: {exc}")
    if not check("chain-nonempty", len(envelopes) > 0, f"{len(envelopes)} envelopes"):
        return fail("empty chain is not a run")

    if not check("sig-engine-available", _CRYPTO_OK or shutil.which("openssl") is not None,
                 "at least one Ed25519 engine (cryptography lib or openssl CLI)"):
        return fail("no Ed25519 engine available: cannot verify signatures")

    referenced: set[str] = set()
    prev_hash = ""
    head = ""
    for index, envelope in enumerate(envelopes):
        try:
            _hex64(envelope["receipt_hash"], f"envelope {index} receipt_hash")
            _hex64(envelope["signal_sha256"], f"envelope {index} signal_sha256")
            if index == 0:
                if envelope["chain_prev"] != "":
                    raise ValueError("envelope 0 chain_prev must be empty")
            else:
                _hex64(envelope["chain_prev"], f"envelope {index} chain_prev")
        except ValueError as exc:
            return fail(str(exc))
        if (not isinstance(envelope["chain_index"], int)
                or isinstance(envelope["chain_index"], bool)
                or envelope["chain_index"] != index):
            return fail(f"envelope {index} chain_index does not match its position")
        recomputed = canonical_sha256(envelope)
        if not check(f"envelope-{index:03d}-hash",
                     recomputed == envelope.get("receipt_hash", ""),
                     f"receipt_hash recompute {envelope.get('envelope_id', '?')}"):
            return fail(f"envelope {index} receipt_hash mismatch (record modified)")
        if not check(f"envelope-{index:03d}-link",
                     envelope.get("chain_prev", "") == prev_hash,
                     "chain link to prior envelope"):
            return fail(f"envelope {index} chain link broken (entry inserted, deleted, or reordered)")
        execution_result = envelope.get("execution_result")
        if not isinstance(execution_result, dict):
            return fail(f"envelope {index} execution_result must be an object")
        artifact_rel = execution_result.get("artifact")
        if artifact_rel is not None:
            if not isinstance(artifact_rel, str):
                return fail(f"envelope {index} artifact path must be a string")
            pure = PurePosixPath(artifact_rel)
            if (pure.is_absolute() or not pure.parts or pure.parts[0] != "artifacts"
                    or any(part in ("", ".", "..") for part in pure.parts)):
                return fail(f"envelope {index} has unsafe artifact path: {artifact_rel}")
            artifact_path = packet_dir.joinpath(*pure.parts)
            try:
                artifact_path.resolve(strict=True).relative_to(packet_dir)
            except ValueError:
                return fail(f"envelope {index} references path outside packet: {artifact_rel}")
            except OSError:
                return fail(f"envelope {index} artifact missing: {artifact_rel}")
            if not _is_plain_file(artifact_path, packet_dir):
                return fail(f"envelope {index} artifact missing: {artifact_rel}")
            try:
                artifact_sha256 = _hex64(
                    execution_result.get("sha256"),
                    f"envelope {index} execution_result sha256",
                )
            except ValueError as exc:
                return fail(str(exc))
            if artifact_sha256 != envelope["signal_sha256"]:
                return fail(
                    f"envelope {index} signal_sha256 does not bind its artifact digest"
                )
            if not check(f"envelope-{index:03d}-artifact",
                         sha256_file(artifact_path) == artifact_sha256,
                         f"artifact hash {artifact_rel}"):
                return fail(f"artifact {artifact_rel} hash mismatch (record modified)")
            referenced.add(pure.as_posix())
        prev_hash = envelope["receipt_hash"]
        head = prev_hash

    try:
        on_disk, on_disk_directories = _artifact_inventory(artifacts_dir, packet_dir)
    except ValueError as exc:
        return fail(str(exc))
    expected_directories = _expected_artifact_directories(referenced)
    if not check("artifacts-complete",
                 on_disk == referenced and on_disk_directories == expected_directories,
                 f"artifacts/ holds exactly the referenced set "
                 f"({len(referenced)} referenced, {len(on_disk)} present; "
                 f"{len(on_disk_directories)} directories)"):
        stray = sorted(on_disk - referenced)[:3]
        missing = sorted(referenced - on_disk)[:3]
        stray_dirs = sorted(on_disk_directories - expected_directories)[:3]
        return fail(f"artifacts/ completeness broken (stray: {stray or 'none'}; "
                    f"missing: {missing or 'none'}; stray dirs: {stray_dirs or 'none'})")

    try:
        attestation = strict_json_loads(
            attest_path.read_text(encoding="utf-8"), "attestation.json"
        )
        _require_exact_keys(attestation, _ATTESTATION_KEYS, "attestation.json")
        if attestation["schema"] != ATTEST_SCHEMA:
            raise ValueError(f"unsupported attestation schema: {attestation['schema']!r}")
        _hex64(attestation["chain_head"], "attestation chain head")
        _hex64(attestation["pubkey"], "attestation pubkey")
        if not isinstance(attestation["operator_id"], str) or not attestation["operator_id"]:
            raise ValueError("attestation operator_id must be a non-empty string")
        if (not isinstance(attestation["signature"], str)
                or len(bytes.fromhex(attestation["signature"])) != 64
                or bytes.fromhex(attestation["signature"]).hex() != attestation["signature"]):
            raise ValueError("attestation signature must be 64-byte lowercase hex")
    except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
        return fail(f"attestation.json rejected: {exc}")

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
            manifest = strict_json_loads(
                manifest_path.read_text(encoding="utf-8"), "manifest.json"
            )
            _require_exact_keys(manifest, _MANIFEST_KEYS, "manifest.json")
            if manifest["schema"] != MANIFEST_SCHEMA:
                raise ValueError(f"unsupported manifest schema: {manifest['schema']!r}")
            if manifest["key_model"] not in ("persistent-identity", "ephemeral-integrity"):
                raise ValueError(f"unsupported key model: {manifest['key_model']!r}")
            if not isinstance(manifest["files"], dict):
                raise ValueError("manifest files must be an object")
            if not isinstance(manifest["operator_id"], str) or not manifest["operator_id"]:
                raise ValueError("manifest operator_id must be a non-empty string")
            _hex64(manifest["pubkey"], "manifest pubkey")
            if (not isinstance(manifest["signature"], str)
                    or len(bytes.fromhex(manifest["signature"])) != 64
                    or bytes.fromhex(manifest["signature"]).hex() != manifest["signature"]):
                raise ValueError("manifest signature must be 64-byte lowercase hex")
            if manifest["live"] is not None:
                _require_exact_keys(manifest["live"], _LIVE_KEYS, "manifest live section")
        except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
            return fail(f"manifest.json rejected: {exc}")
        files = manifest["files"]
        if not check("manifest-files-complete",
                     set(files) == set(MANIFEST_FILES)
                     and all(isinstance(files[name], str) for name in MANIFEST_FILES),
                     f"manifest covers exactly {MANIFEST_FILES}"):
            return fail("manifest.json does not seal exactly the derived-file allowlist")
        for name in MANIFEST_FILES:
            target = packet_dir / name
            if not _is_plain_file(target, packet_dir) or not check(
                    f"manifest-{name}", sha256_file(target) == files.get(name),
                    "derived file hash matches manifest"):
                return fail(f"derived file {name} modified after build (or missing)")
        try:
            manifest_message = manifest_signed_bytes(manifest)
        except (TypeError, ValueError) as exc:
            return fail(f"manifest canonicalization rejected: {exc}")
        m_ok, m_engines, m_reason = _verify_ed25519(
            manifest["pubkey"], manifest_message, bytes.fromhex(manifest["signature"])
        )
        if not m_ok:
            return fail(f"manifest signature invalid ({m_reason})")
        check("manifest-signature", True,
              f"Ed25519 ok over every manifest control field ({', '.join(m_engines)})")
        engines[:] = [engine for engine in engines if engine in m_engines]
        if not engines:
            return fail("no single signature engine verified both attestation and manifest")

        if not check("identity-single-key",
                     manifest["pubkey"] == attestation["pubkey"]
                     and manifest["operator_id"] == attestation["operator_id"],
                     "packet seal and manifest share one identity and operator id"):
            return fail("manifest and attestation identity fields differ")

        live = manifest["live"]
        if live is not None:
            if (live["key_model"] != "capture-time-signed"
                    or not isinstance(live["entries"], int) or isinstance(live["entries"], bool)
                    or live["entries"] < 0
                    or not isinstance(live["verified_at_build"], list)):
                return fail("manifest live section has invalid field types")
            try:
                _hex64(live["head"], "live ledger head")
            except ValueError as exc:
                return fail(str(exc))
            for field in ("ledger", "sigs"):
                value = live[field]
                if not isinstance(value, str):
                    return fail(f"live {field} path must be a string")
                pure = PurePosixPath(value)
                if (pure.is_absolute() or not pure.parts or pure.parts[0] != "artifacts"
                        or any(part in ("", ".", "..") for part in pure.parts)):
                    return fail(f"live {field} path is unsafe: {value}")
            ledger_path = packet_dir.joinpath(*PurePosixPath(live["ledger"]).parts)
            sigs_path = packet_dir.joinpath(*PurePosixPath(live["sigs"]).parts)
            if not check("live-files-present",
                         _is_plain_file(ledger_path, packet_dir)
                         and _is_plain_file(sigs_path, packet_dir),
                         "sealed live ledger + sig stream present"):
                return fail("live section references missing files")
            try:
                entries = [strict_json_loads(line, f"live ledger line {index + 1}")
                           for index, line in enumerate(
                               ledger_path.read_text(encoding="utf-8").splitlines())
                           if line.strip()]
                sigs = [strict_json_loads(line, f"live signature line {index + 1}")
                        for index, line in enumerate(
                            sigs_path.read_text(encoding="utf-8").splitlines())
                        if line.strip()]
                for index, entry in enumerate(entries):
                    if not isinstance(entry, dict):
                        raise ValueError(f"live ledger line {index + 1} must be an object")
                for index, record in enumerate(sigs):
                    _require_exact_keys(record, _LIVE_SIG_KEYS,
                                        f"live signature line {index + 1}")
                    if record["schema"] != "aaap-live-sig/1":
                        raise ValueError(f"live signature {index} has unsupported schema")
            except (OSError, UnicodeDecodeError, ValueError) as exc:
                return fail(f"live artifacts rejected: {exc}")
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
                try:
                    signature_i = bytes.fromhex(record["signature"])
                except (TypeError, ValueError):
                    live_ok, live_detail = False, f"sig {i} malformed"
                    break
                if len(signature_i) != 64 or signature_i.hex() != record["signature"]:
                    live_ok, live_detail = False, f"sig {i} malformed"
                    break
                ok_i, engines_i, reason_i = _verify_ed25519(
                    attestation["pubkey"], msg_i, signature_i
                )
                if not ok_i:
                    live_ok, live_detail = False, f"sig {i} invalid ({reason_i})"
                    break
                engines[:] = [engine for engine in engines if engine in engines_i]
                if not engines:
                    live_ok, live_detail = False, (
                        f"sig {i} had no verifier engine in common with prior signatures"
                    )
                    break
            if not check("live-capture-signatures", live_ok,
                         live_detail or f"all {len(sigs)} capture-time signatures verify "
                         f"against the packet identity key ({', '.join(engines)})"):
                return fail(f"capture-time signature failure: {live_detail}")

    if not check("signature-engine-consistency", bool(engines),
                 f"common engines across every checked signature: {', '.join(engines)}"):
        return fail("signature engine coverage was inconsistent")

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


def _safe_result_target(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1


def _write_result_atomic(path: Path, result: dict) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".aaap-verify-", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        try:
            temporary_path.unlink()
        except OSError:
            pass
        raise


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Verify an AAAP packet fail-closed.")
    parser.add_argument("packet_dir")
    parser.add_argument("--expected-head")
    parser.add_argument("--expected-pubkey")
    parser.add_argument("--anchor-registry", action="append", default=[])
    parser.add_argument("--packet-name", default="packet")
    args = parser.parse_args(argv[1:])

    if bool(args.expected_head) != bool(args.expected_pubkey):
        parser.error("--expected-head and --expected-pubkey must be supplied together")
    if args.anchor_registry and (args.expected_head or args.expected_pubkey):
        parser.error("use agreed anchor registries or explicit anchors, not both")
    expected_head = args.expected_head
    expected_pubkey = args.expected_pubkey
    if args.anchor_registry:
        try:
            expected_head, expected_pubkey, identity_id = load_agreed_anchors(
                [Path(path) for path in args.anchor_registry], args.packet_name
            )
            print(f"anchor identity active: {identity_id}")
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            print(f"FAIL: anchor registry rejected: {exc}", file=sys.stderr)
            return 1

    packet_dir = Path(args.packet_dir).expanduser().resolve()
    result_path = packet_dir / "verify.json"
    if not _safe_result_target(result_path):
        print("FAIL: unsafe verify.json output target (symlink, hardlink, or special file)",
              file=sys.stderr)
        return 1
    result = verify_packet(packet_dir,
                           expected_head=expected_head,
                           expected_pubkey=expected_pubkey)
    try:
        _write_result_atomic(result_path, result)
    except OSError as exc:
        print(f"FAIL: could not safely write verify.json: {exc}", file=sys.stderr)
        return 1
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
