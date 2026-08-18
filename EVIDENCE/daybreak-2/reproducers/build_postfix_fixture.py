#!/usr/bin/env python3
"""Build a deterministic test-only packet signed for post-fix hostile testing."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path("<SCRUBBED-TMP-PATH>")
SOURCE_REPO = ROOT / "successor" / "aaap-challenge"
OUTPUT = ROOT / "reproducers" / "postfix-fixture-v2"
PACKET = OUTPUT / "packet"
OPERATOR = "daybreak-ii/local-test-only"
IDENTITY = "aaap-daybreak-ii-local-test"
ATTEST_SCHEMA = "deponent-attestation/v1"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_envelope(envelope: dict) -> bytes:
    value = dict(envelope)
    value["receipt_hash"] = ""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def attestation_message(head: str) -> bytes:
    return json.dumps(
        {"schema": ATTEST_SCHEMA, "operator_id": OPERATOR, "chain_head": head},
        sort_keys=True,
    ).encode("utf-8")


def manifest_message(manifest: dict) -> bytes:
    payload = {key: manifest[key] for key in sorted(set(manifest) - {"signature"})}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def main() -> int:
    if OUTPUT.exists():
        raise SystemExit(f"refusing to overwrite preserved fixture: {OUTPUT}")
    shutil.copytree(SOURCE_REPO / "packet", PACKET)

    # Public, deterministic test seed. Never use this identity outside this fixture.
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("42" * 32))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    ledger_path = PACKET / "artifacts" / "live" / "ledger.jsonl"
    sigs_path = PACKET / "artifacts" / "live" / "ledger.sig.jsonl"
    entries = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    signatures = []
    for index, entry in enumerate(entries):
        message = json.dumps(
            {"schema": "aaap-live-sig/1", "idx": index, "entry_hash": entry["entry_hash"]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        signatures.append({
            "schema": "aaap-live-sig/1",
            "idx": index,
            "entry_hash": entry["entry_hash"],
            "signature": private_key.sign(message).hex(),
        })
    sigs_path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in signatures),
        encoding="utf-8",
    )

    chain_path = PACKET / "chain.jsonl"
    envelopes = [json.loads(line) for line in chain_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    final = envelopes[-1]
    if final["execution_result"]["artifact"] != "artifacts/live/ledger.sig.jsonl":
        raise SystemExit("unexpected final artifact; refusing to construct fixture")
    live_sigs_hash = sha256(sigs_path)
    final["execution_result"]["sha256"] = live_sigs_hash
    final["signal_sha256"] = live_sigs_hash
    final["receipt_hash"] = hashlib.sha256(canonical_envelope(final)).hexdigest()
    chain_path.write_text(
        "".join(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n" for item in envelopes),
        encoding="utf-8",
    )
    chain_head = final["receipt_hash"]

    attestation = json.loads((PACKET / "attestation.json").read_text(encoding="utf-8"))
    attestation.update({
        "operator_id": OPERATOR,
        "chain_head": chain_head,
        "pubkey": public_key,
        "signature": private_key.sign(attestation_message(chain_head)).hex(),
    })
    (PACKET / "attestation.json").write_text(
        json.dumps(attestation, indent=2) + "\n", encoding="utf-8"
    )

    manifest = json.loads((PACKET / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"]["verify_packet.py"] = sha256(PACKET / "verify_packet.py")
    manifest["operator_id"] = OPERATOR
    manifest["pubkey"] = public_key
    manifest["key_model"] = "ephemeral-integrity"
    manifest["signature"] = private_key.sign(manifest_message(manifest)).hex()
    (PACKET / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    registry = json.loads((SOURCE_REPO / "anchors.json").read_text(encoding="utf-8"))
    active = registry["identities"][0]
    active.update({
        "identity_id": IDENTITY,
        "pubkey": public_key,
        "operator": "Daybreak II local test fixture only",
        "revoked": False,
        "custody_stage": "deterministic public test seed",
    })
    active.pop("valid_until", None)
    active.pop("revocation_reason", None)
    registry["packets"][0]["chain_head"] = chain_head
    registry["packets"][0]["pubkey_identity"] = IDENTITY
    registry_bytes = (json.dumps(registry, indent=2) + "\n").encode("utf-8")
    (OUTPUT / "anchor-1.json").write_bytes(registry_bytes)
    (OUTPUT / "anchor-2.json").write_bytes(registry_bytes)

    command = [
        sys.executable,
        str(PACKET / "verify_packet.py"),
        str(PACKET),
        "--expected-head", chain_head,
        "--expected-pubkey", public_key,
    ]
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    proc = subprocess.run(
        command,
        cwd=OUTPUT,
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    result = json.loads((PACKET / "verify.json").read_text(encoding="utf-8"))
    metadata = {
        "schema": "aaap-daybreak-ii-postfix-fixture/1",
        "source_commit": "a8b9d15c6b80100eaf52be02abbc1b3322ac3234",
        "purpose": "test-only; not a production identity or publishable packet",
        "chain_head": chain_head,
        "pubkey": public_key,
        "identity_id": IDENTITY,
        "verifier_sha256": sha256(PACKET / "verify_packet.py"),
        "baseline_exit": proc.returncode,
        "baseline_verdict": result.get("verdict"),
        "baseline_engines": result.get("engines"),
    }
    metadata["valid"] = proc.returncode == 0 and result.get("verdict") == "PASS"
    (OUTPUT / "command.txt").write_text(shlex.join(command) + "\n", encoding="utf-8")
    (OUTPUT / "stdout.txt").write_text(proc.stdout, encoding="utf-8")
    (OUTPUT / "stderr.txt").write_text(proc.stderr, encoding="utf-8")
    (OUTPUT / "FIXTURE.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2))
    return 0 if metadata["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
