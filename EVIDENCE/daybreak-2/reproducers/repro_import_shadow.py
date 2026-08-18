#!/usr/bin/env python3
"""Clean-room reproducer for pre-validation Python import shadowing."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path("<SCRUBBED-TMP-PATH>")
SOURCE_PACKET = ROOT / "audit" / "aaap-challenge-a8b9" / "packet"
CASE_ROOT = ROOT / "reproducers" / "import-shadow-case"
PACKET = CASE_ROOT / "packet"
EXPECTED_HEAD = "14d14281170d89f6f8b918daf6541f81e7e13549dd4c66f5b085304ff6a61724"
EXPECTED_PUBKEY = "e7fb4aad8b0e0246eb6569f49d301ad88a0b54333e3de8bb57e02e118fd3716c"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_fake_crypto(packet: Path) -> None:
    package = packet / "cryptography"
    asymmetric = package / "hazmat" / "primitives" / "asymmetric"
    asymmetric.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "exceptions.py").write_text(
        "class InvalidSignature(Exception):\n    pass\n", encoding="utf-8"
    )
    (package / "hazmat" / "__init__.py").write_text("", encoding="utf-8")
    (package / "hazmat" / "primitives" / "__init__.py").write_text("", encoding="utf-8")
    (asymmetric / "__init__.py").write_text("", encoding="utf-8")
    (asymmetric / "ed25519.py").write_text(
        """from pathlib import Path
import shutil

class _ForgedPublicKey:
    def verify(self, signature, message):
        return None

class Ed25519PublicKey:
    @classmethod
    def from_public_bytes(cls, value):
        return _ForgedPublicKey()

_package = Path(__file__).resolve().parents[3]
(_package.parent.parent / "IMPORT_SHADOW_EXECUTED").write_text(
    "unsealed cryptography package executed before packet-root validation\\n",
    encoding="utf-8",
)
shutil.rmtree(_package)
""",
        encoding="utf-8",
    )


def verifier_command() -> list[str]:
    return [
        sys.executable,
        str(PACKET / "verify_packet.py"),
        str(PACKET),
        "--expected-head",
        EXPECTED_HEAD,
        "--expected-pubkey",
        EXPECTED_PUBKEY,
    ]


def run(command: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=CASE_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )


def main() -> int:
    if CASE_ROOT.exists():
        raise SystemExit(f"refusing to overwrite preserved reproducer: {CASE_ROOT}")
    shutil.copytree(SOURCE_PACKET, PACKET)

    manifest_path = PACKET / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    original_model = manifest["key_model"]
    manifest["key_model"] = "ephemeral-integrity"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    verifier_hash = sha256(PACKET / "verify_packet.py")
    expected_verifier_hash = manifest["files"]["verify_packet.py"]
    if verifier_hash != expected_verifier_hash:
        raise SystemExit("source verifier does not match its signed manifest hash")

    write_fake_crypto(PACKET)
    empty_path = CASE_ROOT / "empty-path"
    empty_path.mkdir()
    hostile_env = os.environ.copy()
    hostile_env["PATH"] = str(empty_path)
    hostile_env.pop("PYTHONPATH", None)
    hostile_env.pop("PYTHONHOME", None)

    command = verifier_command()
    attacked = run(command, hostile_env)
    (CASE_ROOT / "attack.stdout.txt").write_text(attacked.stdout, encoding="utf-8")
    (CASE_ROOT / "attack.stderr.txt").write_text(attacked.stderr, encoding="utf-8")
    (CASE_ROOT / "attack.command.txt").write_text(
        f"PATH={shlex.quote(str(empty_path))} {shlex.join(command)}\n", encoding="utf-8"
    )
    attack_result = json.loads((PACKET / "verify.json").read_text(encoding="utf-8"))
    shutil.copy2(PACKET / "verify.json", CASE_ROOT / "attack.verify.json")

    control_env = os.environ.copy()
    control_env.pop("PYTHONPATH", None)
    control_env.pop("PYTHONHOME", None)
    controlled = run(command, control_env)
    (CASE_ROOT / "control.stdout.txt").write_text(controlled.stdout, encoding="utf-8")
    (CASE_ROOT / "control.stderr.txt").write_text(controlled.stderr, encoding="utf-8")
    (CASE_ROOT / "control.command.txt").write_text(shlex.join(command) + "\n", encoding="utf-8")
    control_result = json.loads((PACKET / "verify.json").read_text(encoding="utf-8"))
    shutil.copy2(PACKET / "verify.json", CASE_ROOT / "control.verify.json")

    summary = {
        "schema": "aaap-daybreak-ii-reproducer/1",
        "case": "pre-validation-import-shadow",
        "source_commit": "a8b9d15c6b80100eaf52be02abbc1b3322ac3234",
        "parent_commit": "c06b1638ec2942e0d481a967391e88d6532837dc",
        "verifier_sha256": verifier_hash,
        "signed_verifier_sha256": expected_verifier_hash,
        "mutation": {"manifest.key_model": [original_model, manifest["key_model"]]},
        "attack": {
            "exit_code": attacked.returncode,
            "verdict": attack_result.get("verdict"),
            "engines": attack_result.get("engines"),
            "import_side_effect": (CASE_ROOT / "IMPORT_SHADOW_EXECUTED").exists(),
            "unsealed_package_self_removed": not (PACKET / "cryptography").exists(),
        },
        "real_engine_control": {
            "exit_code": controlled.returncode,
            "verdict": control_result.get("verdict"),
            "reason": control_result.get("reason"),
        },
    }
    summary["reproduced"] = (
        summary["attack"]["exit_code"] == 0
        and summary["attack"]["verdict"] == "PASS"
        and summary["attack"]["engines"] == ["cryptography"]
        and summary["attack"]["import_side_effect"]
        and summary["attack"]["unsealed_package_self_removed"]
        and summary["real_engine_control"]["exit_code"] != 0
        and summary["real_engine_control"]["verdict"] == "FAIL"
    )
    (CASE_ROOT / "result.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))
    return 0 if summary["reproduced"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
