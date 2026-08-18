#!/usr/bin/env python3
"""Stable-directory proof that an unsealed packet module executes pre-validation."""

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
SOURCE = ROOT / "audit" / "aaap-challenge-a8b9-clean2" / "packet"
CASE = ROOT / "reproducers" / "static-import-side-effect-case"
PACKET = CASE / "packet"
HEAD = "14d14281170d89f6f8b918daf6541f81e7e13549dd4c66f5b085304ff6a61724"
PUBKEY = "e7fb4aad8b0e0246eb6569f49d301ad88a0b54333e3de8bb57e02e118fd3716c"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if CASE.exists():
        raise SystemExit(f"refusing to overwrite preserved reproducer: {CASE}")
    shutil.copytree(SOURCE, PACKET)
    package = PACKET / "cryptography"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from pathlib import Path\n"
        "Path(__file__).resolve().parent.parent.parent.joinpath(\n"
        "    'STATIC_IMPORT_EXECUTED'\n"
        ").write_text('unsealed module executed before inventory\\n', encoding='utf-8')\n",
        encoding="utf-8",
    )

    manifest = json.loads((PACKET / "manifest.json").read_text(encoding="utf-8"))
    verifier_hash = sha256(PACKET / "verify_packet.py")
    signed_hash = manifest["files"]["verify_packet.py"]
    command = [
        sys.executable,
        str(PACKET / "verify_packet.py"),
        str(PACKET),
        "--expected-head", HEAD,
        "--expected-pubkey", PUBKEY,
    ]
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    proc = subprocess.run(
        command,
        cwd=CASE,
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    verdict = json.loads((PACKET / "verify.json").read_text(encoding="utf-8"))
    summary = {
        "schema": "aaap-daybreak-ii-reproducer/1",
        "case": "stable-pre-validation-import-side-effect",
        "source_commit": "a8b9d15c6b80100eaf52be02abbc1b3322ac3234",
        "verifier_sha256": verifier_hash,
        "signed_verifier_sha256": signed_hash,
        "packet_directory_remained_stable": package.exists(),
        "exit_code": proc.returncode,
        "verdict": verdict.get("verdict"),
        "reason": verdict.get("reason"),
        "outside_packet_side_effect": (CASE / "STATIC_IMPORT_EXECUTED").exists(),
    }
    summary["reproduced"] = (
        verifier_hash == signed_hash
        and summary["packet_directory_remained_stable"]
        and summary["exit_code"] == 1
        and summary["verdict"] == "FAIL"
        and summary["outside_packet_side_effect"]
    )
    (CASE / "command.txt").write_text(shlex.join(command) + "\n", encoding="utf-8")
    (CASE / "stdout.txt").write_text(proc.stdout, encoding="utf-8")
    (CASE / "stderr.txt").write_text(proc.stderr, encoding="utf-8")
    (CASE / "result.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if summary["reproduced"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
