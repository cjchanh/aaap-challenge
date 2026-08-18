#!/usr/bin/env python3
"""Minimal proof that exponent overflow survives the claimed strict JSON parser."""

from __future__ import annotations

import json
import math
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path("<SCRUBBED-TMP-PATH>")
SOURCE_REPO = ROOT / "audit" / "aaap-challenge-a8b9-clean2"
SOURCE_MIRROR = ROOT / "audit" / "aaap-anchors" / "anchors.json"
CASE = ROOT / "reproducers" / "overflow-anchor-case"
PACKET = CASE / "packet"


def overflow_registry(payload: bytes) -> bytes:
    value = json.loads(payload.decode("utf-8"))
    value["identities"][0]["custody_stage"] = "OVERFLOW_TOKEN"
    text = json.dumps(value, indent=2) + "\n"
    return text.replace('"OVERFLOW_TOKEN"', "1e9999", 1).encode("utf-8")


def main() -> int:
    if CASE.exists():
        raise SystemExit(f"refusing to overwrite preserved reproducer: {CASE}")
    shutil.copytree(SOURCE_REPO / "packet", PACKET)
    CASE.mkdir(exist_ok=True)
    first = CASE / "anchor-1.json"
    second = CASE / "anchor-2.json"
    first.write_bytes(overflow_registry((SOURCE_REPO / "anchors.json").read_bytes()))
    second.write_bytes(overflow_registry(SOURCE_MIRROR.read_bytes()))
    parsed = json.loads(first.read_text(encoding="utf-8"))
    runtime_value = parsed["identities"][0]["custody_stage"]

    command = [
        sys.executable,
        str(PACKET / "verify_packet.py"),
        str(PACKET),
        "--anchor-registry", str(first),
        "--anchor-registry", str(second),
        "--packet-name", "demo/packet",
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
        "case": "anchor-exponent-overflow",
        "source_commit": "a8b9d15c6b80100eaf52be02abbc1b3322ac3234",
        "anchors_commit": "9deae6c211843544d8d4d5143f0ee266e36caab2",
        "input_token": "1e9999",
        "runtime_value_nonfinite": isinstance(runtime_value, float) and math.isinf(runtime_value),
        "exit_code": proc.returncode,
        "verdict": verdict.get("verdict"),
        "engines": verdict.get("engines"),
    }
    summary["reproduced"] = (
        summary["runtime_value_nonfinite"]
        and summary["exit_code"] == 0
        and summary["verdict"] == "PASS"
    )
    (CASE / "command.txt").write_text(shlex.join(command) + "\n", encoding="utf-8")
    (CASE / "stdout.txt").write_text(proc.stdout, encoding="utf-8")
    (CASE / "stderr.txt").write_text(proc.stderr, encoding="utf-8")
    (CASE / "result.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if summary["reproduced"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
