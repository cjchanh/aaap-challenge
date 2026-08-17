#!/usr/bin/env python3
"""Reproduce confirmed AAAP v0.3 breaks without modifying the source clone."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

VULNERABLE_COMMIT = "e0fca96651b30c76d0a29bf867cdd14cdc38db00"
EXPECTED_HEAD = "14d14281170d89f6f8b918daf6541f81e7e13549dd4c66f5b085304ff6a61724"
EXPECTED_PUBKEY = "e7fb4aad8b0e0246eb6569f49d301ad88a0b54333e3de8bb57e02e118fd3716c"


def git(path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *args], text=True, capture_output=True, check=True
    )
    return result.stdout.strip()


def clone_case(source: Path, out: Path, name: str) -> Path:
    case = out / name
    subprocess.run(
        ["git", "clone", "--quiet", "--no-hardlinks", str(source), str(case)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(case), "checkout", "--quiet", "--detach", VULNERABLE_COMMIT],
        check=True,
    )
    return case


def rewrite_json(path: Path, change) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    change(value)
    path.write_text(json.dumps(value, indent=2, allow_nan=True) + "\n", encoding="utf-8")


def verify(case: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(case / "packet/verify_packet.py"),
            str(case / "packet"),
            "--expected-head",
            EXPECTED_HEAD,
            "--expected-pubkey",
            EXPECTED_PUBKEY,
        ],
        text=True,
        capture_output=True,
        timeout=60,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--challenge", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    source = Path(args.challenge).expanduser().resolve()
    out = Path(args.out).expanduser().resolve()
    if out.exists():
        raise SystemExit(f"refusing existing output directory: {out}")
    if git(source, "rev-parse", "HEAD") != VULNERABLE_COMMIT:
        raise SystemExit("challenge clone is not pinned to the vulnerable commit")
    if git(source, "status", "--porcelain"):
        raise SystemExit("challenge source clone is dirty; refusing to mutate evidence")
    out.mkdir(parents=True)

    mutations = {
        "manifest_live_removed": lambda c: rewrite_json(
            c / "packet/manifest.json", lambda m: m.pop("live")
        ),
        "manifest_key_model_tampered": lambda c: rewrite_json(
            c / "packet/manifest.json",
            lambda m: m.__setitem__("key_model", "ephemeral-attacker-claim"),
        ),
        "manifest_schema_tampered": lambda c: rewrite_json(
            c / "packet/manifest.json",
            lambda m: m.__setitem__("schema", "attacker-schema/v999"),
        ),
        "manifest_invalid_nan": lambda c: rewrite_json(
            c / "packet/manifest.json",
            lambda m: m.__setitem__("attacker_claim", float("nan")),
        ),
        "attestation_schema_tampered": lambda c: rewrite_json(
            c / "packet/attestation.json",
            lambda a: a.__setitem__("schema", "attacker-schema/v999"),
        ),
        "attestation_unsigned_claim": lambda c: rewrite_json(
            c / "packet/attestation.json",
            lambda a: a.__setitem__("custody", "hardware-hsm"),
        ),
    }

    records = []
    for name, mutate in mutations.items():
        case = clone_case(source, out, name)
        mutate(case)
        result = verify(case)
        records.append({
            "case": name,
            "exit": result.returncode,
            "unexpected_pass": result.returncode == 0,
            "first_line": (result.stdout or result.stderr).splitlines()[0],
        })

    case = clone_case(source, out, "chain_duplicate_key_confusion")
    chain = case / "packet/chain.jsonl"
    lines = chain.read_text(encoding="utf-8").splitlines()
    lines[0] = '{"policy_decision":"FORGED_FIRST_WINS",' + lines[0][1:]
    chain.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = verify(case)
    records.append({"case": "chain_duplicate_key_confusion", "exit": result.returncode,
                    "unexpected_pass": result.returncode == 0,
                    "first_line": (result.stdout or result.stderr).splitlines()[0]})

    case = clone_case(source, out, "verify_output_symlink")
    report = case / "packet/report.md"
    before = hashlib.sha256(report.read_bytes()).hexdigest()
    output = case / "packet/verify.json"
    output.unlink()
    output.symlink_to("report.md")
    result = verify(case)
    after = hashlib.sha256(report.read_bytes()).hexdigest()
    records.append({"case": "verify_output_symlink", "exit": result.returncode,
                    "unexpected_pass": result.returncode == 0,
                    "sealed_report_overwritten": before != after,
                    "report_before": before, "report_after": after})

    case = clone_case(source, out, "dangling_artifact_symlink")
    (case / "packet/artifacts/UNREFERENCED").symlink_to("missing-target")
    result = verify(case)
    records.append({"case": "dangling_artifact_symlink", "exit": result.returncode,
                    "unexpected_pass": result.returncode == 0,
                    "first_line": (result.stdout or result.stderr).splitlines()[0]})

    case = clone_case(source, out, "unsealed_root_claim")
    (case / "packet/AUDIT_APPROVAL.md").write_text(
        "Approved by an attacker\n", encoding="utf-8"
    )
    result = verify(case)
    records.append({"case": "unsealed_root_claim", "exit": result.returncode,
                    "unexpected_pass": result.returncode == 0,
                    "first_line": (result.stdout or result.stderr).splitlines()[0]})

    case = clone_case(source, out, "derived_file_symlink_escape")
    packet_doc = case / "packet/PACKET.md"
    outside = case / "outside-PACKET.md"
    packet_doc.replace(outside)
    packet_doc.symlink_to("../outside-PACKET.md")
    result = verify(case)
    records.append({"case": "derived_file_symlink_escape", "exit": result.returncode,
                    "unexpected_pass": result.returncode == 0,
                    "first_line": (result.stdout or result.stderr).splitlines()[0]})

    (out / "RESULTS.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(records, indent=2))
    return 0 if all(record["unexpected_pass"] for record in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
