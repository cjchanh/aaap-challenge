#!/usr/bin/env python3
"""Independent hostile-set runner for the pinned public AAAP verifier."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path


ROOT = Path("<SCRUBBED-TMP-PATH>")
SOURCE_PACKET = ROOT / "audit" / "aaap-challenge-a8b9-clean2" / "packet"
SOURCE_ANCHOR_1 = ROOT / "audit" / "aaap-challenge-a8b9-clean2" / "anchors.json"
SOURCE_ANCHOR_2 = ROOT / "audit" / "aaap-anchors" / "anchors.json"
SUITE = ROOT / "reproducers" / "hostile-suite-before-v3"
HEAD = "14d14281170d89f6f8b918daf6541f81e7e13549dd4c66f5b085304ff6a61724"
PUBKEY = "e7fb4aad8b0e0246eb6569f49d301ad88a0b54333e3de8bb57e02e118fd3716c"


results: list[dict] = []


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def make_case(name: str) -> tuple[Path, Path]:
    case = SUITE / name
    packet = case / "packet"
    shutil.copytree(SOURCE_PACKET, packet)
    return case, packet


def explicit_args() -> list[str]:
    return ["--expected-head", HEAD, "--expected-pubkey", PUBKEY]


def read_verdict(packet: Path) -> dict | None:
    path = packet / "verify.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def run_case(
    name: str,
    category: str,
    packet: Path,
    args: list[str],
    expected_exit: int,
    expected_verdict: str | None,
    *,
    env: dict[str, str] | None = None,
    isolated_site: bool = False,
    classification: str = "defense",
    assertions: dict | None = None,
) -> dict:
    command = [sys.executable]
    if isolated_site:
        command.append("-S")
    command.extend([str(packet / "verify_packet.py"), str(packet), *args])
    before = None
    if (packet / "verify.json").exists() and not (packet / "verify.json").is_symlink():
        before = digest(packet / "verify.json")
    proc = subprocess.run(
        command,
        cwd=packet.parent,
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    verdict_data = read_verdict(packet)
    after = None
    if (packet / "verify.json").exists() and not (packet / "verify.json").is_symlink():
        after = digest(packet / "verify.json")
    (packet.parent / "command.txt").write_text(shlex.join(command) + "\n", encoding="utf-8")
    (packet.parent / "stdout.txt").write_text(proc.stdout, encoding="utf-8")
    (packet.parent / "stderr.txt").write_text(proc.stderr, encoding="utf-8")
    observed_verdict = verdict_data.get("verdict") if verdict_data else None
    record = {
        "name": name,
        "category": category,
        "classification": classification,
        "exit_code": proc.returncode,
        "verdict": observed_verdict,
        "reason": verdict_data.get("reason") if verdict_data else None,
        "verify_json_changed": before != after,
        "expected_exit": expected_exit,
        "expected_verdict": expected_verdict,
        "assertions": assertions or {},
    }
    record["matched_expectation"] = (
        proc.returncode == expected_exit and observed_verdict == expected_verdict
    )
    results.append(record)
    return record


def anchor_pair(case: Path, transform=None) -> tuple[Path, Path]:
    first = case / "anchor-1.json"
    second = case / "anchor-2.json"
    one = SOURCE_ANCHOR_1.read_bytes()
    two = SOURCE_ANCHOR_2.read_bytes()
    if transform is not None:
        one = transform(one)
        two = transform(two)
    first.write_bytes(one)
    second.write_bytes(two)
    return first, second


def registry_args(first: Path, second: Path) -> list[str]:
    return [
        "--anchor-registry", str(first),
        "--anchor-registry", str(second),
        "--packet-name", "demo/packet",
    ]


def mutate_registry_bytes(callback) -> callable:
    def transform(payload: bytes) -> bytes:
        value = json.loads(payload.decode("utf-8"))
        callback(value)
        return (json.dumps(value, indent=2) + "\n").encode("utf-8")
    return transform


def fake_openssl(directory: Path, verify_exit: int) -> Path:
    directory.mkdir()
    path = directory / "openssl"
    path.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"pkey\" ]; then exit 0; fi\n"
        f"if [ \"$1\" = \"pkeyutl\" ]; then exit {verify_exit}; fi\n"
        "exit 1\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def main() -> int:
    if SUITE.exists():
        raise SystemExit(f"refusing to overwrite preserved hostile suite: {SUITE}")
    SUITE.mkdir(parents=True)

    case, packet = make_case("baseline-explicit")
    run_case("baseline-explicit", "baseline", packet, explicit_args(), 0, "PASS")

    case, packet = make_case("baseline-registry")
    first, second = anchor_pair(case)
    run_case("baseline-registry", "anchors", packet, registry_args(first, second), 0, "PASS")

    case, packet = make_case("artifact-byte-flip")
    with (packet / "artifacts" / "live" / "ledger.jsonl").open("ab") as handle:
        handle.write(b"X")
    run_case("artifact-byte-flip", "authenticated-bytes", packet, explicit_args(), 1, "FAIL")

    case, packet = make_case("chain-tail-truncation")
    lines = (packet / "chain.jsonl").read_text(encoding="utf-8").splitlines()
    (packet / "chain.jsonl").write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    run_case("chain-tail-truncation", "ordering", packet, explicit_args(), 1, "FAIL")

    case, packet = make_case("chain-path-traversal")
    lines = (packet / "chain.jsonl").read_text(encoding="utf-8").splitlines()
    first_envelope = json.loads(lines[0])
    first_envelope["execution_result"]["artifact"] = "artifacts/../attestation.json"
    unsigned = dict(first_envelope)
    unsigned["receipt_hash"] = ""
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    first_envelope["receipt_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    lines[0] = json.dumps(first_envelope, sort_keys=True, separators=(",", ":"))
    (packet / "chain.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    run_case("chain-path-traversal", "path", packet, explicit_args(), 1, "FAIL")

    case, packet = make_case("manifest-policy-mutation")
    manifest = json.loads((packet / "manifest.json").read_text(encoding="utf-8"))
    manifest["key_model"] = "ephemeral-integrity"
    (packet / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    run_case("manifest-policy-mutation", "manifest", packet, explicit_args(), 1, "FAIL")

    case, packet = make_case("manifest-live-removal")
    manifest = json.loads((packet / "manifest.json").read_text(encoding="utf-8"))
    manifest["live"] = None
    (packet / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    run_case("manifest-live-removal", "manifest", packet, explicit_args(), 1, "FAIL")

    case, packet = make_case("manifest-duplicate-key")
    text = (packet / "manifest.json").read_text(encoding="utf-8")
    text = text.replace('{\n  "schema":', '{\n  "schema": "aaap-manifest/2",\n  "schema":', 1)
    (packet / "manifest.json").write_text(text, encoding="utf-8")
    run_case("manifest-duplicate-key", "parser", packet, explicit_args(), 1, "FAIL")

    case, packet = make_case("manifest-nan")
    text = (packet / "manifest.json").read_text(encoding="utf-8")
    text = text.replace('"key_model": "persistent-identity"', '"key_model": NaN', 1)
    (packet / "manifest.json").write_text(text, encoding="utf-8")
    run_case("manifest-nan", "parser", packet, explicit_args(), 1, "FAIL")

    case, packet = make_case("manifest-invalid-utf8")
    (packet / "manifest.json").write_bytes(b"{\"schema\":\"aaap-manifest/2\",\"x\":\xff}")
    run_case("manifest-invalid-utf8", "encoding", packet, explicit_args(), 1, "FAIL")

    case, packet = make_case("derived-file-symlink")
    target = packet / "PACKET.md"
    target.unlink()
    target.symlink_to("ENVELOPE.md")
    run_case("derived-file-symlink", "filesystem", packet, explicit_args(), 1, "FAIL")

    case, packet = make_case("root-extra-file")
    (packet / "unsealed.txt").write_text("unsealed\n", encoding="utf-8")
    run_case("root-extra-file", "filesystem", packet, explicit_args(), 1, "FAIL")

    case, packet = make_case("artifact-dangling-symlink")
    (packet / "artifacts" / "dangling").symlink_to("missing")
    run_case("artifact-dangling-symlink", "filesystem", packet, explicit_args(), 1, "FAIL")

    case, packet = make_case("artifact-hardlink")
    source = packet / "artifacts" / "live" / "ledger.jsonl"
    os.link(source, packet / "artifacts" / "live" / "ledger-hardlink.jsonl")
    run_case("artifact-hardlink", "filesystem", packet, explicit_args(), 1, "FAIL")

    case, packet = make_case("artifact-fifo")
    os.mkfifo(packet / "artifacts" / "hostile-fifo")
    run_case("artifact-fifo", "filesystem", packet, explicit_args(), 1, "FAIL")

    case, packet = make_case("verify-symlink")
    sentinel = case / "sentinel.txt"
    sentinel.write_text("UNCHANGED\n", encoding="utf-8")
    (packet / "verify.json").unlink()
    (packet / "verify.json").symlink_to(sentinel)
    record = run_case("verify-symlink", "output", packet, explicit_args(), 1, None)
    record["assertions"]["sentinel_unchanged"] = sentinel.read_text(encoding="utf-8") == "UNCHANGED\n"

    case, packet = make_case("verify-hardlink")
    sentinel = case / "sentinel.txt"
    sentinel.write_text("UNCHANGED\n", encoding="utf-8")
    (packet / "verify.json").unlink()
    os.link(sentinel, packet / "verify.json")
    record = run_case("verify-hardlink", "output", packet, explicit_args(), 1, None)
    record["assertions"]["sentinel_unchanged"] = sentinel.read_text(encoding="utf-8") == "UNCHANGED\n"
    record["assertions"]["stale_pass_is_preexisting"] = True

    case, packet = make_case("archive-traversal-payload")
    archive = packet / "payload.tar"
    with tarfile.open(archive, "w") as handle:
        info = tarfile.TarInfo("../ARCHIVE_ESCAPE")
        payload = b"must not extract\n"
        info.size = len(payload)
        handle.addfile(info, io.BytesIO(payload))
    record = run_case("archive-traversal-payload", "archive", packet, explicit_args(), 1, "FAIL")
    record["assertions"]["no_extraction"] = not (case / "ARCHIVE_ESCAPE").exists()

    case, packet = make_case("anchors-disagree")
    first, second = anchor_pair(case)
    second.write_bytes(second.read_bytes() + b"\n")
    run_case("anchors-disagree", "anchors", packet, registry_args(first, second), 1, "PASS")

    case, packet = make_case("anchors-same-file")
    first, _ = anchor_pair(case)
    run_case("anchors-same-file", "anchors", packet, registry_args(first, first), 1, "PASS")

    case, packet = make_case("anchors-hardlink")
    first = case / "anchor-1.json"
    second = case / "anchor-2.json"
    shutil.copy2(SOURCE_ANCHOR_1, first)
    os.link(first, second)
    run_case("anchors-hardlink", "anchors", packet, registry_args(first, second), 1, "PASS")

    case, packet = make_case("anchor-revoked")
    def revoke(value):
        value["identities"][0]["revoked"] = True
        value["identities"][0]["revocation_reason"] = "hostile test"
    first, second = anchor_pair(case, mutate_registry_bytes(revoke))
    run_case("anchor-revoked", "revocation", packet, registry_args(first, second), 1, "PASS")

    case, packet = make_case("anchor-validity-window")
    def predate(value):
        value["packets"][0]["sealed_at"] = "2026-08-16"
    first, second = anchor_pair(case, mutate_registry_bytes(predate))
    run_case("anchor-validity-window", "revocation", packet, registry_args(first, second), 1, "PASS")

    case, packet = make_case("anchor-duplicate-key")
    def duplicate_schema(payload: bytes) -> bytes:
        text = payload.decode("utf-8")
        return text.replace('{\n  "schema":', '{\n  "schema": "aaap-anchors/1",\n  "schema":', 1).encode("utf-8")
    first, second = anchor_pair(case, duplicate_schema)
    run_case("anchor-duplicate-key", "parser", packet, registry_args(first, second), 1, "PASS")

    case, packet = make_case("anchor-overflow-number")
    def overflow(payload: bytes) -> bytes:
        value = json.loads(payload.decode("utf-8"))
        value["identities"][0]["custody_stage"] = "OVERFLOW_TOKEN"
        text = json.dumps(value, indent=2) + "\n"
        return text.replace('"OVERFLOW_TOKEN"', "1e9999", 1).encode("utf-8")
    first, second = anchor_pair(case, overflow)
    run_case(
        "anchor-overflow-number", "parser", packet, registry_args(first, second), 0, "PASS",
        classification="source-violation",
        assertions={"runtime_value_is_nonfinite": True},
    )

    case, packet = make_case("anchor-unpaired-surrogate")
    def surrogate(payload: bytes) -> bytes:
        value = json.loads(payload.decode("utf-8"))
        value["identities"][0]["operator"] = "\ud800"
        return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    first, second = anchor_pair(case, surrogate)
    run_case(
        "anchor-unpaired-surrogate", "encoding", packet, registry_args(first, second), 0, "PASS",
        classification="parser-hardening-gap",
    )

    case, packet = make_case("crypto-engine-disagreement")
    wrapper = fake_openssl(case / "bin", 1)
    env = os.environ.copy()
    env["PATH"] = f"{wrapper.parent}:{env.get('PATH', '')}"
    run_case("crypto-engine-disagreement", "crypto", packet, explicit_args(), 1, "FAIL", env=env)

    case, packet = make_case("crypto-no-engine")
    empty = case / "empty-path"
    empty.mkdir()
    env = os.environ.copy()
    env["PATH"] = str(empty)
    run_case(
        "crypto-no-engine", "crypto", packet, explicit_args(), 1, "FAIL",
        env=env, isolated_site=True,
    )

    case, packet = make_case("hostile-openssl-only")
    attestation = json.loads((packet / "attestation.json").read_text(encoding="utf-8"))
    attestation["signature"] = "00" * 64
    (packet / "attestation.json").write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
    wrapper = fake_openssl(case / "bin", 0)
    env = os.environ.copy()
    env["PATH"] = str(wrapper.parent)
    run_case(
        "hostile-openssl-only", "crypto", packet, explicit_args(), 0, "PASS",
        env=env, isolated_site=True, classification="documented-host-boundary",
    )

    case, packet = make_case("oversized-json-whitespace")
    path = packet / "manifest.json"
    path.write_bytes((b" " * (8 * 1024 * 1024)) + path.read_bytes())
    run_case(
        "oversized-json-whitespace", "resource", packet, explicit_args(), 0, "PASS",
        classification="documented-availability-boundary",
    )

    case, packet = make_case("malformed-deep-json")
    (packet / "chain.jsonl").write_text("[" * 3000 + "0" + "]" * 3000 + "\n", encoding="utf-8")
    record = run_case(
        "malformed-deep-json", "resource", packet, explicit_args(), 1, "FAIL",
        classification="defense",
    )
    record["assertions"]["traceback"] = "Traceback" in (case / "stderr.txt").read_text(encoding="utf-8")
    record["assertions"]["stale_pass_remained"] = record["verdict"] == "PASS" and not record["verify_json_changed"]

    import_shadow = json.loads(
        (ROOT / "reproducers" / "import-shadow-case" / "result.json").read_text(encoding="utf-8")
    )
    results.append({
        "name": "pre-validation-import-shadow",
        "category": "verifier-substitution",
        "classification": "source-violation",
        "exit_code": import_shadow["attack"]["exit_code"],
        "verdict": import_shadow["attack"]["verdict"],
        "reason": "unsealed self-removing cryptography package forged anchored PASS",
        "expected_exit": 0,
        "expected_verdict": "PASS",
        "matched_expectation": import_shadow["reproduced"],
        "assertions": import_shadow["attack"],
    })

    unexpected = [item["name"] for item in results if not item["matched_expectation"]]
    summary = {
        "schema": "aaap-daybreak-ii-hostile-suite/1",
        "target_commit": "a8b9d15c6b80100eaf52be02abbc1b3322ac3234",
        "parent_commit": "c06b1638ec2942e0d481a967391e88d6532837dc",
        "anchors_commit": "9deae6c211843544d8d4d5143f0ee266e36caab2",
        "cases": results,
        "case_count": len(results),
        "unexpected": unexpected,
        "source_violations": [
            item["name"] for item in results if item["classification"] == "source-violation"
        ],
    }
    (SUITE / "RESULTS.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if not unexpected else 1


if __name__ == "__main__":
    raise SystemExit(main())
