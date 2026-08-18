#!/usr/bin/env python3
"""GLM 5.3 adversarial pass (commissioned, same operator) — attack classes
NOT covered by Daybreak I (11) or Daybreak II (33). White-box: targets the
anchors/loader semantics, registry trust model, strict-parser edges, and
type-binding of positional fields. Every case is a minimal reproducer with a
declared expectation; unexpected results are findings.

Honest labeling: same engine family that authored v0.3; v0.4/v0.5 were
authored by a different engine (Codex). Not an independent third party.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent / "aaap-challenge"
ANCHORS = Path(__file__).resolve().parent.parent / "aaap-anchors" / "anchors.json"
PK = REPO / "packet"
V = PK / "verify_packet.py"
NAME = "demo/packet"

CASES = []


def case(cid, expect, describe):
    def reg(fn):
        CASES.append({"id": cid, "expect": expect, "describe": describe, "run": fn})
        return fn
    return reg


def registry():
    return json.loads(ANCHORS.read_text(encoding="utf-8"))


def write_reg(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def run(packet: Path, anchors: list[Path] | None = None) -> tuple[int, str]:
    args = [sys.executable, str(V), str(packet)]
    if anchors:
        for a in anchors:
            args += ["--anchor-registry", str(a)]
        args += ["--packet-name", NAME]
    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    stream = r.stdout.strip().splitlines() + r.stderr.strip().splitlines()
    return r.returncode, (stream[0] if stream else "")


# --- registry distinctness / acquisition ---

@case("G01", "caught", "same registry file twice via symlink alias (vacuous agreement attempt)")
def g01(root, packet):
    a = root / "a.json"
    shutil.copy2(ANCHORS, a)
    b = root / "b.json"
    b.symlink_to(a)
    return run(packet, [a, b])


@case("G02", "documented-pass",
      "two byte-identical COPIES of one registry (agreement is vacuous — "
      "model limit: agreement is necessary, not proof of independent acquisition)")
def g02(root, packet):
    a, b = root / "a.json", root / "b.json"
    shutil.copy2(ANCHORS, a)
    shutil.copy2(ANCHORS, b)
    return run(packet, [a, b])


@case("G03", "caught", "disagreeing registries (one row differs)")
def g03(root, packet):
    a, b = root / "a.json", root / "b.json"
    data = registry()
    write_reg(a, data)
    data["packets"][0]["chain_head"] = "0" * 64
    write_reg(b, data)
    return run(packet, [a, b])


@case("G04", "caught", "symlinked registry file (not a plain regular file)")
def g04(root, packet):
    a = root / "real.json"
    shutil.copy2(ANCHORS, a)
    b = root / "link.json"
    b.symlink_to(a.resolve())
    a.unlink()
    return run(packet, [a, b])  # a now missing; b dangling


# --- registry trust semantics ---

@case("G05", "caught", "packet anchored to a REVOKED identity")
def g05(root, packet):
    data = registry()
    data["packets"][0]["pubkey_identity"] = "aaap-id-ef9eef6cb68a8850"
    a, b = root / "a.json", root / "b.json"
    write_reg(a, data)
    write_reg(b, data)
    return run(packet, [a, b])


@case("G06", "caught",
      "hostile registry re-anchors the REAL packet name to an attacker "
      "identity (trust-the-registry-wholesale attempt; signature must fail)")
def g06(root, packet):
    data = registry()
    attacker = {"identity_id": "aaap-id-attacker", "algorithm": "ed25519",
                "pubkey": "ab" * 32, "operator": "Attacker", "valid_from": "2020-01-01",
                "revoked": False}
    data["identities"].insert(0, attacker)
    data["packets"][0]["pubkey_identity"] = "aaap-id-attacker"
    data["packets"][0]["chain_head"] = registry()["packets"][0]["chain_head"]
    a, b = root / "a.json", root / "b.json"
    write_reg(a, data)
    write_reg(b, data)
    return run(packet, [a, b])


@case("G07", "caught", "duplicate packet names in registry")
def g07(root, packet):
    data = registry()
    data["packets"].append(dict(data["packets"][0]))
    a, b = root / "a.json", root / "b.json"
    write_reg(a, data)
    write_reg(b, data)
    return run(packet, [a, b])


# --- parser edges ---

@case("G08", "caught", "UTF-8 BOM prefixed registry")
def g08(root, packet):
    a = root / "a.json"
    a.write_bytes(b"\xef\xbb\xbf" + ANCHORS.read_bytes())
    b = root / "b.json"
    shutil.copy2(a, b)
    return run(packet, [a, b])


@case("G09", "caught", "chain_index as float 1.0 (type confusion at position 1)")
def g09(root, packet):
    lines = (packet / "chain.jsonl").read_text(encoding="utf-8").splitlines()
    env = json.loads(lines[1])
    env["chain_index"] = 1.0
    from hashlib import sha256
    sealed = dict(env)
    sealed["receipt_hash"] = ""
    env["receipt_hash"] = sha256(json.dumps(sealed, sort_keys=True,
                                            separators=(",", ":")).encode()).hexdigest()
    lines[1] = json.dumps(env, sort_keys=True, separators=(",", ":"))
    (packet / "chain.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return run(packet)


@case("G10", "caught", "unicode homoglyph packet-name in registry (unknown name)")
def g10(root, packet):
    data = registry()
    data["packets"][0]["name"] = "demo/pаcket"  # Cyrillic 'а'
    a, b = root / "a.json", root / "b.json"
    write_reg(a, data)
    write_reg(b, data)
    return run(packet, [a, b])


def main() -> int:
    results = []
    findings = []
    with tempfile.TemporaryDirectory() as tmp:
        for spec in CASES:
            work = Path(tmp) / spec["id"]
            work.mkdir()
            packet = work / "packet"
            shutil.copytree(PK, packet)
            rc, first = spec["run"](work, packet)
            caught = rc != 0
            entry = {"id": spec["id"], "expect": spec["expect"], "exit": rc,
                     "caught": caught, "first_line": first[:140],
                     "describe": spec["describe"]}
            if spec["expect"] == "caught" and not caught:
                entry["verdict"] = "UNEXPECTED PASS — FINDING"
                findings.append(spec["id"])
            elif spec["expect"] == "documented-pass" and caught:
                entry["verdict"] = "UNEXPECTED CATCH"
                findings.append(spec["id"])
            elif spec["expect"] == "documented-pass":
                entry["verdict"] = "documented model limit confirmed"
            else:
                entry["verdict"] = "caught as expected"
            results.append(entry)
    out = {"schema": "aaap-glm-pass/1", "attacker": "GLM 5.3 (commissioned, same operator)",
           "target": "aaap-challenge@9655a65", "results": results,
           "findings": findings}
    print(json.dumps(out, indent=1))
    Path(__file__).resolve().parent.mkdir(exist_ok=True)
    (Path(__file__).resolve().parent / "RESULTS.json").write_text(
        json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
