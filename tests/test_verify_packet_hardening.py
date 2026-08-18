from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SOURCE_PACKET = REPO / "packet"
HEAD = "14d14281170d89f6f8b918daf6541f81e7e13549dd4c66f5b085304ff6a61724"
PUBKEY = "e7fb4aad8b0e0246eb6569f49d301ad88a0b54333e3de8bb57e02e118fd3716c"


def load_verifier_module():
    spec = importlib.util.spec_from_file_location(
        "aaap_verify_packet_hardening_test", SOURCE_PACKET / "verify_packet.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load verifier module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_overflow_anchor(source: Path, target: Path) -> None:
    value = json.loads(source.read_text(encoding="utf-8"))
    value["identities"][0]["custody_stage"] = "OVERFLOW_TOKEN"
    text = json.dumps(value, indent=2) + "\n"
    target.write_text(
        text.replace('"OVERFLOW_TOKEN"', "1e9999", 1), encoding="utf-8"
    )


class VerifierHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.dont_write_bytecode = True
        cls.verifier = load_verifier_module()

    def run_verifier(
        self,
        packet: Path,
        extra_args: list[str],
        *,
        path: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.pop("PYTHONHOME", None)
        env.pop("PYTHONPATH", None)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        if path is not None:
            env["PATH"] = path
        command = [
            sys.executable,
            str(packet / "verify_packet.py"),
            str(packet),
            *extra_args,
        ]
        return subprocess.run(
            command,
            cwd=packet.parent,
            env=env,
            text=True,
            capture_output=True,
            timeout=120,
            check=False,
        )

    def test_exponent_overflow_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-finite JSON number: 1e9999"):
            self.verifier.strict_json_loads('{"value":1e9999}')
        with self.assertRaisesRegex(ValueError, "non-finite JSON number: -1e9999"):
            self.verifier.strict_json_loads('{"value":-1e9999}')

    def test_unsealed_crypto_package_cannot_execute_before_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            case = Path(raw)
            packet = case / "packet"
            shutil.copytree(SOURCE_PACKET, packet)
            package = packet / "cryptography"
            package.mkdir()
            marker = case / "IMPORT_EXECUTED"
            (package / "__init__.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
                encoding="utf-8",
            )
            proc = self.run_verifier(
                packet,
                ["--expected-head", HEAD, "--expected-pubkey", PUBKEY],
            )
            result = json.loads((packet / "verify.json").read_text(encoding="utf-8"))
            self.assertEqual(proc.returncode, 1)
            self.assertFalse(marker.exists())
            self.assertTrue(package.exists())
            self.assertEqual(result["verdict"], "FAIL")
            self.assertIn("unsealed entry: cryptography", result["reason"])

    def test_self_removing_crypto_forgery_is_not_imported(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            case = Path(raw)
            packet = case / "packet"
            shutil.copytree(SOURCE_PACKET, packet)
            package = packet / "cryptography"
            asymmetric = package / "hazmat" / "primitives" / "asymmetric"
            asymmetric.mkdir(parents=True)
            marker = case / "FORGERY_EXECUTED"
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "exceptions.py").write_text(
                "class InvalidSignature(Exception):\n    pass\n", encoding="utf-8"
            )
            (package / "hazmat" / "__init__.py").write_text("", encoding="utf-8")
            (package / "hazmat" / "primitives" / "__init__.py").write_text(
                "", encoding="utf-8"
            )
            (asymmetric / "__init__.py").write_text("", encoding="utf-8")
            (asymmetric / "ed25519.py").write_text(
                "from pathlib import Path\n"
                "import shutil\n"
                "class _Key:\n"
                "    def verify(self, signature, message): return None\n"
                "class Ed25519PublicKey:\n"
                "    @classmethod\n"
                "    def from_public_bytes(cls, value): return _Key()\n"
                "_package = Path(__file__).resolve().parents[3]\n"
                f"Path({str(marker)!r}).write_text('executed')\n"
                "shutil.rmtree(_package)\n",
                encoding="utf-8",
            )
            manifest_path = packet / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["key_model"] = "ephemeral-integrity"
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            empty_path = case / "empty-path"
            empty_path.mkdir()
            proc = self.run_verifier(
                packet,
                ["--expected-head", HEAD, "--expected-pubkey", PUBKEY],
                path=str(empty_path),
            )
            result = json.loads((packet / "verify.json").read_text(encoding="utf-8"))
            self.assertEqual(proc.returncode, 1)
            self.assertFalse(marker.exists())
            self.assertTrue(package.exists())
            self.assertEqual(result["verdict"], "FAIL")
            self.assertIn("unsealed entry: cryptography", result["reason"])

    def test_registry_mode_rejects_exponent_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            case = Path(raw)
            packet = case / "packet"
            shutil.copytree(SOURCE_PACKET, packet)
            first = case / "anchor-1.json"
            second = case / "anchor-2.json"
            write_overflow_anchor(REPO / "anchors.json", first)
            write_overflow_anchor(REPO / "anchors.json", second)
            proc = self.run_verifier(
                packet,
                [
                    "--anchor-registry", str(first),
                    "--anchor-registry", str(second),
                    "--packet-name", "demo/packet",
                ],
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("non-finite JSON number: 1e9999", proc.stderr)

    def test_clean_production_packet_passes_both_anchor_modes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            case = Path(raw)
            packet = case / "packet"
            shutil.copytree(SOURCE_PACKET, packet)

            exact = self.run_verifier(
                packet,
                ["--expected-head", HEAD, "--expected-pubkey", PUBKEY],
            )
            exact_result = json.loads(
                (packet / "verify.json").read_text(encoding="utf-8")
            )
            self.assertEqual(exact.returncode, 0, exact.stdout + exact.stderr)
            self.assertEqual(exact_result["verdict"], "PASS")
            self.assertTrue(exact_result["engines"])

            first = case / "anchor-1.json"
            second = case / "anchor-2.json"
            shutil.copyfile(REPO / "anchors.json", first)
            shutil.copyfile(REPO / "anchors.json", second)
            registry = self.run_verifier(
                packet,
                [
                    "--anchor-registry",
                    str(first),
                    "--anchor-registry",
                    str(second),
                    "--packet-name",
                    "demo/packet",
                ],
            )
            registry_result = json.loads(
                (packet / "verify.json").read_text(encoding="utf-8")
            )
            self.assertEqual(registry.returncode, 0, registry.stdout + registry.stderr)
            self.assertEqual(registry_result["verdict"], "PASS")
            self.assertTrue(registry_result["engines"])


if __name__ == "__main__":
    unittest.main()
