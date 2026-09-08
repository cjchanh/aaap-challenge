from __future__ import annotations

import importlib.util
import io
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VERIFIER_PATH = REPO / "packet" / "verify_packet.py"
HEAD = "14d14281170d89f6f8b918daf6541f81e7e13549dd4c66f5b085304ff6a61724"
PUBKEY = "e7fb4aad8b0e0246eb6569f49d301ad88a0b54333e3de8bb57e02e118fd3716c"
PACKET_ONLY_PASS = (
    "PASS (packet-only: not anchored — supply --expected-head and "
    "--expected-pubkey from an out-of-band source to verify authorship and freshness)"
)


def load_verifier_module():
    spec = importlib.util.spec_from_file_location(
        "aaap_verify_packet_anchor_test", VERIFIER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load verifier module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pass_result() -> dict:
    return {
        "schema": "aaap-verify/1",
        "verdict": "PASS",
        "reason": "ok",
        "engines": ["cryptography"],
        "checks": [],
    }


def _first_bash_block(markdown: str, after: str) -> str:
    start = markdown.index(after)
    rest = markdown[start:]
    marker = "```bash"
    i = rest.index(marker)
    body = rest[i + len(marker) :]
    return body[: body.index("```")].strip()


class VerifierAnchorPostureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = load_verifier_module()

    def _run_main(self, argv: list[str]) -> tuple[int, str, str]:
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            code = self.verifier.main(argv)
        return code, stdout_buf.getvalue(), stderr_buf.getvalue()

    def test_packet_only_pass_line(self) -> None:
        original = self.verifier.verify_packet
        self.verifier.verify_packet = lambda *args, **kwargs: _pass_result()
        try:
            with tempfile.TemporaryDirectory() as raw:
                code, stdout, stderr = self._run_main(
                    ["verify_packet.py", raw]
                )
            self.assertEqual(code, 0)
            self.assertIn(PACKET_ONLY_PASS, stdout.splitlines())
            self.assertEqual(stderr, "")
        finally:
            self.verifier.verify_packet = original

    def test_require_anchors_exits_3(self) -> None:
        code, stdout, stderr = self._run_main(
            ["verify_packet.py", "unused-packet", "--require-anchors"]
        )
        self.assertEqual(code, 3)
        self.assertIn("FAIL: anchors required", stderr.splitlines())
        self.assertNotIn("FAIL: anchors required", stdout.splitlines())

    def test_anchored_pass_line(self) -> None:
        original = self.verifier.verify_packet
        self.verifier.verify_packet = lambda *args, **kwargs: _pass_result()
        try:
            with tempfile.TemporaryDirectory() as raw:
                code, stdout, stderr = self._run_main(
                    [
                        "verify_packet.py",
                        raw,
                        "--expected-head",
                        HEAD,
                        "--expected-pubkey",
                        PUBKEY,
                    ]
                )
            self.assertEqual(code, 0)
            self.assertIn("PASS (anchored)", stdout.splitlines())
            self.assertEqual(stderr, "")
        finally:
            self.verifier.verify_packet = original

    def test_readme_first_verify_command_uses_published_expected_anchors(self) -> None:
        text = (REPO / "README.md").read_text(encoding="utf-8")
        block = _first_bash_block(text, "## Verify")
        self.assertIn(f"--expected-head {HEAD}", block)
        self.assertIn(f"--expected-pubkey {PUBKEY}", block)
        self.assertNotIn("/path/to/independently-acquired/anchors.json", block)
        self.assertNotIn("--anchor-registry anchors.json", block)

    def test_docs_mention_require_anchors(self) -> None:
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        challenge = (REPO / "CHALLENGE.md").read_text(encoding="utf-8")
        self.assertIn("--require-anchors", readme)
        self.assertIn("--require-anchors", challenge)

    def test_readme_documents_two_registry_requirement(self) -> None:
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        self.assertRegex(
            readme,
            re.compile(r"exactly two independently acquired", re.IGNORECASE),
        )
        self.assertIn("a single `anchors.json` argument is rejected", readme)

    def test_packet_root_contains_no_unsealed_test_modules(self) -> None:
        extras = sorted(p.name for p in (REPO / "packet").glob("test_*.py"))
        self.assertEqual(extras, [])

    def test_public_terms_state_commissioned_breaks_and_outside_success(self) -> None:
        for name in ("README.md", "CHALLENGE.md"):
            text = re.sub(r"\s+", " ", (REPO / name).read_text(encoding="utf-8").lower())
            self.assertIn("commissioned", text)
            self.assertIn("cjchanh", text)
            self.assertIn("not commissioned or paid", text)


if __name__ == "__main__":
    unittest.main()
