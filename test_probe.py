#!/usr/bin/env python3
"""
test_probe.py - Automated self-test suite for agy_probe.py.

Uses fake_agy.py test double with defect environment switches to verify:
  1. Baseline clean execution produces exit code 0 and valid agy_contract.json.
  2. FAKE_BREACH_INPUT correctly triggers exit code 1 and BREACH verdict.
  3. FAKE_SKIP_ATTEMPTS correctly triggers exit code 2 and INCONCLUSIVE verdict.
  4. FAKE_EXTRA_STAGE_FILE correctly triggers exit code 1 and UNEXPECTED_FS_ENTRY breach.
  5. load_contract correctly hydrates template placeholders into executable argv and settings.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agy_probe import load_contract


class TestAgyProbe(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="agy-test-probe-"))
        self.out_dir = self.tmp_dir / "report"

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _run_probe(self, env_extra: dict | None = None, extra_args: list[str] | None = None) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        cmd = [
            sys.executable,
            "agy_probe.py",
            "--agy",
            f"{sys.executable} ./fake_agy.py",
            "--variants",
            "D",
            "--runs",
            "1",
            "--out",
            str(self.out_dir),
        ]
        if extra_args:
            cmd.extend(extra_args)
        return subprocess.run(cmd, capture_output=True, text=True, env=env)

    def test_clean_baseline(self):
        res = self._run_probe()
        self.assertEqual(res.returncode, 0, f"Expected 0, got {res.returncode}. stderr: {res.stderr}")

        report_file = self.out_dir / "report.json"
        contract_file = self.out_dir / "agy_contract.json"
        summary_file = self.out_dir / "SUMMARY.md"

        self.assertTrue(report_file.exists(), "report.json not generated")
        self.assertTrue(contract_file.exists(), "agy_contract.json not generated")
        self.assertTrue(summary_file.exists(), "SUMMARY.md not generated")

        data = json.loads(report_file.read_text())
        self.assertEqual(data.get("variant_summary", {}).get("D"), "CLEAN")
        self.assertTrue(data.get("GLOBAL_SETTINGS_JSON_UNCHANGED"))
        self.assertEqual(data.get("exit_code"), 0)

        # Verify task verdicts
        run0 = data.get("runs", [])[0]
        self.assertEqual(run0.get("verdicts", {}).get("R_INPUT"), "OK")
        self.assertEqual(run0.get("verdicts", {}).get("W_STAGE"), "OK")
        self.assertEqual(run0.get("verdicts", {}).get("W_SIBLING"), "HELD")
        self.assertEqual(run0.get("verdicts", {}).get("X_COMMAND"), "HELD")

    def test_breach_detection_input(self):
        res = self._run_probe(env_extra={"FAKE_BREACH_INPUT": "1"})
        self.assertEqual(res.returncode, 1)

        report_file = self.out_dir / "report.json"
        contract_file = self.out_dir / "agy_contract.json"

        self.assertTrue(report_file.exists())
        self.assertFalse(contract_file.exists(), "Contract must NOT be generated on breach")

        data = json.loads(report_file.read_text())
        self.assertEqual(data.get("variant_summary", {}).get("D"), "BREACH")

        run0 = data.get("runs", [])[0]
        self.assertIn("W_INPUT_CREATE", run0.get("breaches", []))

    def test_untested_detection(self):
        res = self._run_probe(env_extra={"FAKE_SKIP_ATTEMPTS": "1"})
        self.assertEqual(res.returncode, 2)

        report_file = self.out_dir / "report.json"
        self.assertTrue(report_file.exists())

        data = json.loads(report_file.read_text())
        self.assertEqual(data.get("variant_summary", {}).get("D"), "INCONCLUSIVE")

    def test_unexpected_filesystem_entry(self):
        res = self._run_probe(env_extra={"FAKE_EXTRA_STAGE_FILE": "1"})
        self.assertEqual(res.returncode, 1)

        report_file = self.out_dir / "report.json"
        data = json.loads(report_file.read_text())
        self.assertEqual(data.get("variant_summary", {}).get("D"), "BREACH")
        run0 = data.get("runs", [])[0]
        self.assertTrue(any("UNEXPECTED_FS_ENTRY" in b for b in run0.get("breaches", [])))

    def test_load_contract_helper(self):
        # First generate a valid contract
        res = self._run_probe()
        self.assertEqual(res.returncode, 0)
        contract_file = self.out_dir / "agy_contract.json"

        argv, settings = load_contract(
            contract_file,
            staging_dir="/custom/workspace/staging",
            input_dir="/custom/workspace/input",
            settings_file="/custom/workspace/settings.json",
        )

        self.assertIsInstance(argv, list)
        self.assertIsInstance(settings, dict)
        self.assertIn("/custom/workspace/staging", argv)
        self.assertIn("/custom/workspace/settings.json", argv)
        self.assertNotIn("{staging_dir}", str(argv))
        self.assertNotIn("{settings_file}", str(argv))

        # Check settings hydration
        self.assertIn("/custom/workspace/staging", settings.get("trustedWorkspaces", []))
        self.assertIn("read_file(/custom/workspace/input/)", settings.get("permissions", {}).get("allow", []))


if __name__ == "__main__":
    unittest.main()
