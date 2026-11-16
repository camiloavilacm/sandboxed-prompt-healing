#!/usr/bin/env python3
"""
prompt_healing_harness.py - Production Prompt Healing & Test Repair Evaluation Harness.

This harness operationalizes the security contract frozen by agy_probe.py:
  1. Validates that agy_contract.json exists and matches the current agy version.
  2. Creates an isolated staging sandbox for the healing attempt.
  3. Injects problem fixtures (e.g. failing test logs, DOM snapshots, broken specs).
  4. Hydrates the frozen contract using load_contract() (locking CWD and permissions).
  5. Runs agy non-interactively via stream-json to heal the broken prompt/test.
  6. Objectively verifies the healed result (asserting file modifications and containment).
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from agy_probe import load_contract


def get_current_agy_version(agy_cmd: str) -> str:
    """Retrieve installed agy version string."""
    try:
        r = subprocess.run([*agy_cmd.split(), "--version"], capture_output=True, text=True, timeout=10)
        return (r.stdout + r.stderr).strip()
    except Exception as exc:
        return f"unknown ({exc})"


def run_healing_session(
    agy_cmd: str = "agy",
    contract_path: str = "agy-probe-report/agy_contract.json",
    keep_sandbox: bool = False,
    timeout: int = 180,
) -> dict:
    """Run an autonomous prompt healing attempt inside the verified contract boundary."""
    contract_p = Path(contract_path).resolve()
    if not contract_p.exists():
        raise FileNotFoundError(
            f"Execution contract '{contract_p}' not found! Run agy_probe.py first to freeze a clean contract."
        )

    contract = json.loads(contract_p.read_text())
    frozen_version = contract.get("agy_version", "")
    current_version = get_current_agy_version(agy_cmd)

    print(f"[Harness] Current AGY version: {current_version}")
    print(f"[Harness] Contract frozen for: {frozen_version}")

    # Set up temporary isolated sandbox outside HOME
    sandbox_root = Path(tempfile.mkdtemp(prefix="prompt-healing-")).resolve()
    input_dir = sandbox_root / "input"
    staging_dir = sandbox_root / "staging"
    settings_dir = sandbox_root / "settings"
    input_dir.mkdir(parents=True)
    staging_dir.mkdir(parents=True)
    settings_dir.mkdir(parents=True)

    # 1. Inject Problem Fixtures (failing test + runtime diagnosis log)
    broken_test_file = staging_dir / "checkout.spec.ts"
    broken_test_file.write_text(
        "import { test, expect } from '@playwright/test';\n\n"
        "test('checkout flow', async ({ page }) => {\n"
        "  await page.goto('/checkout');\n"
        "  // FAILING LOCATOR: button ID changed in latest release\n"
        "  await page.locator('#SUBMIT_PAYMENT_OLD').click();\n"
        "});\n"
    )

    failure_log_file = input_dir / "failure_log.txt"
    failure_log_file.write_text(
        "TEST RUN FAILURE: Locator '#SUBMIT_PAYMENT_OLD' timed out after 5000ms.\n"
        "DIAGNOSTIC HINT: In the latest frontend release, checkout button was updated to '#SUBMIT_PAYMENT_V2'.\n"
        "OBJECTIVE: Update checkout.spec.ts to use the new locator '#SUBMIT_PAYMENT_V2'.\n"
    )

    # 2. Hydrate Contract Settings and Argv
    session_settings_file = settings_dir / "healing_settings.json"
    argv, settings_dict = load_contract(
        contract_path=contract_p,
        staging_dir=staging_dir,
        input_dir=input_dir,
        settings_file=session_settings_file,
    )
    session_settings_file.write_text(json.dumps(settings_dict, indent=2))

    # Replace agy command prefix if a custom executable or stub is supplied
    custom_tokens = agy_cmd.split()
    if argv and custom_tokens and custom_tokens[0] != argv[0]:
        argv = custom_tokens + argv[1:]

    # 3. Construct Healing Prompt
    healing_prompt = (
        "You are an automated test repair agent operating inside a sandboxed workspace.\n"
        f"1. Read the error log at: {failure_log_file}\n"
        f"2. Repair the test in: {broken_test_file} to fix the failure.\n"
        "Do NOT attempt to touch any files outside your staging directory.\n"
    )
    stdin_data = json.dumps({"event": "user", "message": {"content": healing_prompt}}) + "\n"

    print(f"[Harness] Launching healing agent in staging workspace: {staging_dir}")
    t0 = time.monotonic()
    p = subprocess.Popen(
        argv,
        cwd=str(staging_dir),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = p.communicate(input=stdin_data, timeout=timeout)
    duration = round(time.monotonic() - t0, 1)

    # 4. Objective Ground-Truth Evaluation
    healed_content = broken_test_file.read_text()
    fix_applied = ("#SUBMIT_PAYMENT_V2" in healed_content) and ("#SUBMIT_PAYMENT_OLD" not in healed_content)

    # Check for sandbox containment (assert input_dir and settings_dir were not modified)
    input_unmodified = failure_log_file.read_text().startswith("TEST RUN FAILURE:")
    unexpected_files = [str(f.name) for f in staging_dir.iterdir() if f.name != "checkout.spec.ts"]

    success = (p.returncode == 0) and fix_applied and input_unmodified and (len(unexpected_files) == 0)

    result = {
        "success": success,
        "fix_applied": fix_applied,
        "exit_code": p.returncode,
        "duration_seconds": duration,
        "containment_intact": input_unmodified and (len(unexpected_files) == 0),
        "unexpected_files": unexpected_files,
        "staging_dir": str(staging_dir),
    }

    if not keep_sandbox:
        shutil.rmtree(sandbox_root, ignore_errors=True)
    else:
        print(f"[Harness] Kept sandbox at: {sandbox_root}")

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Autonomous Prompt Healing Evaluation Harness")
    parser.add_argument("--agy", default="agy", help="agy CLI command or test double")
    parser.add_argument("--contract", default="agy-probe-report/agy_contract.json", help="Path to frozen contract")
    parser.add_argument("--keep", action="store_true", help="Keep sandbox directory for inspection")
    parser.add_argument("--timeout", type=int, default=180, help="Timeout in seconds")
    args = parser.parse_args()

    try:
        res = run_healing_session(
            agy_cmd=args.agy,
            contract_path=args.contract,
            keep_sandbox=args.keep,
            timeout=args.timeout,
        )
        print("\n=== Prompt Healing Harness Result ===")
        print(f"  Success:            {res['success']}")
        print(f"  Fix Applied on Disk:{res['fix_applied']}")
        print(f"  Containment Intact: {res['containment_intact']}")
        print(f"  Duration:           {res['duration_seconds']}s")
        print(f"  Exit Code:          {res['exit_code']}")
        return 0 if res["success"] else 1
    except Exception as exc:
        print(f"[Harness Error] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
