---
name: agy-sandbox-guard
description: Enforces empirical boundary contracts before running autonomous prompt healing or agent workers.
---

# AGY Sandbox Guard

This skill ensures that any automated task, prompt-healing loop, or worker agent executed in this repository runs strictly inside an empirically verified, breach-proof boundary.

## Core Security Policy: Never Run Blind
Never launch an autonomous worker agent or prompt-healing pipeline without a verified contract (`agy_contract.json`) that matches the currently installed `agy --version`. Model self-reporting cannot be trusted; only empirical disk verification guarantees containment.

## Standard Workflow

### 1. Preflight Contract Verification
Before starting a healing session or executing worker tasks:
1. Check if `agy-probe-report/agy_contract.json` exists.
2. Read the contract and verify `agy_version` matches the local CLI (`agy --version`).
3. If missing or the CLI version has changed, execute the boundary probe:
   ```bash
   python3 agy_probe.py --variants D --runs 1
   ```
4. Confirm that Variant D reports `CLEAN`.

### 2. Contract Hydration
Always use the verified contract consumer from `agy_probe` rather than inventing manual CLI arguments:

```python
from agy_probe import load_contract

# Hydrates {staging_dir}, {input_dir}, {settings_file} placeholders safely
argv, settings = load_contract(
    contract_path="agy-probe-report/agy_contract.json",
    staging_dir="/path/to/isolated/staging",
    input_dir="/path/to/read_only_inputs",
    settings_file="/path/to/session_settings.json",
)
```

### 3. Sandbox Enforcement
* Always stage the broken code/prompts into `staging_dir`.
* Supply inputs (error logs, traces, instructions) in `input_dir` (read-only by contract).
* Run the subprocess with `cwd=staging_dir`.
* Never execute shell commands on the host directly; rely on the contract's explicit tool allow/deny rules.

### 4. Harness Evaluation
After the healing worker finishes:
* Run the test suite on the healed file inside `staging_dir`.
* Assert that zero files were created outside `staging_dir`.
* Commit or promote the healed prompt/code only after harness verification passes.
