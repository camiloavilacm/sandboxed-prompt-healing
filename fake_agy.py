#!/usr/bin/env python3
"""
fake_agy.py (v1.1) - behavioral test double for agy_probe.py self-testing.

NOTE: This stub tests agy_probe.py's harness logic, schema validation, filesystem
auditing, and fault-injection detection. A CLEAN result against fake_agy.py does NOT
establish security of a real Antigravity CLI installation.

Env switches to simulate defects:
  FAKE_NAIVE=1             raw string-prefix matching (no realpath): `..` and symlink escapes succeed
  FAKE_BREACH_INPUT=1      writes to input/ are allowed regardless of rules
  FAKE_SKIP_ATTEMPTS=1     never attempts denied tasks (-> UNTESTED)
  FAKE_EXTRA_STAGE_FILE=1  creates an unrequested file in staging/ (-> UNEXPECTED_FS_ENTRY breach)
  FAKE_NONZERO_RC=1        emits SUCCESS event but exits with code 1 (-> protocol_ok False)
"""
import json
import os
import re
import sys

argv = sys.argv[1:]
GLOBAL_ALLOW = ["command(git)"]


def opt(name):
    return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else None


if "--version" in argv:
    print("agy 0.0.0-fake")
    sys.exit(0)
if "--help" in argv or argv[:1] == ["help"]:
    print("flags: --settings --add-dir --mode --json-schema --print-timeout "
          "--input-format --output-format --dangerously-skip-permissions")
    sys.exit(0)

settings = {}
if opt("--settings"):
    with open(opt("--settings")) as fh:
        settings = json.load(fh)
perms = settings.get("permissions", {"allow": [], "deny": []})
effective_allows = GLOBAL_ALLOW + list(perms.get("allow", []))
effective_denies = list(perms.get("deny", []))

p_flag = "-p" if "-p" in argv else ("--print" if "--print" in argv else None)
if p_flag:
    val = argv[argv.index(p_flag) + 1] if argv.index(p_flag) + 1 < len(argv) else ""
    if val.startswith("--"):  # Go flag quirk: -p swallowed the next flag as its value
        print("received prompt:", val)
        sys.exit(0)
    if val.startswith("/"):
        lines = [f"allow\t{a}" for a in effective_allows] + [f"deny\t{d}" for d in effective_denies]
        print("\n".join(lines) if val == "/permissions" else "(none)")
        sys.exit(0)
    print(json.dumps({"status": "SUCCESS", "response": "PONG", "structured_output": {"pong": "PONG"}}))
    sys.exit(0)

if opt("--input-format") == "stream-json":
    ev = json.loads(sys.stdin.readline())
    prompt = ev["message"]["content"]
    cwd = os.getcwd()
    effective_mode = opt("--mode") or settings.get("agentMode") or "auto"
    tool_perm = settings.get("toolPermission", "request-review")
    allow_non_ws = bool(settings.get("allowNonWorkspaceAccess", False))

    # Build workspace roots from trustedWorkspaces + --add-dir (or fallback to cwd if unset)
    NAIVE = os.environ.get("FAKE_NAIVE") == "1"

    def norm(p):
        return p if NAIVE else os.path.realpath(p)

    configured_ws = settings.get("trustedWorkspaces")
    raw_roots = list(configured_ws) if isinstance(configured_ws, list) else [cwd]
    if opt("--add-dir"):
        raw_roots.append(opt("--add-dir"))
    roots = [norm(r_) for r_ in raw_roots]

    print(json.dumps({"event": "init", "init": {"cwd": cwd, "tools": ["read_file", "write_file"],
                                                 "permission_mode": effective_mode}}))
    m = re.search(r"<<<TASKS\n(.*?)\nTASKS>>>", prompt, re.S)
    if not m:
        so = {"pong": "PONG"}
    else:
        def matches(target, path):
            n = norm(path)
            t = target if NAIVE else (os.path.realpath(target.rstrip("/")) + ("/" if target.endswith("/") else ""))
            return target == "*" or n == t.rstrip("/") or n.startswith(t if t.endswith("/") else t + "/")

        def parse_rules(rule_list):
            out = []
            for r in rule_list:
                mm = re.match(r"(\w+)\((.*)\)$", r)
                if mm:
                    out.append((mm.group(1), mm.group(2)))
            return out

        deny_rules = parse_rules(effective_denies)
        allow_rules = parse_rules(effective_allows)

        def in_workspace(path):
            n = norm(path)
            return any(n == r_ or n.startswith(r_ + "/") for r_ in roots)

        def decide(kind, path):
            if tool_perm == "strict":
                return False  # strict prompts on every tool call -> fails in headless
            for act, tgt in deny_rules:
                if (act == kind or (act == "read_file" and kind == "write_file")) and matches(tgt, path):
                    return False
            for act, tgt in allow_rules:
                if (act == kind or (act == "write_file" and kind == "read_file")) and matches(tgt, path):
                    return True
            if in_workspace(path) and effective_mode in ("accept-edits", "auto"):
                return True
            return allow_non_ws and kind == "read_file"

        def decide_command(cmd_str):
            for act, tgt in deny_rules:
                if act == "command" and (tgt == "*" or cmd_str.startswith(tgt)):
                    return False
            for act, tgt in allow_rules:
                if act == "command" and (tgt == "*" or cmd_str.startswith(tgt)):
                    return True
            return effective_mode == "auto"

        results = []
        for t in json.loads(m.group(1)):
            tid, action, path = t["id"], t["action"], t.get("path", "")
            denied_task = tid not in ("R_INPUT", "W_STAGE")
            if denied_task and os.environ.get("FAKE_SKIP_ATTEMPTS") == "1":
                results.append({"id": tid, "attempted": False, "outcome": "skipped",
                                "content_read": "", "tool_message": "skipped by FAKE_SKIP_ATTEMPTS"})
                continue
            res = {"id": tid, "attempted": True, "outcome": "denied", "content_read": "", "tool_message": "denied"}
            if action == "run shell command":
                if decide_command(t["command"]):
                    os.system(t["command"])
                    res["outcome"] = "success"
                    res["tool_message"] = "ran"
            elif action == "read":
                if decide("read_file", path):
                    res["content_read"] = open(path).read()
                    res["outcome"] = "success"
                    res["tool_message"] = "ok"
            else:
                allowed = decide("write_file", path)
                if tid in ("W_INPUT_CREATE", "W_INPUT_OVERWRITE") and os.environ.get("FAKE_BREACH_INPUT") == "1":
                    allowed = True
                if allowed:
                    if action == "edit":
                        txt = open(path).read().replace("LOCATOR_OLD", "LOCATOR_NEW")
                        open(path, "w").write(txt)
                    elif action == "overwrite file":
                        open(path, "w").write(t.get("content", "x"))
                    else:
                        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
                        with open(path, "a") as fh:
                            fh.write(t.get("content", "x"))
                    res["outcome"] = "success"
                    res["tool_message"] = "written"
            results.append(res)

        if os.environ.get("FAKE_EXTRA_STAGE_FILE") == "1":
            with open(os.path.join(roots[-1], "unauthorized.ts"), "w") as fh:
                fh.write("// unexpected file in staging\n")

        so = {"results": results}
    print(json.dumps({"event": "result", "result": {"status": "SUCCESS", "response": "done",
                                                      "structured_output": so}}))
    sys.exit(1 if os.environ.get("FAKE_NONZERO_RC") == "1" else 0)

print("no mode matched", file=sys.stderr)
sys.exit(2)