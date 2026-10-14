#!/usr/bin/env python3
"""Safety Hook - PreToolUse hook for Claude Code that blocks clearly destructive commands.

Reads a PreToolUse JSON event from stdin and prints a permission decision JSON to stdout.
Denied attempts are logged locally. Safe commands produce no output (exit 0), so the
normal Claude Code permission flow applies.

Scope and limits: this hook inspects text of shell commands only. It cannot stop
destructive actions performed through other tools, scripts, or indirect execution.
It is a safety net, not a replacement for OS permissions or backups.

Requires: Python 3.8+ (standard library only).
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone

# --- Configuration ---------------------------------------------------------

def log_path() -> str:
    """Log file location; overridable via SAFETY_HOOK_LOG for tests/demo."""
    return os.environ.get(
        "SAFETY_HOOK_LOG",
        os.path.join(os.path.expanduser("~"), ".claude", "hooks", "blocked.log"),
    )

MAX_LOGGED_CMD = 300  # characters kept per log line

# --- Redaction (never log obvious secrets) ---------------------------------

SECRET_RE = re.compile(
    r"(?i)\b(token|password|passwd|secret|api[_-]?key|auth|credential)"
    r"([\s]*[=:][\s]*)(\S+)"
)
ENV_ASSIGN_RE = re.compile(r"(?i)^\s*([A-Z_]*(KEY|TOKEN|SECRET|PASSWORD)[A-Z_]*)=(\S+)")

def redact(command: str) -> str:
    """Mask values that look like secrets before logging."""
    out = SECRET_RE.sub(r"\1\2[REDACTED]", command)
    parts = []
    for word in out.split():
        parts.append(ENV_ASSIGN_RE.sub(r"\1=[REDACTED]", word, count=1))
    return " ".join(parts)

# --- Detection rules --------------------------------------------------------
# Each rule: (compiled regex or callable, human-readable reason).
# Deliberately narrow: normal day-to-day commands must keep working.

RECURSIVE_RM_RE = re.compile(
    r"\brm\b\s+(?:-[\w.]*\s+)*-[\w.]*r[\w.]*|\brm\b[^\n|&;]*--recursive\b",
    re.IGNORECASE,
)
PS_RECURSIVE_RE = re.compile(r"\bRemove-Item\b[^\n|&;]*-Recurse\b", re.IGNORECASE)
GIT_FORCE_PUSH_RE = re.compile(
    r"\bgit\s+push\b[^\n|&;]*(--force\b|--force-with-lease\b|-f\b)", re.IGNORECASE
)
SQL_DROP_RE = re.compile(r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", re.IGNORECASE)
SQL_TRUNCATE_RE = re.compile(r"\bTRUNCATE\s+(TABLE\s+)?\w", re.IGNORECASE)
SQL_DELETE_FROM_RE = re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE)

def _segments(command: str) -> list[str]:
    """Split a command line into sub-commands so SQL rules are evaluated per statement."""
    return re.split(r"[;&|]+|\n", command)

def _delete_without_where(command: str) -> bool:
    for seg in _segments(command):
        if SQL_DELETE_FROM_RE.search(seg) and not re.search(r"\bWHERE\b", seg, re.IGNORECASE):
            return True
    return False

RULES = [
    (lambda c: bool(RECURSIVE_RM_RE.search(c)),
     "recursive file deletion (rm -rf / rm -r / Remove-Item -Recurse style)"),
    (lambda c: bool(PS_RECURSIVE_RE.search(c)),
     "recursive file deletion (Remove-Item -Recurse)"),
    (lambda c: bool(GIT_FORCE_PUSH_RE.search(c)),
     "force-pushing to git (git push --force / -f)"),
    (lambda c: bool(SQL_DROP_RE.search(c)),
     "destructive SQL (DROP TABLE/DATABASE/SCHEMA)"),
    (lambda c: bool(SQL_TRUNCATE_RE.search(c)),
     "destructive SQL (TRUNCATE)"),
    (_delete_without_where,
     "destructive SQL (DELETE FROM without a WHERE clause)"),
]

def analyze(command: str) -> tuple[bool, str]:
    """Return (blocked, reason). Pure function; no I/O."""
    if not isinstance(command, str) or not command.strip():
        return False, ""
    for check, reason in RULES:
        try:
            if check(command):
                return True, reason
        except Exception:
            continue  # a broken rule must never crash the hook
    return False, ""

# --- Logging ----------------------------------------------------------------

def log_block(command: str, reason: str, cwd: str = "") -> None:
    """Append one line to the local log. Never logs more than MAX_LOGGED_CMD chars,
    and redacts secret-looking values. Failures are silently ignored (fail-open)."""
    try:
        path = log_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        safe_cmd = redact(command)[:MAX_LOGGED_CMD]
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{stamp}\tBLOCKED\t{reason}\tcwd={cwd}\tcmd={safe_cmd}\n")
    except Exception:
        pass

# --- Hook entry point -------------------------------------------------------

def handle(payload: dict) -> dict | None:
    """Return a deny-decision dict, or None to let the normal flow proceed."""
    command = ""
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        cmd = tool_input.get("command")
        if isinstance(cmd, str):
            command = cmd
    blocked, reason = analyze(command)
    if not blocked:
        return None
    log_block(command, reason, cwd=str(payload.get("cwd") or ""))
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"Blocked by safety-hook: {reason}. "
                "If you are sure this is needed, ask the user to run it manually."
            ),
        }
    }

def main() -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("top-level JSON is not an object")
    except Exception as e:
        # Fail open: invalid input must not break normal work.
        print(f"safety-hook: could not parse input ({e}); no decision", file=sys.stderr)
        return 0
    decision = handle(payload)
    if decision is not None:
        print(json.dumps(decision))
    return 0

if __name__ == "__main__":
    sys.exit(main())
