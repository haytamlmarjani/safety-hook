"""Tests for safety_hook. No network, no destructive commands are executed;
we only feed text strings to the analyzer and the stdin/stdout pipeline."""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import safety_hook as sh


class TestAnalyzeBlocks(unittest.TestCase):
    def assertBlocked(self, cmd):
        blocked, reason = sh.analyze(cmd)
        self.assertTrue(blocked, f"should block: {cmd!r}")
        self.assertTrue(reason)

    def test_rm_rf(self):
        self.assertBlocked("rm -rf /tmp/build")

    def test_rm_fr_reordered(self):
        self.assertBlocked("rm -fr node_modules")

    def test_rm_separate_flags(self):
        self.assertBlocked("rm -r -f dist")

    def test_rm_recursive_long_flag(self):
        self.assertBlocked("rm --recursive old")

    def test_powershell_remove_item_recurse(self):
        self.assertBlocked("Remove-Item -Path build -Recurse -Force")

    def test_git_push_force(self):
        self.assertBlocked("git push origin main --force")

    def test_git_push_short_f(self):
        self.assertBlocked("git push -f")

    def test_git_push_force_with_lease(self):
        self.assertBlocked("git push --force-with-lease")

    def test_drop_table(self):
        self.assertBlocked("psql -c 'DROP TABLE users;'")

    def test_drop_database_case_insensitive(self):
        self.assertBlocked("mysql -e 'drop database prod'")

    def test_truncate(self):
        self.assertBlocked("sqlite3 app.db 'TRUNCATE TABLE logs;'")

    def test_delete_without_where(self):
        self.assertBlocked("sqlite3 app.db 'DELETE FROM users;'")

    def test_chained_command_still_caught(self):
        self.assertBlocked("ls -la && rm -rf dist")


class TestAnalyzeAllows(unittest.TestCase):
    def assertAllowed(self, cmd):
        blocked, _ = sh.analyze(cmd)
        self.assertFalse(blocked, f"should allow: {cmd!r}")

    def test_plain_rm_single_file(self):
        self.assertAllowed("rm file.txt")

    def test_rm_force_single_file_not_recursive(self):
        self.assertAllowed("rm -f build-output.tmp")

    def test_normal_git_push(self):
        self.assertAllowed("git push origin main")

    def test_git_commit(self):
        self.assertAllowed("git commit -m 'fix bug'")

    def test_delete_with_where(self):
        self.assertAllowed("sqlite3 app.db 'DELETE FROM sessions WHERE expired = 1;'")

    def test_select_star(self):
        self.assertAllowed("sqlite3 app.db 'SELECT * FROM users;'")

    def test_word_boundary_no_false_positive(self):
        # "formatted" contains "rm -f"-like letters; must not match
        self.assertAllowed("echo formatted output")
        self.assertAllowed("grep -rn 'confirm' src")

    def test_empty_and_whitespace(self):
        self.assertAllowed("")
        self.assertAllowed("   ")

    def test_npm_commands(self):
        self.assertAllowed("npm install && npm test")


class TestRedact(unittest.TestCase):
    def test_token_values_masked(self):
        out = sh.redact("curl -H 'Authorization: token=abc123xyz' https://x")
        self.assertNotIn("abc123xyz", out)
        self.assertIn("[REDACTED]", out)

    def test_env_assignment_masked(self):
        out = sh.redact("AWS_SECRET_ACCESS_KEY=supersecretvalue rm -rf x")
        self.assertNotIn("supersecretvalue", out)

    def test_normal_text_unchanged(self):
        self.assertEqual(sh.redact("git status"), "git status")


class TestLogBlock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.old = os.environ.get("SAFETY_HOOK_LOG")
        os.environ["SAFETY_HOOK_LOG"] = os.path.join(self.tmp, "blocked.log")

    def tearDown(self):
        if self.old is None:
            os.environ.pop("SAFETY_HOOK_LOG", None)
        else:
            os.environ["SAFETY_HOOK_LOG"] = self.old

    def test_log_line_written(self):
        sh.log_block("rm -rf /tmp/x", "recursive file deletion", cwd="C:\\proj")
        content = Path(os.environ["SAFETY_HOOK_LOG"]).read_text(encoding="utf-8")
        self.assertIn("BLOCKED", content)
        self.assertIn("recursive file deletion", content)
        self.assertIn("cwd=C:\\proj", content)
        self.assertIn("rm -rf /tmp/x", content)

    def test_log_never_contains_secrets(self):
        sh.log_block("drop table users --password=hunter2", "sql", cwd="")
        content = Path(os.environ["SAFETY_HOOK_LOG"]).read_text(encoding="utf-8")
        self.assertNotIn("hunter2", content)

    def test_long_command_truncated(self):
        sh.log_block("rm -rf " + "a" * 1000, "reason", cwd="")
        content = Path(os.environ["SAFETY_HOOK_LOG"]).read_text(encoding="utf-8")
        self.assertLess(len(content), 700)


class TestPipeline(unittest.TestCase):
    def run_hook(self, stdin_text):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin_text)
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                code = sh.main()
        finally:
            sys.stdin = old_stdin
        return code, out.getvalue(), err.getvalue()

    def test_deny_json_shape(self):
        payload = {"tool_name": "Bash",
                   "tool_input": {"command": "rm -rf /"},
                   "cwd": "C:\\demo"}
        code, out, _ = self.run_hook(json.dumps(payload))
        self.assertEqual(code, 0)
        decision = json.loads(out)
        hso = decision["hookSpecificOutput"]
        self.assertEqual(hso["hookEventName"], "PreToolUse")
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertIn("safety-hook", hso["permissionDecisionReason"])

    def test_safe_command_silent(self):
        payload = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
        code, out, _ = self.run_hook(json.dumps(payload))
        self.assertEqual(code, 0)
        self.assertEqual(out, "")

    def test_invalid_json_fails_open(self):
        code, out, err = self.run_hook("{not json")
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("could not parse", err)

    def test_non_object_json_fails_open(self):
        code, out, _ = self.run_hook('["a", "b"]')
        self.assertEqual(code, 0)
        self.assertEqual(out, "")

    def test_missing_tool_input(self):
        code, out, _ = self.run_hook(json.dumps({"tool_name": "Bash"}))
        self.assertEqual(code, 0)
        self.assertEqual(out, "")

    def test_empty_stdin_fails_open(self):
        code, out, _ = self.run_hook("")
        self.assertEqual(code, 0)
        self.assertEqual(out, "")


if __name__ == "__main__":
    unittest.main()
