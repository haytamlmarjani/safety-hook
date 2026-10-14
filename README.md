# Safety Hook for Claude Code

A local `PreToolUse` hook that blocks clearly destructive shell commands
before Claude Code executes them, and logs every blocked attempt to a local file.

Pure Python 3.8+, standard library only. No network calls. No data leaves your machine.

## What it blocks

| Pattern | Examples blocked |
|---|---|
| Recursive file deletion | `rm -rf /path`, `rm -fr dir`, `rm -r -f dir`, `Remove-Item -Recurse` |
| Force-pushing to git | `git push --force`, `git push -f`, `git push --force-with-lease` |
| Destructive SQL | `DROP TABLE`, `DROP DATABASE`, `DROP SCHEMA`, `TRUNCATE`, `DELETE FROM` without a `WHERE` clause |

Chained commands (`ls && rm -rf dist`) are caught too.

## What it deliberately allows

`rm file.txt`, `rm -f tmp`, normal `git push`, `DELETE FROM t WHERE ...` ,
`SELECT`, and everyday commands (`npm test`, `ls`, ...). The rules are narrow on
purpose so normal work is not interrupted.

## Honest limitations

- It inspects the **text** of Bash/PowerShell tool calls only. It cannot see commands
  hidden inside scripts, binaries, or other tools, and cannot stop destructive
  actions taken through other channels.
- Pattern matching is heuristic: determined bypasses exist. This is a **safety net,
  not a security boundary**. Keep OS permissions, least-privilege accounts, and
  backups as your real defenses.
- On malformed input or internal errors it **fails open** (allows the command) so a
  broken hook never blocks your work; a note is written to stderr instead.

## Log file

Blocked attempts go to `~/.claude/hooks/blocked.log`, one TSV line each:
`timestamp, BLOCKED, reason, cwd, command`. Secret-looking values
(`token=...`, `PASSWORD=...`, etc.) are redacted and commands are truncated to
300 characters. Override the location with the `SAFETY_HOOK_LOG` environment
variable (useful for testing).

## Install (2 copy-paste steps)

1. Copy the script into your hooks folder:

   ```powershell
   Copy-Item .\safety_hook.py "$HOME\.claude\hooks\safety_hook.py"
   ```

2. Add this block to `~/.claude/settings.json` (merge with existing `hooks` if any):

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Bash|PowerShell",
           "hooks": [
             {
               "type": "command",
               "command": "py -3 \"%USERPROFILE%\\.claude\\hooks\\safety_hook.py\""
             }
           ]
         }
       ]
     }
   }
   ```

   On macOS/Linux use `"command": "python3 ~/.claude/hooks/safety_hook.py"`.

   To enable it for a single project instead, place the same block in
  `.claude/settings.json` inside that project (see `settings.example.json`).

## Verify it works

```powershell
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"}}' | py -3 safety_hook.py
```

Expected: a JSON object with `"permissionDecision": "deny"`, and a new line in the log.

## Uninstall

Delete the script and remove the `PreToolUse` block you added to your settings file.
Delete `~/.claude/hooks/blocked.log` if you do not want to keep the history.

## Tests

```powershell
py -3 -m unittest discover -s tests -v
```

Current status: **34/34 passing** (run on 2026-10-14, Python 3.15, Windows).

`examples/blocked.sample.log` is a demo log generated from **fake test commands**
only; it contains no real user data.
