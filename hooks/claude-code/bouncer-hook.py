#!/usr/bin/env python3
"""Claude Code PreToolUse hook for package-bouncer.

Denies any Bash tool invocation that reaches a bouncer-covered package manager
with a remote-fetching verb unless the command is explicitly prefixed with
`bouncer`. The agent then reissues with the prefix; bouncer's CLI does the
actual scan and decides.

Why this exists: shell-function shims don't apply through wrappers that
execvp() the binary directly (timeout, xargs, env, sudo, ...) or in
non-interactive shells that didn't source the shim init. The hook closes
those gaps by intercepting at Claude Code's tool layer, before the shell
ever sees the command.

Escape hatch: prepend `BOUNCER_BYPASS=1 ` to the command.
"""

import json
import os
import shlex
import shutil
import sys

PMS = {
    "npm", "npx", "yarn", "pnpm", "pnpx",
    "rush", "rushx", "bun", "bunx",
    "pip", "pip3", "uv", "uvx", "poetry", "pipx", "pdm",
}

# Per-PM verbs that resolve/fetch remote packages.
DANGEROUS_VERBS = {
    "npm":    {"install", "i", "add", "ci", "update", "up", "upgrade"},
    "yarn":   {"install", "add", "upgrade", "up", "dlx"},
    "pnpm":   {"install", "i", "add", "update", "up", "upgrade", "dlx"},
    "bun":    {"install", "i", "add", "update", "upgrade", "x", "create"},
    "rush":   {"install", "add", "update"},
    "pip":    {"install", "download"},
    "pip3":   {"install", "download"},
    "pipx":   {"install", "upgrade", "inject", "run"},
    "uv":     {"add", "sync", "install", "tool", "run", "pip"},
    "poetry": {"install", "add", "update", "lock"},
    "pdm":    {"install", "add", "update", "sync"},
}

# Always-dangerous PMs — every non-help invocation fetches and runs remote code.
EXEC_PMS = {"npx", "pnpx", "bunx", "rushx", "uvx"}

# Wrappers that execvp the next command, bypassing shell functions.
WRAPPERS = {
    "timeout", "env", "sudo", "doas", "nice", "ionice", "nohup",
    "time", "command", "builtin", "exec", "stdbuf", "unbuffer",
    "watch", "xargs", "chronic", "ts",
}

# Shells that take -c "<inline command>" — recurse into the inner string.
SHELL_BINS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}

LIST_SEPS = {"|", "||", "&&", ";", "&"}


def base(tok):
    return tok.rsplit("/", 1)[-1]


def is_redirect(tok):
    """Filter shell redirection tokens (>, >>, 2>, 2>&1, &>file, etc.) that
    shlex tokenizes as ordinary strings. Without this filter, `2>&1` is
    parsed as if it were a command argument."""
    if not tok:
        return False
    # Strip optional leading file-descriptor digit; what remains is the operator.
    s = tok.lstrip("0123456789")
    if not s:
        return False
    return s.startswith(("<", ">", "&>"))


def split_by_separators(tokens):
    cmds, current = [], []
    for t in tokens:
        if t in LIST_SEPS:
            if current:
                cmds.append(current)
                current = []
        else:
            current.append(t)
    if current:
        cmds.append(current)
    return cmds


def strip_redirects(tokens):
    """Remove redirect tokens AND their filename successors when present."""
    out = []
    skip_next = False
    for t in tokens:
        if skip_next:
            skip_next = False
            continue
        if is_redirect(t):
            # If the redirect token doesn't already include a target (e.g.
            # ">", "2>" alone), the next token is the filename — skip it too.
            stripped = t.lstrip("0123456789").lstrip("<>&")
            if stripped == "":
                skip_next = True
            continue
        out.append(t)
    return out


def expand_shell_invocations(tokens):
    """If tokens are `bash -c "..."` or similar, recursively parse the inner
    string. Returns a list of token lists (one per logical command found)."""
    if len(tokens) < 3:
        return [tokens]
    if base(tokens[0]) not in SHELL_BINS:
        return [tokens]
    for i in range(1, len(tokens)):
        t = tokens[i]
        if t == "-c" and i + 1 < len(tokens):
            try:
                inner = shlex.split(tokens[i + 1])
            except ValueError:
                return [tokens]
            inner = strip_redirects(inner)
            out = []
            for sub in split_by_separators(inner):
                out.extend(expand_shell_invocations(sub))
            return out
        if not t.startswith("-"):
            break
    return [tokens]


def strip_env_assignments(tokens):
    """Drop leading `VAR=value` assignments."""
    i = 0
    while i < len(tokens) and "=" in tokens[i] and not tokens[i].startswith("-"):
        name, _, _ = tokens[i].partition("=")
        if name and name.replace("_", "").isalnum():
            i += 1
            continue
        break
    return tokens[i:]


def strip_wrappers(tokens):
    """Peel off known wrappers and their flags until we reach the real binary."""
    while tokens:
        b = base(tokens[0])
        if b not in WRAPPERS:
            return tokens
        tokens = tokens[1:]
        if b == "env":
            while tokens and (tokens[0].startswith("-") or
                              ("=" in tokens[0] and not tokens[0].startswith("-"))):
                if tokens[0] in ("-u", "-S", "-C"):
                    tokens = tokens[2:] if len(tokens) > 1 else []
                else:
                    tokens = tokens[1:]
        elif b in ("sudo", "doas"):
            while tokens and tokens[0].startswith("-"):
                if tokens[0] in ("-u", "-g", "-h", "-p", "-C", "-D", "-T", "-U", "-A"):
                    tokens = tokens[2:] if len(tokens) > 1 else []
                else:
                    tokens = tokens[1:]
        elif b == "timeout":
            while tokens and tokens[0].startswith("-"):
                if tokens[0] in ("-s", "-k", "--signal", "--kill-after"):
                    tokens = tokens[2:] if len(tokens) > 1 else []
                else:
                    tokens = tokens[1:]
            if tokens:
                tokens = tokens[1:]  # the DURATION arg
        elif b in ("nice", "ionice"):
            while tokens and tokens[0].startswith("-"):
                if tokens[0] in ("-n", "-c", "-p"):
                    tokens = tokens[2:] if len(tokens) > 1 else []
                else:
                    tokens = tokens[1:]
        elif b == "xargs":
            while tokens and tokens[0].startswith("-"):
                if tokens[0] in ("-I", "-n", "-P", "-L", "-J", "-d", "-E", "-s",
                                 "--max-args", "--max-procs", "--max-lines",
                                 "--delimiter", "--max-chars", "--replace"):
                    tokens = tokens[2:] if len(tokens) > 1 else []
                else:
                    tokens = tokens[1:]
        elif b == "time":
            while tokens and tokens[0].startswith("-"):
                tokens = tokens[1:]
        elif b == "watch":
            while tokens and tokens[0].startswith("-"):
                if tokens[0] in ("-n", "-d"):
                    tokens = tokens[2:] if len(tokens) > 1 else []
                else:
                    tokens = tokens[1:]
        elif b == "stdbuf":
            while tokens and (tokens[0].startswith("-") or "=" in tokens[0]):
                if tokens[0] in ("-i", "-o", "-e"):
                    tokens = tokens[2:] if len(tokens) > 1 else []
                else:
                    tokens = tokens[1:]
    return tokens


def is_risky(tokens):
    if not tokens:
        return None
    b = base(tokens[0])
    if b == "bouncer":
        return None  # already guarded
    if b not in PMS:
        return None
    if b in EXEC_PMS:
        rest = [a for a in tokens[1:] if not a.startswith("-")]
        if not rest:
            return None
        if rest[0] in ("help", "--help", "-h", "--version", "-v"):
            return None
        return b
    verbs = DANGEROUS_VERBS.get(b, set())
    for a in tokens[1:]:
        if a.startswith("-"):
            continue
        return b if a in verbs else None
    return None


def analyze(cmd):
    try:
        top = shlex.split(cmd, posix=True)
    except ValueError:
        return None  # unparseable; let shell handle it
    if not top:
        return None
    if top[0] == "BOUNCER_BYPASS=1":
        return None

    top = strip_redirects(top)
    for sub in split_by_separators(top):
        for inner in expand_shell_invocations(sub):
            inner = strip_redirects(inner)
            inner = strip_env_assignments(inner)
            inner = strip_wrappers(inner)
            pm = is_risky(inner)
            if pm:
                return pm, inner
    return None


def bouncer_reachable():
    """Returns the absolute path to the bouncer binary on PATH, or None if
    it cannot be resolved or isn't executable. Hooks must fail closed if
    bouncer can't actually be invoked — telling the agent to "prefix with
    bouncer" is useless if the prefix won't run."""
    path = shutil.which("bouncer")
    if not path:
        return None
    if not os.access(path, os.X_OK):
        return None
    return path


def main():
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return
    if payload.get("tool_name") != "Bash":
        return
    cmd = payload.get("tool_input", {}).get("command", "")
    if not cmd:
        return
    finding = analyze(cmd)
    if not finding:
        return
    pm, tokens = finding

    # Fail-closed if bouncer itself isn't reachable: telling the agent to add
    # a `bouncer` prefix is meaningless when there's no bouncer to invoke.
    # Surface this loudly so colleagues notice the mis-install instead of
    # silently believing the gate is running.
    if not bouncer_reachable():
        out = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"bouncer-hook: BLOCKED unguarded `{pm}` invocation, "
                    f"AND the bouncer binary itself was not found on PATH.\n\n"
                    f"This means the safety gate is not installed correctly. "
                    f"Do NOT retry this command — the agent has no way to "
                    f"route a package-manager call through a malware scan "
                    f"right now.\n\n"
                    f"To fix:\n"
                    f"  1. Build and install bouncer: `make install` in the "
                    f"package-bouncer repo, OR `go install "
                    f"github.com/brynbellomy/package-bouncer/cmd/bouncer@latest`\n"
                    f"  2. Confirm `which bouncer` resolves to a real binary\n"
                    f"  3. Then retry the original command."
                ),
            }
        }
        json.dump(out, sys.stdout)
        return

    corrected = "bouncer " + " ".join(shlex.quote(t) for t in tokens)
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"bouncer-hook: blocked unguarded `{pm}` invocation.\n"
                f"Reason: package-bouncer only protects you when the command "
                f"is routed through it. Re-run with an explicit `bouncer` "
                f"prefix so the malware scan runs:\n\n  {corrected}\n\n"
                f"If multiple commands are chained, only the package-manager "
                f"leaf needs the prefix. To bypass intentionally, prepend "
                f"`BOUNCER_BYPASS=1 ` to the command."
            ),
        }
    }
    json.dump(out, sys.stdout)


# Claude Code's PreToolUse hooks "fail open" when the hook script exits with
# any non-zero status other than 2 — the tool call proceeds as if no hook ran.
# That makes uncaught exceptions in this script a silent fail-open hole: a
# missing import, a parser bug, anything that lets an exception escape would
# let an unguarded `npm install evil` through.
#
# Two-part defense:
#  1. Wrap main() so any exception is converted to a hard `deny` JSON output
#     on stdout and a clean exit 0. The tool call is blocked with a clear
#     "INTERNAL ERROR — install aborted" message.
#  2. If even that fails (e.g. stdout is closed, JSON encoding raises), exit
#     with status 2, which Claude Code treats as a blocking error.
#
# The only fail-open path that remains is "Python interpreter not present at
# the shebang path" — at that point Claude Code never even runs this script.
# A Go rewrite would close that final hole; tracked as a deferred task.
def safe_main():
    try:
        main()
    except Exception as exc:  # noqa: BLE001 — intentional catch-all
        try:
            json.dump({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        "bouncer-hook: INTERNAL ERROR in hook script — install "
                        "aborted fail-closed.\n\n"
                        "The hook crashed before it could make a routing "
                        "decision. The agent's command was NOT executed.\n\n"
                        f"Underlying error: {type(exc).__name__}: {exc}\n\n"
                        "Re-run the original command only after the hook is "
                        "fixed (or temporarily unwire it from "
                        "~/.claude/settings.json if you accept the risk)."
                    ),
                }
            }, sys.stdout)
        except Exception:
            # stdout broken or JSON encoder choked. Exit 2 makes Claude Code
            # treat this as a blocking error per its documented contract.
            sys.exit(2)


if __name__ == "__main__":
    safe_main()
