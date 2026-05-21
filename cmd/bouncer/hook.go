// Claude Code PreToolUse hook entrypoint.
//
// `bouncer hook claude-code` reads the JSON payload Claude Code sends to a
// PreToolUse command-hook on stdin, runs the analyzer, and writes a JSON
// hook-output decision to stdout. Compiled into the same binary as the
// rest of bouncer so a missing-python3 shebang failure can never silently
// fail-OPEN — if the bouncer binary is on PATH the hook is present.
//
// Fail-closed defense in depth:
//
//  1. Recovered panics: convert to a hard "deny" with INTERNAL ERROR.
//  2. Bouncer binary not resolvable: deny with a hard "do not retry"
//     message so colleagues notice the mis-install instead of seeing
//     bouncer get silently bypassed.
//  3. Risky command detected: deny with the corrected `bouncer …` prefix
//     in the message so the agent re-issues correctly.
//
// All three states emit a Claude-Code-shaped JSON envelope and exit 0.
// Exiting non-zero would cause Claude Code to fail-OPEN by default; only
// exit 2 produces a blocking error, used here as a last-resort fallback
// if stdout itself is broken.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/rs/zerolog"

	"github.com/brynbellomy/package-bouncer/internal/hook/claudecode"
)

// claudeHookInput is the subset of Claude Code's PreToolUse payload we use.
// Documented at https://docs.claude.com/en/docs/claude-code/hooks — we ignore
// anything outside Bash and outside `tool_input.command`.
type claudeHookInput struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

// claudeHookOutput matches Claude Code's `hookSpecificOutput.PreToolUse`
// shape. Only `permissionDecision` and `permissionDecisionReason` are
// load-bearing — the schema requires `hookEventName` for routing.
type claudeHookOutput struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

// runHook dispatches `bouncer hook <subcommand>`. Only `claude-code` is
// implemented today; others print usage so users see a clear "not wired
// yet" message instead of a silent no-op.
func runHook(logger zerolog.Logger, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "bouncer hook: missing subcommand. Try `bouncer hook claude-code`.")
		return exitUsage
	}
	switch args[0] {
	case "claude-code":
		return runClaudeCodeHook(logger, os.Stdin, os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "bouncer hook: unknown subcommand %q. Available: claude-code\n", args[0])
		return exitUsage
	}
}

// runClaudeCodeHook is the inner implementation. Takes io.Reader/Writer so
// tests can drive it without touching stdin/stdout. Always returns 0
// (success path or fail-closed "deny" envelope), unless the JSON envelope
// itself cannot be emitted — then we exit 2, which Claude Code treats as
// a blocking error per its documented contract.
func runClaudeCodeHook(logger zerolog.Logger, stdin io.Reader, stdout io.Writer) (rc int) {
	// Defense layer 1: any panic in the analyzer or transport becomes a
	// hard "deny" with INTERNAL ERROR. Without this, an uncaught panic
	// would exit non-zero, which Claude Code interprets as fail-OPEN.
	defer func() {
		if r := recover(); r != nil {
			logger.Error().Interface("panic", r).Msg("hook panic — emitting fail-closed deny")
			if writeErr := writeDeny(stdout, fmt.Sprintf(
				"bouncer-hook: INTERNAL ERROR in hook script — install aborted fail-closed.\n\n"+
					"The hook crashed before it could make a routing decision. The agent's command was NOT executed.\n\n"+
					"Underlying error: %v\n\n"+
					"Re-run the original command only after the hook is fixed (or temporarily unwire it from "+
					"~/.claude/settings.json if you accept the risk).",
				r,
			)); writeErr != nil {
				rc = 2 // Claude Code: exit 2 = blocking error.
				return
			}
			rc = exitOK
		}
	}()

	var input claudeHookInput
	if err := json.NewDecoder(stdin).Decode(&input); err != nil {
		// Malformed input is one of the few cases where letting the tool
		// call proceed is the right call — if we can't tell what the tool
		// is, we have no business gating it. Same behavior as the Python
		// original (which returned without emitting anything).
		logger.Debug().Err(err).Msg("decode hook input")
		return exitOK
	}
	if input.ToolName != "Bash" || input.ToolInput.Command == "" {
		return exitOK
	}

	finding, risky := claudecode.Analyze(input.ToolInput.Command)
	if !risky {
		return exitOK
	}

	// Defense layer 2: if bouncer itself isn't on PATH at hook time,
	// telling the agent to "prefix with bouncer" is useless. Fail closed
	// loudly so the mis-install is visible.
	if !bouncerReachable() {
		msg := fmt.Sprintf(
			"bouncer-hook: BLOCKED unguarded `%s` invocation, AND the bouncer binary itself was not found on PATH.\n\n"+
				"This means the safety gate is not installed correctly. Do NOT retry this command — the agent has no way to "+
				"route a package-manager call through a malware scan right now.\n\n"+
				"To fix:\n"+
				"  1. Build and install bouncer: `make install` in the package-bouncer repo, OR `go install "+
				"github.com/brynbellomy/package-bouncer/cmd/bouncer@latest`\n"+
				"  2. Confirm `which bouncer` resolves to a real binary\n"+
				"  3. Then retry the original command.",
			finding.PM,
		)
		return writeDecisionOrFail(stdout, msg)
	}

	corrected := "bouncer " + joinShellQuoted(finding.Tokens)
	msg := fmt.Sprintf(
		"bouncer-hook: blocked unguarded `%s` invocation.\n"+
			"Reason: package-bouncer only protects you when the command is routed through it. Re-run with an explicit "+
			"`bouncer` prefix so the malware scan runs:\n\n  %s\n\n"+
			"If multiple commands are chained, only the package-manager leaf needs the prefix. To bypass intentionally, "+
			"prepend `BOUNCER_BYPASS=1 ` to the command.",
		finding.PM, corrected,
	)
	return writeDecisionOrFail(stdout, msg)
}

// writeDecisionOrFail writes a `deny` envelope or, if even that fails,
// returns exit 2 — the only return value Claude Code documents as a
// blocking error when the hook itself misbehaves.
func writeDecisionOrFail(stdout io.Writer, reason string) int {
	if err := writeDeny(stdout, reason); err != nil {
		return 2
	}
	return exitOK
}

// writeDeny emits the Claude-Code-shaped JSON envelope.
func writeDeny(stdout io.Writer, reason string) error {
	var out claudeHookOutput
	out.HookSpecificOutput.HookEventName = "PreToolUse"
	out.HookSpecificOutput.PermissionDecision = "deny"
	out.HookSpecificOutput.PermissionDecisionReason = reason
	return json.NewEncoder(stdout).Encode(out)
}

// bouncerReachable mirrors the Python original's check: confirm that the
// shell can resolve `bouncer` from PATH, since the agent re-invokes by
// bare name after we tell it to add the prefix. If the hook is wired by
// absolute path but `bouncer` is not on PATH, the corrected command will
// fail with "command not found" — fail closed loudly instead.
func bouncerReachable() bool {
	path, err := exec.LookPath("bouncer")
	if err != nil {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}

// joinShellQuoted formats a slice of tokens back into a shell-safe string
// suitable for the corrected command line shown to the agent. We use
// shlex.Join from google/shlex's sibling for symmetry with the analyzer.
//
// Implementation note: google/shlex doesn't expose a Join, so we
// hand-format. The python original used shlex.quote per token; same idea
// here. Tokens with no shell-special characters pass through unquoted;
// anything else gets single-quoted with embedded single-quotes escaped.
func joinShellQuoted(tokens []string) string {
	parts := make([]string, len(tokens))
	for i, t := range tokens {
		parts[i] = shellQuote(t)
	}
	return strings.Join(parts, " ")
}

// shellQuote mirrors Python's `shlex.quote`: returns t unchanged if it
// only contains "safe" characters; otherwise wraps in single quotes with
// `'` escaped as `'\''`.
func shellQuote(t string) string {
	if t == "" {
		return "''"
	}
	const safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@%+=:,./-_"
	allSafe := true
	for i := 0; i < len(t); i++ {
		if !strings.ContainsRune(safe, rune(t[i])) {
			allSafe = false
			break
		}
	}
	if allSafe {
		return t
	}
	return "'" + strings.ReplaceAll(t, "'", `'\''`) + "'"
}

