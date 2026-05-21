// Claude Code settings.json wiring.
//
// `veto install-claude-hook` makes the JSON edit that wires the Go
// `veto hook claude-code` subcommand into Claude Code's PreToolUse Bash
// chain. We make this a first-class subcommand (rather than asking
// colleagues to hand-edit JSON) because:
//
//   - editing JSON by hand drops trailing newlines, breaks the trailing
//     comma rules in different ways than people expect, and silently
//     corrupts settings files;
//   - the hook chain may already contain unrelated hooks (rtk-rewrite,
//     gsd-statusline, etc.) — a naive "write the whole file" approach
//     would clobber them;
//   - having one subcommand to wire-up means the onboarding doc can read
//     "run `veto install-claude-hook`" instead of a multi-step JSON
//     surgery walkthrough.
//
// Atomicity: we write to a sibling tmp file and rename. settings.json is
// frequently held open or mid-write by other tooling; a partial write
// would brick Claude Code session startup.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
)

// runInstallClaudeHook implements `veto install-claude-hook
// [--settings PATH] [--project] [--print]`.
//
// Without flags, edits ~/.claude/settings.json. With --project, edits
// .claude/settings.json relative to cwd (the per-project file Claude Code
// recognises). With --settings PATH, edits an explicit path. --print
// writes the resulting JSON to stdout instead of mutating the file —
// useful for inspecting without committing.
func runInstallClaudeHook(logger zerolog.Logger, args []string) int {
	opts, err := parseClaudeHookFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto install-claude-hook: %v\n", err)
		return exitUsage
	}

	vetoPath, err := resolveVetoBinary()
	if err != nil {
		logger.Error().Err(err).Msg("locate veto binary")
		return exitInternal
	}

	settings, err := readSettings(opts.path)
	if err != nil {
		logger.Error().Err(err).Str("path", opts.path).Msg("read settings")
		return exitInternal
	}

	changed, action := ensureClaudeHook(settings, vetoPath)
	if !changed {
		fmt.Printf("veto: %s already wired in %s\n", action, opts.path)
		return exitOK
	}

	if opts.print {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(settings); err != nil {
			logger.Error().Err(err).Msg("encode settings")
			return exitInternal
		}
		return exitOK
	}

	if err := writeSettings(opts.path, settings); err != nil {
		logger.Error().Err(err).Str("path", opts.path).Msg("write settings")
		return exitInternal
	}
	fmt.Printf("veto: %s in %s\n", action, opts.path)
	fmt.Printf("         hook command: %s hook claude-code\n", vetoPath)
	fmt.Println("         Restart Claude Code (or open a new session) for the hook to take effect.")
	return exitOK
}

// runUninstallClaudeHook removes the veto hook entry from the file
// (matching by command containing our binary path or the literal
// "veto hook claude-code" — so older python-shebang installs are also
// caught). Other hooks in the same PreToolUse chain are preserved.
func runUninstallClaudeHook(logger zerolog.Logger, args []string) int {
	opts, err := parseClaudeHookFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto uninstall-claude-hook: %v\n", err)
		return exitUsage
	}

	settings, err := readSettings(opts.path)
	if err != nil {
		logger.Error().Err(err).Str("path", opts.path).Msg("read settings")
		return exitInternal
	}

	removed := removeClaudeHook(settings)
	if !removed {
		fmt.Printf("veto: no veto hook found in %s — nothing to do\n", opts.path)
		return exitOK
	}

	if err := writeSettings(opts.path, settings); err != nil {
		logger.Error().Err(err).Str("path", opts.path).Msg("write settings")
		return exitInternal
	}
	fmt.Printf("veto: removed hook entry from %s\n", opts.path)
	return exitOK
}

type claudeHookFlags struct {
	path  string
	print bool
}

func parseClaudeHookFlags(args []string) (claudeHookFlags, error) {
	var (
		opts        claudeHookFlags
		explicit    string
		projectMode bool
	)
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--print":
			opts.print = true
		case a == "--project":
			projectMode = true
		case a == "--settings":
			if i+1 >= len(args) {
				return opts, errors.New("--settings requires a path argument")
			}
			explicit = args[i+1]
			i++
		case strings.HasPrefix(a, "--settings="):
			explicit = strings.TrimPrefix(a, "--settings=")
		default:
			return opts, errors.WithNew("unknown argument").Set("arg", a)
		}
	}
	switch {
	case explicit != "":
		opts.path = explicit
	case projectMode:
		opts.path = filepath.Join(".claude", "settings.json")
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return opts, errors.With(err, "resolve home dir")
		}
		opts.path = filepath.Join(home, ".claude", "settings.json")
	}
	abs, err := filepath.Abs(opts.path)
	if err != nil {
		return opts, errors.With(err, "resolve settings path")
	}
	opts.path = abs
	return opts, nil
}

// readSettings returns the parsed contents of path, or an empty map if
// the file doesn't exist. Existing-but-malformed is an error — we refuse
// to silently overwrite a settings.json someone hand-tuned, even if the
// JSON is currently invalid.
func readSettings(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, errors.With(err, "read").Set("path", path)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, errors.With(err, "parse settings.json — refusing to overwrite a malformed file").Set("path", path)
	}
	return m, nil
}

// writeSettings serializes settings as 2-space-indented JSON and writes
// atomically (tmp + rename). Adds a trailing newline so editors and
// version-control diffs stay clean.
func writeSettings(path string, settings map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errors.With(err, "mkdir").Set("dir", filepath.Dir(path))
	}
	buf, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return errors.With(err, "marshal settings")
	}
	buf = append(buf, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings.json.")
	if err != nil {
		return errors.With(err, "tmpfile")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op if rename succeeded
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		return errors.With(err, "write tmpfile")
	}
	if err := tmp.Close(); err != nil {
		return errors.With(err, "close tmpfile")
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return errors.With(err, "chmod tmpfile")
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return errors.With(err, "rename")
	}
	return nil
}

// ensureClaudeHook mutates settings in place to contain a PreToolUse Bash
// hook entry that invokes `<vetoPath> hook claude-code`. Idempotent:
// if the entry already exists (matched by command string or by "veto
// hook claude-code" substring), it is updated to the current vetoPath
// and the function reports no-change.
//
// Returns (changed, humanReadableSummary). The summary distinguishes
// "added a new entry", "updated an existing entry's command path", and
// "already correct".
func ensureClaudeHook(settings map[string]any, vetoPath string) (bool, string) {
	wantedCmd := vetoPath + " hook claude-code"

	hooks := getOrCreateObject(settings, "hooks")
	preToolUse := getOrCreateArray(hooks, "PreToolUse")

	// Find or create the Bash matcher block.
	bashEntry, bashIdx := findMatcherEntry(preToolUse, "Bash")
	if bashEntry == nil {
		bashEntry = map[string]any{
			"matcher": "Bash",
			"hooks":   []any{},
		}
		preToolUse = append(preToolUse, bashEntry)
		bashIdx = len(preToolUse) - 1
	}

	inner, _ := bashEntry["hooks"].([]any)

	// Look for an existing veto entry (matched lenient: any command
	// referencing veto-hook.py or `hook claude-code` is ours).
	for i, raw := range inner {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		cmd, _ := entry["command"].(string)
		if !isVetoHookCommand(cmd) {
			continue
		}
		if cmd == wantedCmd {
			return false, "hook"
		}
		entry["command"] = wantedCmd
		entry["type"] = "command"
		inner[i] = entry
		bashEntry["hooks"] = inner
		preToolUse[bashIdx] = bashEntry
		hooks["PreToolUse"] = preToolUse
		return true, "updated hook command to point at " + vetoPath
	}

	// Not found — append.
	inner = append(inner, map[string]any{
		"type":    "command",
		"command": wantedCmd,
	})
	bashEntry["hooks"] = inner
	preToolUse[bashIdx] = bashEntry
	hooks["PreToolUse"] = preToolUse
	return true, "added hook entry"
}

// removeClaudeHook strips any veto-owned hook entry from the
// PreToolUse Bash chain. If that empties the Bash chain, the matcher
// block is also removed. Returns whether the settings map changed.
func removeClaudeHook(settings map[string]any) bool {
	hooksRaw, ok := settings["hooks"]
	if !ok {
		return false
	}
	hooks, ok := hooksRaw.(map[string]any)
	if !ok {
		return false
	}
	pre, ok := hooks["PreToolUse"].([]any)
	if !ok {
		return false
	}
	changed := false
	newPre := make([]any, 0, len(pre))
	for _, raw := range pre {
		entry, ok := raw.(map[string]any)
		if !ok {
			newPre = append(newPre, raw)
			continue
		}
		matcher, _ := entry["matcher"].(string)
		if matcher != "Bash" {
			newPre = append(newPre, raw)
			continue
		}
		innerRaw, _ := entry["hooks"].([]any)
		newInner := make([]any, 0, len(innerRaw))
		for _, h := range innerRaw {
			hm, ok := h.(map[string]any)
			if !ok {
				newInner = append(newInner, h)
				continue
			}
			cmd, _ := hm["command"].(string)
			if isVetoHookCommand(cmd) {
				changed = true
				continue
			}
			newInner = append(newInner, h)
		}
		if len(newInner) == 0 {
			// Empty chain — drop the matcher entry too.
			changed = true
			continue
		}
		entry["hooks"] = newInner
		newPre = append(newPre, entry)
	}
	if !changed {
		return false
	}
	if len(newPre) == 0 {
		delete(hooks, "PreToolUse")
	} else {
		hooks["PreToolUse"] = newPre
	}
	return true
}

// isVetoHookCommand recognises any hook command string we (or our
// Python predecessor) would have inserted. We deliberately do NOT use
// a loose strings.Contains(cmd, "veto") check: that pattern was the
// same drift class the install-wrappers Layer-4 fix removed. An
// attacker-planted hook command like
// `/opt/homebrew/bin/notveto-evil hook claude-code` would have
// matched the old check and been silently accepted as "already ours."
//
// Instead, we tokenize cmd, take the first token, and require its
// basename to be exactly `veto` (modern command) or to end in
// `veto-hook` / `veto-hook.py` (the Python predecessor). The lexical
// check is the floor — settings.json commonly stores absolute paths
// that no longer exist (e.g. after `make install` to a different
// prefix), and we still need to recognize those as ours to avoid
// leaving duplicate stale entries on uninstall.
//
// TODO(H1): when a settings.json entry references an existing file,
// additionally identity-check the resolved binary against the running
// veto via vetopath.PointsAt. The basename floor must remain for the
// stale-path case (uninstall after `make install` to a new prefix),
// so the identity check is a strict-mode AND, not a replacement.
func isVetoHookCommand(cmd string) bool {
	if cmd == "" {
		return false
	}
	exe := firstTokenBasename(cmd)
	if exe == "" {
		return false
	}
	// Modern form: `<somewhere>/veto hook claude-code [...]`. Require
	// the leaf basename to be exactly `veto` (not merely contain it).
	if exe == "veto" && strings.Contains(cmd, "hook claude-code") {
		return true
	}
	// Legacy Python predecessor: `<somewhere>/veto-hook.py` or
	// `<somewhere>/veto-hook` (with or without extension).
	if exe == "veto-hook" || exe == "veto-hook.py" {
		return true
	}
	return false
}

// firstTokenBasename extracts the basename of the first whitespace-
// separated token of a command string. Quoted paths are unwrapped so
// `"/Users/me/Application Support/veto" hook claude-code` collapses
// to `veto`. Returns "" if the input is empty or malformed.
//
// This is a minimal, dependency-free tokenizer; we don't need shlex
// here because the hook commands we recognise have a strict shape
// (path + ` hook claude-code` or path alone).
func firstTokenBasename(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if cmd[0] == '"' {
		if end := strings.IndexByte(cmd[1:], '"'); end > 0 {
			return filepath.Base(cmd[1 : 1+end])
		}
		return ""
	}
	if cmd[0] == '\'' {
		if end := strings.IndexByte(cmd[1:], '\''); end > 0 {
			return filepath.Base(cmd[1 : 1+end])
		}
		return ""
	}
	if i := strings.IndexAny(cmd, " \t"); i > 0 {
		return filepath.Base(cmd[:i])
	}
	return filepath.Base(cmd)
}

func findMatcherEntry(entries []any, matcher string) (map[string]any, int) {
	for i, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if m, _ := entry["matcher"].(string); m == matcher {
			return entry, i
		}
	}
	return nil, -1
}

func getOrCreateObject(m map[string]any, key string) map[string]any {
	if existing, ok := m[key].(map[string]any); ok {
		return existing
	}
	obj := map[string]any{}
	m[key] = obj
	return obj
}

func getOrCreateArray(m map[string]any, key string) []any {
	if existing, ok := m[key].([]any); ok {
		return existing
	}
	arr := []any{}
	m[key] = arr
	return arr
}
