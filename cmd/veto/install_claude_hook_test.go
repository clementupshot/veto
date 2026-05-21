package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEnsureClaudeHook_FreshSettings: brand-new settings file (or empty)
// gets the full hooks.PreToolUse[Bash][hooks] scaffolding inserted.
func TestEnsureClaudeHook_FreshSettings(t *testing.T) {
	settings := map[string]any{}
	changed, summary := ensureClaudeHook(settings, "/abs/path/to/veto")
	require.True(t, changed)
	require.Equal(t, "added hook entry", summary)

	cmd := getHookCommand(t, settings, "Bash", 0)
	require.Equal(t, "/abs/path/to/veto hook claude-code", cmd)
}

// TestEnsureClaudeHook_PreservesUnrelatedHooks: the user already has a
// PreToolUse Bash chain with non-veto entries (rtk-rewrite, etc.).
// Our entry must be appended without disturbing them.
func TestEnsureClaudeHook_PreservesUnrelatedHooks(t *testing.T) {
	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "Bash",
					"hooks": []any{
						map[string]any{"type": "command", "command": "/foo/rtk-rewrite.sh"},
					},
				},
			},
		},
	}
	changed, _ := ensureClaudeHook(settings, "/abs/path/to/veto")
	require.True(t, changed)

	chain := getBashHookChain(t, settings)
	require.Len(t, chain, 2, "rtk-rewrite must still be in the chain")
	require.Equal(t, "/foo/rtk-rewrite.sh", chain[0].(map[string]any)["command"])
	require.Equal(t, "/abs/path/to/veto hook claude-code", chain[1].(map[string]any)["command"])
}

// TestEnsureClaudeHook_Idempotent: running install twice with the same
// veto path is a no-op the second time.
func TestEnsureClaudeHook_Idempotent(t *testing.T) {
	settings := map[string]any{}
	ensureClaudeHook(settings, "/abs/path/to/veto")
	changed, summary := ensureClaudeHook(settings, "/abs/path/to/veto")
	require.False(t, changed)
	require.Equal(t, "hook", summary)
}

// TestEnsureClaudeHook_UpgradesLegacyPython: an existing Python-shebang
// install at .../veto-hook.py must be migrated to the Go subcommand
// in place — same chain position, replaced command.
func TestEnsureClaudeHook_UpgradesLegacyPython(t *testing.T) {
	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "Bash",
					"hooks": []any{
						map[string]any{"type": "command", "command": "/old/path/veto-hook.py"},
					},
				},
			},
		},
	}
	changed, summary := ensureClaudeHook(settings, "/new/veto")
	require.True(t, changed)
	require.Contains(t, summary, "updated")

	chain := getBashHookChain(t, settings)
	require.Len(t, chain, 1, "legacy entry must be replaced in place, not duplicated")
	require.Equal(t, "/new/veto hook claude-code", chain[0].(map[string]any)["command"])
}

// TestEnsureClaudeHook_UpgradesPathChange: veto was reinstalled at a
// different absolute path. Our install must rewrite the command string.
func TestEnsureClaudeHook_UpgradesPathChange(t *testing.T) {
	settings := map[string]any{}
	ensureClaudeHook(settings, "/old/veto")

	changed, summary := ensureClaudeHook(settings, "/new/veto")
	require.True(t, changed)
	require.Contains(t, summary, "updated")
	cmd := getHookCommand(t, settings, "Bash", 0)
	require.Equal(t, "/new/veto hook claude-code", cmd)
}

// TestRemoveClaudeHook_LeavesOtherHooksAlone: uninstall must surgically
// remove our entry while preserving siblings.
func TestRemoveClaudeHook_LeavesOtherHooksAlone(t *testing.T) {
	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "Bash",
					"hooks": []any{
						map[string]any{"type": "command", "command": "/abs/veto hook claude-code"},
						map[string]any{"type": "command", "command": "/foo/rtk-rewrite.sh"},
					},
				},
			},
		},
	}
	require.True(t, removeClaudeHook(settings))
	chain := getBashHookChain(t, settings)
	require.Len(t, chain, 1)
	require.Equal(t, "/foo/rtk-rewrite.sh", chain[0].(map[string]any)["command"])
}

// TestRemoveClaudeHook_StripsEmptyBashMatcher: removing the only hook in
// the Bash chain should also drop the now-empty matcher entry, not leave
// a dangling { matcher: Bash, hooks: [] }.
func TestRemoveClaudeHook_StripsEmptyBashMatcher(t *testing.T) {
	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "Bash",
					"hooks": []any{
						map[string]any{"type": "command", "command": "/abs/veto hook claude-code"},
					},
				},
			},
		},
	}
	require.True(t, removeClaudeHook(settings))
	hooks := settings["hooks"].(map[string]any)
	_, hasPre := hooks["PreToolUse"]
	require.False(t, hasPre, "empty PreToolUse must be dropped after removing the last entry")
}

// TestReadWriteSettings_RoundTrip: writing and re-reading a settings.json
// preserves the entries we just installed.
func TestReadWriteSettings_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")

	settings := map[string]any{
		"model": "opus[1m]",
		"env":   map[string]any{"FOO": "bar"},
	}
	ensureClaudeHook(settings, "/abs/path/to/veto")
	require.NoError(t, writeSettings(path, settings))

	roundTripped, err := readSettings(path)
	require.NoError(t, err)
	require.Equal(t, "opus[1m]", roundTripped["model"])
	require.Equal(t, "bar", roundTripped["env"].(map[string]any)["FOO"])
	chain := getBashHookChain(t, roundTripped)
	require.Len(t, chain, 1)
}

// TestReadSettings_MalformedRefused: rather than silently overwriting
// invalid JSON, readSettings must fail loudly so install-claude-hook
// stops and the user can fix the file by hand.
func TestReadSettings_MalformedRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	require.NoError(t, os.WriteFile(path, []byte("{not valid json"), 0o644))
	_, err := readSettings(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "refusing to overwrite a malformed file")
}

// TestWriteSettings_AtomicReplace: writeSettings should leave a file in
// either pre-write or post-write state, never a half-written truncation.
// We can't easily prove atomicity but we can confirm the file is fully
// re-readable as JSON after a write.
func TestWriteSettings_AtomicReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"model":"old"}`), 0o644))

	settings := map[string]any{"model": "new"}
	require.NoError(t, writeSettings(path, settings))

	buf, err := os.ReadFile(path)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(buf, &m))
	require.Equal(t, "new", m["model"])
}

func getBashHookChain(t *testing.T, settings map[string]any) []any {
	t.Helper()
	hooks := settings["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	for _, raw := range pre {
		entry := raw.(map[string]any)
		if entry["matcher"] == "Bash" {
			return entry["hooks"].([]any)
		}
	}
	t.Fatal("no Bash matcher entry found")
	return nil
}

func getHookCommand(t *testing.T, settings map[string]any, matcher string, idx int) string {
	t.Helper()
	chain := getBashHookChain(t, settings)
	require.Greater(t, len(chain), idx)
	return chain[idx].(map[string]any)["command"].(string)
}

// TestIsVetoHookCommand_TightensBasenameMatching: the old check used
// strings.Contains(cmd, "veto") which would accept ANY command path
// that merely contained the substring "veto". An attacker-planted hook
// command like `/opt/homebrew/bin/notveto-evil hook claude-code` would
// have matched. The tightened check requires the basename of the first
// token to be exactly "veto". Same drift class the install-wrappers
// Layer-4 fix removed; this is the doctor/install-claude-hook side.
func TestIsVetoHookCommand_TightensBasenameMatching(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		{"empty", "", false},
		{"bare veto + hook claude-code", "veto hook claude-code", true},
		{"abs-path veto + hook claude-code", "/usr/local/bin/veto hook claude-code", true},
		{"abs-path veto + hook claude-code + args", "/usr/local/bin/veto hook claude-code --some-flag", true},
		{"quoted veto path with spaces", `"/Users/me/Application Support/veto" hook claude-code`, true},
		{"legacy veto-hook.py", "/opt/veto/veto-hook.py", true},
		{"legacy veto-hook (no extension)", "/usr/local/bin/veto-hook", true},
		// Impostor cases the OLD substring check would have accepted:
		{"impostor: basename embeds veto but is not veto", "/opt/homebrew/bin/notveto-evil hook claude-code", false},
		{"impostor: parent dir embeds veto but exe is not", "/opt/veto-tools/bin/evil hook claude-code", false},
		{"impostor: substring-only veto in arg", "/opt/homebrew/bin/evil hook claude-code /opt/veto-decoy", false},
		// Not a veto command at all.
		{"unrelated rtk-rewrite hook", "/usr/local/bin/rtk-rewrite", false},
		{"veto basename but no hook subcommand", "/usr/local/bin/veto status", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, isVetoHookCommand(tc.cmd))
		})
	}
}
