package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestHasVetoClaudeHook covers the matrix of settings.json shapes the
// doctor must understand: a new-style "veto hook claude-code" entry,
// a legacy python-shebang entry, a non-veto-Bash hook (rtk-rewrite,
// etc.), and a completely unconfigured file.
func TestHasVetoClaudeHook(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
		want     bool
	}{
		{
			name:     "no hooks block",
			settings: map[string]any{"model": "opus"},
			want:     false,
		},
		{
			name: "Bash chain present but no veto entry",
			settings: map[string]any{
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
			},
			want: false,
		},
		{
			name: "new-style in-binary hook",
			settings: map[string]any{
				"hooks": map[string]any{
					"PreToolUse": []any{
						map[string]any{
							"matcher": "Bash",
							"hooks": []any{
								map[string]any{"type": "command", "command": "/Users/x/.local/bin/veto hook claude-code"},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "legacy python shebang",
			settings: map[string]any{
				"hooks": map[string]any{
					"PreToolUse": []any{
						map[string]any{
							"matcher": "Bash",
							"hooks": []any{
								map[string]any{"type": "command", "command": "/Users/x/.claude/hooks/veto-hook.py"},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "veto hook present in a non-Bash matcher does NOT count",
			settings: map[string]any{
				"hooks": map[string]any{
					"PreToolUse": []any{
						map[string]any{
							"matcher": "Edit",
							"hooks": []any{
								map[string]any{"type": "command", "command": "/x/veto hook claude-code"},
							},
						},
					},
				},
			},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, hasVetoClaudeHook(c.settings))
		})
	}
}

// TestPrintResults_ColorMarkers spot-checks that PASS/WARN/FAIL produce
// distinct ANSI markers. We don't assert exact escape sequences (those
// could change), just that they differ.
func TestPrintResults_ColorMarkers(t *testing.T) {
	var buf bytes.Buffer
	results := []checkResult{
		{status: statusPass, label: "happy", detail: "ok"},
		{status: statusWarn, label: "soft", detail: "partial", howToFix: "do X"},
		{status: statusFail, label: "broken", detail: "no go", howToFix: "do Y"},
	}
	printResults(&buf, results)
	out := buf.String()
	require.Contains(t, out, "PASS")
	require.Contains(t, out, "WARN")
	require.Contains(t, out, "FAIL")
	require.Contains(t, out, "do X")
	require.Contains(t, out, "do Y")
	// PASS entries print their label/detail but never a how-to-fix arrow.
	require.Contains(t, out, "happy")
	require.Contains(t, out, "ok")
	// Exactly two `→` lines (one per non-PASS entry).
	require.Equal(t, 2, strings.Count(out, "→"), "exactly the WARN+FAIL entries should emit a fix arrow")
}

func TestCheckShellIntegrationFromDetectedRC(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SHELL", "/bin/zsh")
	shimDir := filepath.Join(dir, ".local", "bin")
	vetoPath := filepath.Join(shimDir, "veto")
	for _, target := range []struct {
		name string
		kind shellKind
	}{
		{name: ".zshrc", kind: shellKindZsh},
		{name: ".bashrc", kind: shellKindBash},
		{name: ".bash_profile", kind: shellKindBash},
		{name: ".profile", kind: shellKindProfile},
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, target.name), []byte(renderShellIntegrationBlock(shimDir, vetoPath, target.kind)), 0o644))
	}

	got := checkShellIntegration()
	require.Equal(t, statusPass, got.status)
	require.Equal(t, "shell integration", got.label)
}

func TestCheckShellIntegrationWarnsWhenMissing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SHELL", "/bin/zsh")
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".zshrc"), []byte("alias g=git\n"), 0o644))

	got := checkShellIntegration()
	require.Equal(t, statusWarn, got.status)
	require.Contains(t, got.howToFix, "install-shell")
}

func TestCheckShellIntegrationWarnsWhenOneBashFileMissing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SHELL", "/bin/zsh")
	shimDir := filepath.Join(dir, ".local", "bin")
	vetoPath := filepath.Join(shimDir, "veto")
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".zshrc"), []byte(renderShellIntegrationBlock(shimDir, vetoPath, shellKindZsh)), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".bashrc"), []byte(renderShellIntegrationBlock(shimDir, vetoPath, shellKindBash)), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".profile"), []byte(renderShellIntegrationBlock(shimDir, vetoPath, shellKindProfile)), 0o644))

	got := checkShellIntegration()
	require.Equal(t, statusWarn, got.status)
	require.Contains(t, got.detail, ".bash_profile")
}

// TestEarlierRealBinary covers the "shim shadowed by mise/homebrew"
// detection: a real `npm` earlier in PATH than our shim dir must be
// flagged. A `veto`-pointing symlink earlier in PATH is NOT a
// conflict (the user has veto installed in a non-default place).
func TestEarlierRealBinary(t *testing.T) {
	dir := t.TempDir()
	mise := filepath.Join(dir, "mise-shims")
	user := filepath.Join(dir, "user-bin")
	for _, d := range []string{mise, user} {
		require.NoError(t, mkdir(d))
	}
	// Real npm in mise dir.
	realNpm := filepath.Join(mise, "npm")
	require.NoError(t, writeFile(realNpm, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	pathParts := []string{mise, user}
	shimIdx := 1 // user is the shim dir (last)
	got := earlierRealBinary("npm", pathParts, shimIdx)
	require.Equal(t, realNpm, got)

	// No conflict for a binary that doesn't exist earlier.
	got = earlierRealBinary("pip", pathParts, shimIdx)
	require.Equal(t, "", got)
}

// TestDetectVersionManager: the doctor recognises the canonical
// install/shim dirs of the version managers we know how to advise about.
// Misclassification would either suppress useful advice (false negative)
// or print a misleading recipe (false positive) — both worse than the
// generic fallback.
func TestDetectVersionManager(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/Users/x/.local/share/mise/installs/node/20.0.0/bin/npm", "mise"},
		{"/Users/x/.local/share/mise/shims/npm", "mise"},
		{"/Users/x/.asdf/installs/python/3.11.0/bin/pip", "asdf"},
		{"/Users/x/.asdf/shims/pip", "asdf"},
		{"/Users/x/.pyenv/shims/python", "pyenv"},
		{"/Users/x/.pyenv/versions/3.11.0/bin/python", "pyenv"},
		{"/Users/x/.nvm/versions/node/20.0.0/bin/npm", "nvm"},
		// Not a version manager dir: must NOT misclassify.
		{"/opt/homebrew/bin/npm", ""},
		{"/usr/local/bin/npm", ""},
		{"/Users/x/.local/bin/npm", ""},
		// Substring "mise" without the directory shape must NOT match.
		{"/Users/x/.local/bin/promise-checker", ""},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			require.Equal(t, c.want, detectVersionManager(c.path))
		})
	}
}

// TestPrintVersionManagerFooters_DedupesPerManager: ten mise-shadowed
// shims should still produce only one mise footer block, not ten.
func TestPrintVersionManagerFooters_DedupesPerManager(t *testing.T) {
	var buf bytes.Buffer
	results := []checkResult{
		{status: statusFail, label: "shim:npm", detail: "mise install at /x shadows the veto shim"},
		{status: statusFail, label: "shim:pnpm", detail: "mise install at /y shadows the veto shim"},
		{status: statusFail, label: "shim:yarn", detail: "mise install at /z shadows the veto shim"},
	}
	printVersionManagerFooters(&buf, results)
	out := buf.String()
	require.Equal(t, 1, strings.Count(out, "mise PATH-ordering recipe"),
		"a multi-mise-shadow doctor run must print the footer exactly once")
	require.Contains(t, out, "veto install-shell")
	require.Contains(t, out, "managed block", "chpwd-hook workaround must be delegated to the managed block")
}

// TestPrintVersionManagerFooters_OnlyOnFail: a PASS result that happens
// to mention "mise" (e.g. a shim whose mise-version is healthy) must
// NOT trigger the footer.
func TestPrintVersionManagerFooters_OnlyOnFail(t *testing.T) {
	var buf bytes.Buffer
	results := []checkResult{
		{status: statusPass, label: "shim:npm", detail: "mise-installed but healthy"},
	}
	printVersionManagerFooters(&buf, results)
	require.Empty(t, buf.String())
}

// TestPrintVersionManagerFooters_OnlyForRecognizedManagers: a FAIL
// whose detail names some other tool must not produce a footer block.
func TestPrintVersionManagerFooters_OnlyForRecognizedManagers(t *testing.T) {
	var buf bytes.Buffer
	results := []checkResult{
		{status: statusFail, label: "shim:npm", detail: "rbenv install at /x shadows the veto shim"},
	}
	printVersionManagerFooters(&buf, results)
	require.Empty(t, buf.String(), "no footer for unrecognised version managers — fall through to generic advice")
}

// Small file-IO helpers used by the earlier-real-binary test.
func mkdir(p string) error                                 { return os.MkdirAll(p, 0o755) }
func writeFile(p string, data []byte, m os.FileMode) error { return os.WriteFile(p, data, m) }
