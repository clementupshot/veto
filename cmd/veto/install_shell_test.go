package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestRenderPOSIXShellIntegrationBlock(t *testing.T) {
	block := renderShellIntegrationBlock("/Users/x/.local/bin", "/Users/x/.local/bin/veto", shellKindZsh)
	require.Contains(t, block, shellMarkerStart)
	require.Contains(t, block, shellMarkerEnd)
	require.Contains(t, block, "_veto_pin_path")
	require.Contains(t, block, "precmd_functions+=(_veto_pin_path)")
	require.NotContains(t, block, "_bouncer_pin_path")
	require.Contains(t, block, "PIP_UPLOADED_PRIOR_TO")
	require.Contains(t, block, "UV_EXCLUDE_NEWER")
	require.Contains(t, block, "_veto_bin='/Users/x/.local/bin/veto'")
	require.Contains(t, block, "\"$_veto_bin\" pip")
	require.Contains(t, block, "\"$_veto_bin\" uv")
	require.NotContains(t, block, "typeset -U path PATH 2>/dev/null || true")
	// Phase 1.3: user-set env wins over the 3-day default. The `:-`
	// expansion only fires when the var is unset OR empty, which
	// matches the behavior we want (a user passing
	// PIP_UPLOADED_PRIOR_TO= explicitly empty also gets the default,
	// which is a safe over-block).
	require.Contains(t, block, "${PIP_UPLOADED_PRIOR_TO:-",
		"wrapper must honor user-set PIP_UPLOADED_PRIOR_TO via :- default expansion")
	require.Contains(t, block, "${UV_EXCLUDE_NEWER:-",
		"wrapper must honor user-set UV_EXCLUDE_NEWER via :- default expansion")
}

func TestRenderBashShellIntegrationBlock(t *testing.T) {
	block := renderShellIntegrationBlock("/Users/x/.local/bin", "/Users/x/.local/bin/veto", shellKindBash)
	require.Contains(t, block, "PROMPT_COMMAND")
	require.NotContains(t, block, "precmd_functions")
	require.Contains(t, block, "${PATH//$_veto_shim_dir:/}")
}

func TestRenderProfileShellIntegrationBlockIsPortable(t *testing.T) {
	block := renderShellIntegrationBlock("/Users/x/.local/bin", "/Users/x/.local/bin/veto", shellKindProfile)
	require.Contains(t, block, "for _veto_path_part in $PATH")
	require.NotContains(t, block, "${PATH//")
}

func TestRenderFishShellIntegrationBlock(t *testing.T) {
	block := renderShellIntegrationBlock("/Users/x/.local/bin", "/Users/x/.local/bin/veto", shellKindFish)
	require.Contains(t, block, "fish_add_path --move --prepend")
	require.Contains(t, block, "--on-event fish_prompt")
	require.Contains(t, block, "set -gx _veto_bin")
	require.Contains(t, block, "function uv")
	require.Contains(t, block, "$_veto_bin uv")
	// Phase 1.3: user-set env wins. Fish's `set -q VAR; or set VAR …`
	// idiom mirrors the bash/zsh ${VAR:-default} pattern.
	require.Contains(t, block, "set -q PIP_UPLOADED_PRIOR_TO; or set",
		"fish wrapper must honor user-set PIP_UPLOADED_PRIOR_TO via set -q guard")
	require.Contains(t, block, "set -q UV_EXCLUDE_NEWER; or set",
		"fish wrapper must honor user-set UV_EXCLUDE_NEWER via set -q guard")
}

func TestRenderPOSIXShellIntegrationBlockParsesInZshAndBash(t *testing.T) {
	cases := []struct {
		shell string
		kind  shellKind
	}{
		{shell: "zsh", kind: shellKindZsh},
		{shell: "bash", kind: shellKindBash},
		{shell: "sh", kind: shellKindProfile},
	}
	for _, tc := range cases {
		block := renderShellIntegrationBlock("/Users/x/.local/bin", "/Users/x/.local/bin/veto", tc.kind)
		shellPath, err := exec.LookPath(tc.shell)
		if err != nil {
			t.Skipf("%s not available", tc.shell)
		}
		cmd := exec.Command(shellPath, "-n")
		cmd.Stdin = strings.NewReader(block)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s rejected generated shell block:\n%s", tc.shell, out)
	}
}

func TestUpsertShellIntegrationBlockReplacesExisting(t *testing.T) {
	dir := t.TempDir()
	rc := filepath.Join(dir, ".zshrc")
	oldBlock := shellMarkerStart + "\nold\n" + shellMarkerEnd + "\n"
	require.NoError(t, os.WriteFile(rc, []byte("before\n"+oldBlock+"after\n"), 0o644))

	newBlock := renderShellIntegrationBlock("/Users/x/.local/bin", "/Users/x/.local/bin/veto", shellKindZsh)
	require.NoError(t, upsertShellIntegrationBlock(rc, newBlock))
	out, err := os.ReadFile(rc)
	require.NoError(t, err)
	s := string(out)
	require.Contains(t, s, "before")
	require.Contains(t, s, "after")
	require.NotContains(t, s, "old")
	require.Equal(t, 1, strings.Count(s, shellMarkerStart))
}

func TestManagedBlockStatus(t *testing.T) {
	dir := t.TempDir()
	rc := filepath.Join(dir, ".zshrc")
	require.NoError(t, os.WriteFile(rc, []byte(shellMarkerStart+"\nbody\n"+shellMarkerEnd+"\n"), 0o644))
	exists, malformed, err := managedBlockStatus(rc, shellMarkerStart, shellMarkerEnd)
	require.NoError(t, err)
	require.True(t, exists)
	require.False(t, malformed)

	broken := filepath.Join(dir, "broken")
	require.NoError(t, os.WriteFile(broken, []byte(shellMarkerStart+"\nbody\n"), 0o644))
	exists, malformed, err = managedBlockStatus(broken, shellMarkerStart, shellMarkerEnd)
	require.NoError(t, err)
	require.False(t, exists)
	require.True(t, malformed)
}

func TestParseShellFlags(t *testing.T) {
	opts, err := parseShellFlags([]string{"--shell-rc=auto", "--print"})
	require.NoError(t, err)
	require.True(t, opts.autoRC)
	require.True(t, opts.print)

	_, err = parseShellFlags([]string{"--wat"})
	require.Error(t, err)
}

func TestShellKindForRC(t *testing.T) {
	require.Equal(t, shellKindFish, shellKindForRC("/Users/x/.config/fish/config.fish"))
	require.Equal(t, shellKindZsh, shellKindForRC("/Users/x/.zshrc"))
	require.Equal(t, shellKindBash, shellKindForRC("/Users/x/.bash_profile"))
	require.Equal(t, shellKindProfile, shellKindForRC("/Users/x/.profile"))
	require.Equal(t, shellKindZsh, shellKindForRC("/Users/x/fishsticks/.zshrc"))
}

func TestInstallShellDefaultsToDetectedRCAndBashFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SHELL", "/bin/zsh")
	rc := filepath.Join(dir, ".zshrc")
	require.NoError(t, os.WriteFile(rc, []byte("alias g=git\n"), 0o644))

	got := runInstallShell(zerolog.Nop(), nil)
	require.Equal(t, exitOK, got)
	out, err := os.ReadFile(rc)
	require.NoError(t, err)
	require.Contains(t, string(out), shellMarkerStart)
	require.Contains(t, string(out), "_veto_pin_path")
	for _, name := range []string{".bashrc", ".bash_profile", ".profile"} {
		out, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		require.Contains(t, string(out), shellMarkerStart)
	}
}

func TestDefaultShellIntegrationTargetsIncludesBashFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SHELL", "/bin/zsh")

	targets, err := defaultShellIntegrationTargets()
	require.NoError(t, err)
	got := make([]string, 0, len(targets))
	for _, target := range targets {
		got = append(got, filepath.Base(target.path))
	}
	require.Contains(t, got, ".zshrc")
	require.Contains(t, got, ".bashrc")
	require.Contains(t, got, ".bash_profile")
	require.Contains(t, got, ".profile")
}
