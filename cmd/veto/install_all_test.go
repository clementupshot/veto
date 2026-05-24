package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseInstallAllFlags(t *testing.T) {
	opts, err := parseInstallAllFlags([]string{"--lib", "/tmp/lib.dylib", "--shell-rc=auto", "--force", "--skip-interposer"})
	require.NoError(t, err)
	require.Equal(t, "/tmp/lib.dylib", opts.libPath)
	require.True(t, opts.autoRC)
	require.True(t, opts.force)
	require.True(t, opts.skipInterpos)

	_, err = parseInstallAllFlags([]string{"--bad"})
	require.Error(t, err)
}

func TestShellRCArgsDefaultsToAuto(t *testing.T) {
	opts := installAllOpts{autoRC: true}
	require.Equal(t, []string{"--shell-rc", "auto"}, shellRCArgs(opts))

	opts = installAllOpts{shellRC: "/tmp/.zshrc", autoRC: true}
	require.Equal(t, []string{"--shell-rc", "/tmp/.zshrc"}, shellRCArgs(opts))
}

func TestPinPathEnvMovesShimDirToFront(t *testing.T) {
	sep := string(os.PathListSeparator)
	got := pinPathEnv(strings.Join([]string{"/usr/bin", "/Users/x/.local/bin", "/bin"}, sep), "/Users/x/.local/bin")
	require.Equal(t, strings.Join([]string{"/Users/x/.local/bin", "/usr/bin", "/bin"}, sep), got)
}

func TestFindInterposerArtifactExplicit(t *testing.T) {
	dir := t.TempDir()
	name := "libveto_interpose.dylib"
	if runtime.GOOS != "darwin" {
		name = "libveto_interpose.so"
	}
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o644))

	got, err := findInterposerArtifact(path)
	require.NoError(t, err)
	require.Equal(t, path, got)
}
