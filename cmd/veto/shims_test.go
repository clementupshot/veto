package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEnsureShim covers the four states ensureShim can encounter at the
// target path: missing, already-correct symlink, symlink-to-something-else,
// and regular file. The --force toggle decides the last two.
func TestEnsureShim(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto-binary")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\n"), 0o755))

	t.Run("creates symlink when target missing", func(t *testing.T) {
		target := filepath.Join(dir, "npm-1")
		action, err := ensureShim(target, veto, false)
		require.NoError(t, err)
		require.Contains(t, action, "created")
		linked, err := os.Readlink(target)
		require.NoError(t, err)
		require.Equal(t, veto, linked)
	})

	t.Run("no-op when already correct", func(t *testing.T) {
		target := filepath.Join(dir, "npm-2")
		require.NoError(t, os.Symlink(veto, target))
		action, err := ensureShim(target, veto, false)
		require.NoError(t, err)
		require.Empty(t, action, "expected silent no-op when symlink is already correct")
	})

	t.Run("refuses to replace symlink pointing elsewhere without force", func(t *testing.T) {
		target := filepath.Join(dir, "npm-3")
		other := filepath.Join(dir, "some-other-binary")
		require.NoError(t, os.WriteFile(other, []byte(""), 0o755))
		require.NoError(t, os.Symlink(other, target))
		_, err := ensureShim(target, veto, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "symlink points elsewhere")
	})

	t.Run("force replaces symlink pointing elsewhere", func(t *testing.T) {
		target := filepath.Join(dir, "npm-4")
		other := filepath.Join(dir, "some-other-binary-2")
		require.NoError(t, os.WriteFile(other, []byte(""), 0o755))
		require.NoError(t, os.Symlink(other, target))
		action, err := ensureShim(target, veto, true)
		require.NoError(t, err)
		require.Contains(t, action, "updated")
		linked, err := os.Readlink(target)
		require.NoError(t, err)
		require.Equal(t, veto, linked)
	})

	t.Run("refuses to overwrite a regular file without force", func(t *testing.T) {
		target := filepath.Join(dir, "npm-5")
		require.NoError(t, os.WriteFile(target, []byte("real binary"), 0o755))
		_, err := ensureShim(target, veto, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "file exists and is not a symlink")
		// Confirm we didn't touch it:
		content, _ := os.ReadFile(target)
		require.Equal(t, "real binary", string(content))
	})

	t.Run("force replaces a regular file", func(t *testing.T) {
		target := filepath.Join(dir, "npm-6")
		require.NoError(t, os.WriteFile(target, []byte("real binary"), 0o755))
		action, err := ensureShim(target, veto, true)
		require.NoError(t, err)
		require.Contains(t, action, "updated")
		linked, err := os.Readlink(target)
		require.NoError(t, err)
		require.Equal(t, veto, linked)
	})
}

// TestEnsureShim_Force_RenamesRealBinary proves --force preserves any
// pre-existing real binary at the target path by renaming it to
// <target>.veto-displaced rather than deleting it. Closes the L2
// reviewer's "silently destroys homebrew npm" finding.
func TestEnsureShim_Force_RenamesRealBinary(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto-binary")
	require.NoError(t, os.WriteFile(veto, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	target := filepath.Join(dir, "npm")
	realBinary := []byte("#!/bin/sh\necho real-npm\n")
	require.NoError(t, os.WriteFile(target, realBinary, 0o755))

	action, err := ensureShim(target, veto, true)
	require.NoError(t, err)
	require.Contains(t, action, "updated")

	// Target is now a symlink to veto.
	resolved, err := os.Readlink(target)
	require.NoError(t, err)
	require.Equal(t, veto, resolved)

	// Real binary preserved at .veto-displaced.
	got, err := os.ReadFile(target + ".veto-displaced")
	require.NoError(t, err)
	require.Equal(t, realBinary, got, "real binary must be renamed, not deleted")
}

// TestRemoveShim_RestoresDisplacedBinary proves uninstall-shims puts
// the displaced binary back at its original path.
func TestRemoveShim_RestoresDisplacedBinary(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto-binary")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))

	target := filepath.Join(dir, "npm")
	original := []byte("real-npm-bytes")
	require.NoError(t, os.WriteFile(target, original, 0o755))

	_, err := ensureShim(target, veto, true)
	require.NoError(t, err)
	// Now: target is symlink, target.veto-displaced has original bytes.

	removed, err := removeShim(target, veto)
	require.NoError(t, err)
	require.True(t, removed)

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, original, got, "removeShim must restore the displaced real binary")
	_, statErr := os.Lstat(target + ".veto-displaced")
	require.True(t, os.IsNotExist(statErr), ".veto-displaced must be gone after restore")
}

func TestRemoveShim(t *testing.T) {
	dir := t.TempDir()
	veto := filepath.Join(dir, "veto-binary")
	require.NoError(t, os.WriteFile(veto, []byte(""), 0o755))

	t.Run("removes a veto-pointing symlink", func(t *testing.T) {
		target := filepath.Join(dir, "npm-r1")
		require.NoError(t, os.Symlink(veto, target))
		removed, err := removeShim(target, veto)
		require.NoError(t, err)
		require.True(t, removed)
		_, statErr := os.Lstat(target)
		require.True(t, os.IsNotExist(statErr))
	})

	t.Run("skips a symlink pointing elsewhere", func(t *testing.T) {
		target := filepath.Join(dir, "npm-r2")
		other := filepath.Join(dir, "some-other")
		require.NoError(t, os.WriteFile(other, []byte(""), 0o755))
		require.NoError(t, os.Symlink(other, target))
		removed, err := removeShim(target, veto)
		require.NoError(t, err)
		require.False(t, removed)
		// Symlink still in place:
		_, statErr := os.Lstat(target)
		require.NoError(t, statErr)
	})

	t.Run("skips a regular file", func(t *testing.T) {
		target := filepath.Join(dir, "npm-r3")
		require.NoError(t, os.WriteFile(target, []byte("real binary"), 0o755))
		removed, err := removeShim(target, veto)
		require.NoError(t, err)
		require.False(t, removed)
	})

	t.Run("skips missing target without error", func(t *testing.T) {
		target := filepath.Join(dir, "missing")
		removed, err := removeShim(target, veto)
		require.NoError(t, err)
		require.False(t, removed)
	})
}

func TestIsShimName(t *testing.T) {
	// Spot-check that the dispatch table matches the install set. If these
	// drift apart, `veto install-shims` would create a symlink that the
	// shim-dispatch code wouldn't recognize.
	for _, name := range shimmedManagers {
		require.True(t, isShimName(name), "isShimName must recognize %s", name)
	}
	require.False(t, isShimName("veto"))
	require.False(t, isShimName(""))
}
