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
