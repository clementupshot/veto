package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestApplyWrapper_HappyPath_RegularFile is the canonical case: a real
// PM binary sits at <dir>/<pm> as a regular file. We move it aside and
// drop a bouncer symlink in its place.
func TestApplyWrapper_HappyPath_RegularFile(t *testing.T) {
	dir := t.TempDir()
	bouncer := filepath.Join(dir, "bouncer")
	require.NoError(t, os.WriteFile(bouncer, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	npm := filepath.Join(dir, "npm")
	require.NoError(t, os.WriteFile(npm, []byte("#!/bin/sh\nexec real-npm\n"), 0o755))

	c := wrapCandidate{path: npm, pm: "npm", source: "user"}
	action, err := applyWrapper(c, bouncer, false, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionWrapped, action)

	// npm is now a symlink to bouncer.
	info, err := os.Lstat(npm)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink)
	target, _ := os.Readlink(npm)
	require.Equal(t, bouncer, target)

	// .bouncer-original holds the real npm.
	original := npm + ".bouncer-original"
	body, err := os.ReadFile(original)
	require.NoError(t, err)
	require.Contains(t, string(body), "real-npm")
}

// TestApplyWrapper_HappyPath_SymlinkSource exercises the homebrew shape:
// /opt/homebrew/bin/npm is a symlink to ../Cellar/.../bin/npm. Wrapping
// must rename the SYMLINK aside (keeping its target intact) and replace
// the original path with a bouncer symlink.
func TestApplyWrapper_HappyPath_SymlinkSource(t *testing.T) {
	dir := t.TempDir()
	bouncer := filepath.Join(dir, "bouncer")
	require.NoError(t, os.WriteFile(bouncer, []byte(""), 0o755))

	cellar := filepath.Join(dir, "cellar-npm")
	require.NoError(t, os.WriteFile(cellar, []byte("real"), 0o755))
	binNpm := filepath.Join(dir, "npm")
	require.NoError(t, os.Symlink(cellar, binNpm))

	c := wrapCandidate{path: binNpm, pm: "npm", source: "homebrew"}
	action, err := applyWrapper(c, bouncer, false, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionWrapped, action)

	// Symlink at original path now points at bouncer.
	target, _ := os.Readlink(binNpm)
	require.Equal(t, bouncer, target)

	// `.bouncer-original` preserves the homebrew→Cellar symlink (so
	// upgrades that update the symlink target still work after unwrap).
	originalTarget, err := os.Readlink(binNpm + ".bouncer-original")
	require.NoError(t, err)
	require.Equal(t, cellar, originalTarget)
}

// TestApplyWrapper_IdempotentOnSecondCall: re-running install must not
// double-wrap or corrupt state.
func TestApplyWrapper_IdempotentOnSecondCall(t *testing.T) {
	dir := t.TempDir()
	bouncer := filepath.Join(dir, "bouncer")
	require.NoError(t, os.WriteFile(bouncer, []byte(""), 0o755))
	pip := filepath.Join(dir, "pip")
	require.NoError(t, os.WriteFile(pip, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	c := wrapCandidate{path: pip, pm: "pip", source: "user"}
	_, err := applyWrapper(c, bouncer, false, false)
	require.NoError(t, err)

	action, err := applyWrapper(c, bouncer, false, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionSkipAlreadyOurs, action)
}

// TestApplyWrapper_RefusesToClobberPartialState: if `.bouncer-original`
// exists but the symlink is gone (interrupted previous run), we refuse
// to silently clobber the .bouncer-original. --force overrides.
func TestApplyWrapper_RefusesToClobberPartialState(t *testing.T) {
	dir := t.TempDir()
	bouncer := filepath.Join(dir, "bouncer")
	require.NoError(t, os.WriteFile(bouncer, []byte(""), 0o755))
	pnpm := filepath.Join(dir, "pnpm")
	require.NoError(t, os.WriteFile(pnpm, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	require.NoError(t, os.WriteFile(pnpm+".bouncer-original", []byte("stale"), 0o644))

	c := wrapCandidate{path: pnpm, pm: "pnpm", source: "user"}
	_, err := applyWrapper(c, bouncer, false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")

	// --force overrides.
	_, err = applyWrapper(c, bouncer, false, true)
	require.NoError(t, err)
}

// TestApplyWrapper_DryRun_TouchesNothing: --dry-run mode reports what
// would happen without making filesystem changes.
func TestApplyWrapper_DryRun_TouchesNothing(t *testing.T) {
	dir := t.TempDir()
	bouncer := filepath.Join(dir, "bouncer")
	require.NoError(t, os.WriteFile(bouncer, []byte(""), 0o755))
	pip := filepath.Join(dir, "pip")
	originalBody := []byte("#!/bin/sh\nexec real\n")
	require.NoError(t, os.WriteFile(pip, originalBody, 0o755))

	c := wrapCandidate{path: pip, pm: "pip", source: "user"}
	action, err := applyWrapper(c, bouncer, true, false)
	require.NoError(t, err)
	require.Equal(t, wrapperActionSkipDryRun, action)

	// File unchanged.
	body, err := os.ReadFile(pip)
	require.NoError(t, err)
	require.Equal(t, originalBody, body)
	_, err = os.Lstat(pip + ".bouncer-original")
	require.True(t, os.IsNotExist(err), "dry-run must not create .bouncer-original")
}

// TestUnwrap_RestoresOriginal: the canonical unwrap path.
func TestUnwrap_RestoresOriginal(t *testing.T) {
	dir := t.TempDir()
	bouncer := filepath.Join(dir, "bouncer")
	require.NoError(t, os.WriteFile(bouncer, []byte(""), 0o755))
	npm := filepath.Join(dir, "npm")
	realBody := []byte("#!/bin/sh\nexec real-npm\n")
	require.NoError(t, os.WriteFile(npm, realBody, 0o755))

	c := wrapCandidate{path: npm, pm: "npm", source: "user"}
	_, err := applyWrapper(c, bouncer, false, false)
	require.NoError(t, err)

	entry := wrapperEntry{
		Path:         npm,
		OriginalPath: npm + ".bouncer-original",
		PM:           "npm",
		Source:       "user",
	}
	require.NoError(t, unwrap(entry, false))

	// npm is once again a regular file with the original body.
	info, err := os.Lstat(npm)
	require.NoError(t, err)
	require.Zero(t, info.Mode()&os.ModeSymlink)
	body, _ := os.ReadFile(npm)
	require.Equal(t, realBody, body)
	// .bouncer-original is gone.
	_, err = os.Lstat(npm + ".bouncer-original")
	require.True(t, os.IsNotExist(err))
}

// TestUnwrap_BailsIfSymlinkRetargeted: if something (brew upgrade?)
// replaced our symlink with a non-bouncer target between install and
// uninstall, unwrap must NOT clobber. Stale .bouncer-original is left
// for manual cleanup.
func TestUnwrap_BailsIfSymlinkRetargeted(t *testing.T) {
	dir := t.TempDir()
	npm := filepath.Join(dir, "npm")
	other := filepath.Join(dir, "other")
	require.NoError(t, os.WriteFile(other, []byte(""), 0o755))
	require.NoError(t, os.Symlink(other, npm)) // not pointing at bouncer

	original := npm + ".bouncer-original"
	require.NoError(t, os.WriteFile(original, []byte("orig"), 0o755))

	entry := wrapperEntry{Path: npm, OriginalPath: original, PM: "npm"}
	err := unwrap(entry, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no longer points at bouncer")

	// Symlink and .bouncer-original both intact.
	target, _ := os.Readlink(npm)
	require.Equal(t, other, target)
	_, err = os.Stat(original)
	require.NoError(t, err)
}

// TestFindWrappedOriginal exercises the resolver used by execReal. When
// bouncer is invoked through a wrapper symlink, argv[0] is the wrapper
// path; we want to find the sibling `.bouncer-original`.
func TestFindWrappedOriginal(t *testing.T) {
	dir := t.TempDir()
	pip := filepath.Join(dir, "pip")
	original := pip + ".bouncer-original"
	require.NoError(t, os.WriteFile(original, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	got, ok := findWrappedOriginal(pip)
	require.True(t, ok, "should find sibling .bouncer-original")
	require.Equal(t, original, got)

	// Path with no separator (bare name) — must NOT match. Bare names
	// don't reach the wrapper-resolver; they go through PATH lookup.
	got, ok = findWrappedOriginal("pip")
	require.False(t, ok)
	require.Empty(t, got)

	// Sibling missing — must return false.
	noOriginal := filepath.Join(dir, "yarn")
	require.NoError(t, os.WriteFile(noOriginal, []byte(""), 0o755))
	_, ok = findWrappedOriginal(noOriginal)
	require.False(t, ok, "no .bouncer-original sibling means no wrapper")
}

// TestWrapperState_RoundTrip: state file survives a save/load cycle.
func TestWrapperState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := config{CacheDir: dir}

	state := wrapperState{}
	state.add(wrapperEntry{Path: "/opt/homebrew/bin/npm", OriginalPath: "/opt/homebrew/bin/npm.bouncer-original", PM: "npm", Source: "homebrew"})
	state.add(wrapperEntry{Path: "/x/uv", OriginalPath: "/x/uv.bouncer-original", PM: "uv", Source: "mise"})

	require.NoError(t, saveWrapperState(cfg, state))

	loaded, err := loadWrapperState(cfg)
	require.NoError(t, err)
	require.Len(t, loaded.Wrappers, 2)
	require.Equal(t, "/opt/homebrew/bin/npm", loaded.Wrappers[0].Path)
	require.Equal(t, "uv", loaded.Wrappers[1].PM)
}

// TestWrapperState_AddIsIdempotent: re-adding the same Path updates in
// place rather than duplicating the entry. This matches install-wrappers
// being re-run after an upgrade.
func TestWrapperState_AddIsIdempotent(t *testing.T) {
	state := wrapperState{}
	state.add(wrapperEntry{Path: "/x/npm", PM: "npm", Source: "homebrew"})
	state.add(wrapperEntry{Path: "/x/npm", PM: "npm", Source: "homebrew", OriginalPath: "/x/npm.bouncer-original"})
	require.Len(t, state.Wrappers, 1, "duplicate Path entry must replace, not append")
	require.Equal(t, "/x/npm.bouncer-original", state.Wrappers[0].OriginalPath)
}

// TestLoadWrapperState_MissingFile_ReturnsEmpty: first-run experience —
// no state file yet means an empty state, not an error.
func TestLoadWrapperState_MissingFile_ReturnsEmpty(t *testing.T) {
	cfg := config{CacheDir: t.TempDir()}
	state, err := loadWrapperState(cfg)
	require.NoError(t, err)
	require.Empty(t, state.Wrappers)
}

// TestLoadWrapperState_MalformedJSON_Errors: a corrupted state file
// should fail loud rather than silently treat as empty (which would
// leave wrappers stranded with no record of how to undo them).
func TestLoadWrapperState_MalformedJSON_Errors(t *testing.T) {
	dir := t.TempDir()
	cfg := config{CacheDir: dir}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wrappers.json"), []byte("{not json"), 0o644))
	_, err := loadWrapperState(cfg)
	require.Error(t, err)
}

// TestIsWrappableTarget_FiltersCorrectly: the discovery helper that
// decides whether a candidate is something we should wrap. Critical
// because false positives (wrapping our own symlink) cause loops.
func TestIsWrappableTarget_FiltersCorrectly(t *testing.T) {
	dir := t.TempDir()

	regular := filepath.Join(dir, "regular")
	require.NoError(t, os.WriteFile(regular, []byte("#!/bin/sh\n"), 0o755))
	require.True(t, isWrappableTarget(regular), "regular executable should be wrappable")

	notExec := filepath.Join(dir, "notexec")
	require.NoError(t, os.WriteFile(notExec, []byte(""), 0o644))
	require.False(t, isWrappableTarget(notExec), "non-executable should be skipped")

	bouncerSym := filepath.Join(dir, "bouncer-shim")
	bouncer := filepath.Join(dir, "bouncer")
	require.NoError(t, os.WriteFile(bouncer, []byte(""), 0o755))
	require.NoError(t, os.Symlink(bouncer, bouncerSym))
	require.False(t, isWrappableTarget(bouncerSym), "already-bouncer symlink must NOT be re-wrappable")

	cellarTarget := filepath.Join(dir, "cellar-real")
	require.NoError(t, os.WriteFile(cellarTarget, []byte(""), 0o755))
	homebrewLink := filepath.Join(dir, "homebrew-link")
	require.NoError(t, os.Symlink(cellarTarget, homebrewLink))
	require.True(t, isWrappableTarget(homebrewLink), "homebrew-style real symlink IS wrappable")

	dirPath := filepath.Join(dir, "subdir")
	require.NoError(t, os.Mkdir(dirPath, 0o755))
	require.False(t, isWrappableTarget(dirPath), "directories must not be wrappable")
}

// TestRunInstallWrappers_EndToEnd: drive runInstallWrappers against a
// synthetic install dir, verify wrapping happened, then drive
// runUninstallWrappers and verify it all reverses cleanly.
func TestRunInstallWrappers_EndToEnd(t *testing.T) {
	// Synthetic env: a tempdir containing a fake bouncer binary and a
	// fake PM dir.
	root := t.TempDir()
	pmDir := filepath.Join(root, "pms")
	require.NoError(t, os.MkdirAll(pmDir, 0o755))
	for _, pm := range []string{"npm", "pip"} {
		require.NoError(t, os.WriteFile(filepath.Join(pmDir, pm), []byte("real"), 0o755))
	}
	// Bouncer self path: simulate running as a binary under root/bin.
	bouncerBin := filepath.Join(root, "bouncer")
	require.NoError(t, os.WriteFile(bouncerBin, []byte(""), 0o755))

	// Use the cmd binary directly via runInstallWrappers, with cfg
	// pointing at a cache dir under root.
	cfg := config{CacheDir: filepath.Join(root, "cache")}

	// Re-exec ourselves via the same process? Too noisy. We can just
	// call the lower-level function: build candidates manually and
	// hand them to applyWrapper. The end-to-end runInstallWrappers
	// uses resolveBouncerBinary(), which depends on os.Executable() —
	// in a `go test` process that's the test binary, not bouncer, so
	// we substitute by passing a candidate-bouncer path explicitly.

	candidates := []wrapCandidate{
		{path: filepath.Join(pmDir, "npm"), pm: "npm", source: "user"},
		{path: filepath.Join(pmDir, "pip"), pm: "pip", source: "user"},
	}
	state := wrapperState{}
	for _, c := range candidates {
		_, err := applyWrapper(c, bouncerBin, false, false)
		require.NoError(t, err)
		state.add(wrapperEntry{Path: c.path, OriginalPath: c.path + wrapperSuffix, PM: c.pm, Source: c.source})
	}
	require.NoError(t, saveWrapperState(cfg, state))

	// Each candidate is now a bouncer symlink.
	for _, c := range candidates {
		target, err := os.Readlink(c.path)
		require.NoError(t, err)
		require.Equal(t, bouncerBin, target)
	}

	// Confirm state file persisted.
	loaded, err := loadWrapperState(cfg)
	require.NoError(t, err)
	require.Len(t, loaded.Wrappers, 2)

	// Round-trip JSON shape sanity.
	bytes, err := json.Marshal(loaded)
	require.NoError(t, err)
	require.Contains(t, string(bytes), wrapperSuffix)

	// Unwrap each and confirm reversal.
	for _, w := range loaded.Wrappers {
		require.NoError(t, unwrap(w, false))
	}
	for _, c := range candidates {
		info, err := os.Lstat(c.path)
		require.NoError(t, err)
		require.Zero(t, info.Mode()&os.ModeSymlink, "post-unwrap, path should be a regular file again")
	}
}
