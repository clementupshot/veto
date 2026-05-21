// Layer 4: real-binary wrappers.
//
// PATH shims (Layer 2) only engage when the caller resolves the PM by
// bare name. `subprocess.run(["/opt/homebrew/bin/npm", ...])` and
// `/.local/share/mise/installs/node/24.7.0/bin/npm install …` both skip
// PATH lookup entirely. The interposer (Layer 3) closes most of that
// hole — but it depends on the calling process inheriting
// DYLD_INSERT_LIBRARIES / LD_PRELOAD, which an agent can strip.
//
// Layer 4 closes the absolute-path hole without depending on env vars
// at all: for each known PM at a known install dir, we
//
//   1. atomically move the real binary to `<bin>.veto-original`, and
//   2. replace `<bin>` with a symlink to the veto binary.
//
// Any caller naming the original absolute path — bare-name, full-path,
// `subprocess.run` with no env, `os.execvp` from inside an LSP — hits
// veto. The gate runs, then execReal's resolver (in main.go) finds
// the `.veto-original` sibling and exec's it.
//
// Tradeoffs documented for users:
//
//   - Brew / mise / asdf upgrades will overwrite our symlink. Re-run
//     `veto install-wrappers` after upgrading toolchain versions.
//     `veto doctor` flags unwrapped install dirs so a stale state
//     is visible, not silent.
//   - SIP-protected binaries (`/usr/bin/pip3`) can't be wrapped — the
//     dirs are read-only even to root. Layer 3 hits the same wall.
//   - Wrapping requires write access to the candidate dirs. Homebrew
//     and mise install dirs are user-owned by default; `/usr/local/bin`
//     on Intel Macs may need sudo.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/managers"
	"github.com/brynbellomy/veto/internal/vetopath"
)

// wrapperSuffix is the rename target. `.veto-original` is verbose on
// purpose — a colleague who finds it during debugging needs to see
// what made it instead of guessing.
const wrapperSuffix = ".veto-original"

// stateFileName is the JSON registry of every wrapper veto has
// installed. Kept alongside the intel cache so a single
// VETO_CACHE_DIR override moves both. uninstall-wrappers replays
// this list in reverse; install-wrappers adds to it idempotently.
const stateFileName = "wrappers.json"

// wrapperState is what we serialise into stateFileName. Each entry is
// one wrapped PM binary. Stored as a list (not a map) so JSON output
// is stable for diffing.
type wrapperState struct {
	Wrappers []wrapperEntry `json:"wrappers"`
}

// wrapperEntry records one wrapper installation. We persist enough
// information to fully reverse the operation without re-discovering the
// system.
type wrapperEntry struct {
	// Path is the absolute path where the veto symlink lives.
	Path string `json:"path"`
	// OriginalPath is Path + wrapperSuffix — the moved-aside real
	// binary. Kept explicit so a future suffix rename doesn't strand
	// old entries.
	OriginalPath string `json:"original_path"`
	// PM is the basename (e.g. "npm"). Useful for doctor output.
	PM string `json:"pm"`
	// Source identifies what kind of install dir this came from
	// ("homebrew", "mise", "asdf", "user"). Cosmetic — used only in
	// the per-wrapper status line.
	Source string `json:"source"`
	// Sha256 is the hex sha256 of the .veto-original file content at
	// install time. Verified by findRealBinary before syscall.Exec —
	// a mismatch means a malicious package install script has
	// replaced the sibling with attacker code, which would otherwise
	// persist as a wormable RCE across PM invocations.
	//
	// Empty for legacy entries written before this PR; the
	// integrity-check call site logs a one-time warning and proceeds
	// so existing installs keep working until the user re-runs
	// install-wrappers (the install path always populates this).
	Sha256 string `json:"sha256,omitempty"`
	// OriginalTarget captures os.Readlink(c.path) at install time when
	// c.path was a symlink (homebrew shape: /opt/homebrew/bin/npm →
	// ../Cellar/.../bin/npm). Used by unwrap --force when the symlink
	// can no longer be resolved (the binary moved, the target was
	// removed) — EvalSymlinks would fail there; OriginalTarget lets
	// us still compare against the recorded value. Empty when the
	// wrapped target was a regular file.
	OriginalTarget string `json:"original_target,omitempty"`
}

// wrappedManagers is the set of PM names we wrap. Sourced from
// internal/managers so this site cannot drift from the shim list,
// the claude-code hook list, or the in-process gate's PM registry.
var wrappedManagers = managers.Supported

// TODO(M7): when wrapping decisions are about to refuse based on a
// pre-existing veto symlink that points at a different veto installation
// (dev-veto vs system veto, or two parallel forks), consult a configurable
// known-veto-installation list so the operator can declare which one is
// authoritative and which one to mutual-exec through. Today the partial-
// state guard refuses; the M7 ticket asks for a richer "knows-other-veto"
// reconciliation. See consolidated-report.md.

// runInstallWrappers implements `veto install-wrappers [--dry-run] [--force]`.
//
// Default behavior: discover candidate dirs (homebrew, mise installs,
// asdf installs, user-specified --dir flags), find every PM in our
// wrappedManagers list living in those dirs, and wrap each one.
//
//	--dry-run        list the changes that would be made without making them.
//	--force          re-wrap entries we previously wrapped (no-op normally;
//	                 useful after an upgrade re-installed the real binary).
//	--dir DIR        add an additional discovery dir. Can be repeated.
//	--only PM        only wrap this PM. Can be repeated.
func runInstallWrappers(logger zerolog.Logger, cfg config, args []string) int {
	opts, err := parseWrapperFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto install-wrappers: %v\n", err)
		return exitUsage
	}

	vetoPath, err := resolveVetoBinary()
	if err != nil {
		logger.Error().Err(err).Msg("locate veto binary")
		return exitInternal
	}

	candidates, err := discoverWrapCandidates(opts, vetoPath)
	if err != nil {
		logger.Error().Err(err).Msg("discover wrap candidates")
		return exitInternal
	}

	state, _ := loadWrapperState(cfg) // empty state is fine

	// Empty candidates is ambiguous: either no PMs exist in known dirs
	// (fresh machine, nothing to wrap), or everything's already wrapped
	// from a prior install-wrappers run. Distinguish by consulting state.
	if len(candidates) == 0 {
		if existing := len(state.Wrappers); existing > 0 {
			fmt.Printf("veto install-wrappers: %d wrapper%s already installed — nothing new to wrap.\n",
				existing, pluralS(existing))
			fmt.Println("Re-run after `brew upgrade` / `mise install` / `asdf install` to re-wrap binaries that toolchain")
			fmt.Println("upgrades replaced. `veto doctor` will flag any wrapper that drifted.")
			return exitOK
		}
		fmt.Fprintln(os.Stderr, "veto install-wrappers: no candidate PM binaries found in known dirs.")
		fmt.Fprintln(os.Stderr, "Checked: /opt/homebrew/bin, /usr/local/bin, ~/.local/share/mise/installs/*/*/bin,")
		fmt.Fprintln(os.Stderr, "         ~/.asdf/installs/*/*/bin, ~/.bun/bin.")
		fmt.Fprintln(os.Stderr, "Pass --dir to add more discovery roots, or skip Layer 4 if no PMs are installed locally.")
		return exitOK
	}

	stats := wrapperStats{}
	for _, c := range candidates {
		res, err := applyWrapper(c, vetoPath, opts.dryRun, opts.force)
		switch {
		case err != nil:
			stats.failed++
			fmt.Fprintf(os.Stderr, "  %-10s  FAIL  %s — %v\n", c.pm, c.path, err)
		case res.action == wrapperActionSkipAlreadyOurs:
			stats.alreadyOurs++
			if opts.verbose {
				fmt.Printf("  %-10s  ok    already wrapped: %s\n", c.pm, c.path)
			}
		case res.action == wrapperActionSkipDryRun:
			stats.wouldWrap++
			fmt.Printf("  %-10s  ok    would wrap: %s\n", c.pm, c.path)
		case res.action == wrapperActionWrapped:
			stats.wrapped++
			fmt.Printf("  %-10s  ok    wrapped: %s\n", c.pm, c.path)
			state.add(wrapperEntry{
				Path:           c.path,
				OriginalPath:   c.path + wrapperSuffix,
				PM:             c.pm,
				Source:         c.source,
				Sha256:         res.sha256,
				OriginalTarget: res.originalTarget,
			})
		}
	}

	if !opts.dryRun && (stats.wrapped > 0 || stats.failed > 0) {
		if err := saveWrapperState(cfg, state); err != nil {
			logger.Error().Err(err).Msg("save wrapper state")
			return exitInternal
		}
	}

	fmt.Printf("\nSummary: %d wrapped, %d already-ours, %d would-wrap, %d failed\n",
		stats.wrapped, stats.alreadyOurs, stats.wouldWrap, stats.failed)
	if stats.failed > 0 {
		return exitInternal
	}
	return exitOK
}

// runUninstallWrappers reverses every wrapper recorded in state. Files
// not recorded in state are left untouched — symmetric with how
// install-shims refuses to clobber things it didn't install.
func runUninstallWrappers(logger zerolog.Logger, cfg config, args []string) int {
	opts, err := parseWrapperFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto uninstall-wrappers: %v\n", err)
		return exitUsage
	}

	state, err := loadWrapperState(cfg)
	if err != nil {
		logger.Error().Err(err).Msg("load wrapper state")
		return exitInternal
	}
	if len(state.Wrappers) == 0 {
		fmt.Println("veto uninstall-wrappers: no wrappers recorded; nothing to do.")
		return exitOK
	}

	// Resolve the current veto binary once so unwrap can do strict
	// physical-path identity checks against it for every entry.
	vetoPath, err := resolveVetoBinary()
	if err != nil {
		logger.Error().Err(err).Msg("locate veto binary")
		return exitInternal
	}

	remaining := []wrapperEntry{}
	failed := 0
	removed := 0
	for _, w := range state.Wrappers {
		switch err := unwrap(w, vetoPath, opts.dryRun, opts.force); {
		case err != nil:
			failed++
			remaining = append(remaining, w)
			fmt.Fprintf(os.Stderr, "  %-10s  FAIL  %s — %v\n", w.PM, w.Path, err)
		case opts.dryRun:
			fmt.Printf("  %-10s  ok    would unwrap: %s\n", w.PM, w.Path)
			remaining = append(remaining, w)
		default:
			removed++
			fmt.Printf("  %-10s  ok    unwrapped: %s\n", w.PM, w.Path)
		}
	}
	if !opts.dryRun {
		state.Wrappers = remaining
		if err := saveWrapperState(cfg, state); err != nil {
			logger.Error().Err(err).Msg("save wrapper state")
			return exitInternal
		}
	}
	fmt.Printf("\nSummary: %d unwrapped, %d failed, %d remaining\n", removed, failed, len(remaining))
	if failed > 0 {
		return exitInternal
	}
	return exitOK
}

// wrapperFlags captures parsed CLI args for both install/uninstall.
type wrapperFlags struct {
	dirs    []string
	only    map[string]struct{}
	dryRun  bool
	force   bool
	verbose bool
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

type wrapperStats struct {
	wrapped     int
	alreadyOurs int
	wouldWrap   int
	failed      int
}

type wrapAction int

const (
	wrapperActionSkipAlreadyOurs wrapAction = iota
	wrapperActionSkipDryRun
	wrapperActionWrapped
)

func parseWrapperFlags(args []string) (wrapperFlags, error) {
	opts := wrapperFlags{only: map[string]struct{}{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--dry-run":
			opts.dryRun = true
		case a == "--force":
			opts.force = true
		case a == "--verbose", a == "-v":
			opts.verbose = true
		case a == "--dir":
			if i+1 >= len(args) {
				return opts, errors.New("--dir requires a path argument")
			}
			opts.dirs = append(opts.dirs, args[i+1])
			i++
		case strings.HasPrefix(a, "--dir="):
			opts.dirs = append(opts.dirs, strings.TrimPrefix(a, "--dir="))
		case a == "--only":
			if i+1 >= len(args) {
				return opts, errors.New("--only requires a PM name")
			}
			opts.only[args[i+1]] = struct{}{}
			i++
		case strings.HasPrefix(a, "--only="):
			opts.only[strings.TrimPrefix(a, "--only=")] = struct{}{}
		default:
			return opts, errors.WithNew("unknown argument").Set("arg", a)
		}
	}
	return opts, nil
}

// wrapCandidate is one (dir, pm) pair discovery surfaced.
type wrapCandidate struct {
	path   string // absolute path to the existing PM file
	pm     string // basename (e.g. "npm")
	source string // "homebrew", "mise", "asdf", "user"
}

// discoverWrapCandidates walks the well-known install-dir patterns
// looking for files whose basename matches one of wrappedManagers. We
// only return files that exist and are executable, and we only return
// real files (not already veto symlinks).
func discoverWrapCandidates(opts wrapperFlags, vetoPath string) ([]wrapCandidate, error) {
	candidates := []wrapCandidate{}
	pmFilter := func(name string) bool {
		if len(opts.only) == 0 {
			return true
		}
		_, ok := opts.only[name]
		return ok
	}

	// 1) Homebrew prefix dirs. On Apple Silicon, /opt/homebrew/bin; on
	//    Intel, /usr/local/bin. We check both — the wrong one will be
	//    a no-op rather than a failure.
	for _, dir := range []string{"/opt/homebrew/bin", "/usr/local/bin"} {
		for _, pm := range wrappedManagers {
			if !pmFilter(pm) {
				continue
			}
			p := filepath.Join(dir, pm)
			if isWrappableTarget(p, vetoPath) {
				candidates = append(candidates, wrapCandidate{path: p, pm: pm, source: "homebrew"})
			}
		}
	}

	// 2) mise install dirs: ~/.local/share/mise/installs/<tool>/<v>/bin/<pm>.
	if home, err := os.UserHomeDir(); err == nil {
		miseRoot := filepath.Join(home, ".local", "share", "mise", "installs")
		for _, binDir := range globMiseBinDirs(miseRoot) {
			for _, pm := range wrappedManagers {
				if !pmFilter(pm) {
					continue
				}
				p := filepath.Join(binDir, pm)
				if isWrappableTarget(p, vetoPath) {
					candidates = append(candidates, wrapCandidate{path: p, pm: pm, source: "mise"})
				}
			}
		}
		// 3) asdf: ~/.asdf/installs/<tool>/<v>/bin/<pm>.
		asdfRoot := filepath.Join(home, ".asdf", "installs")
		for _, binDir := range globMiseBinDirs(asdfRoot) {
			for _, pm := range wrappedManagers {
				if !pmFilter(pm) {
					continue
				}
				p := filepath.Join(binDir, pm)
				if isWrappableTarget(p, vetoPath) {
					candidates = append(candidates, wrapCandidate{path: p, pm: pm, source: "asdf"})
				}
			}
		}
		// 4) Direct bun install: ~/.bun/bin
		bunDir := filepath.Join(home, ".bun", "bin")
		for _, pm := range []string{"bun", "bunx"} {
			if !pmFilter(pm) {
				continue
			}
			p := filepath.Join(bunDir, pm)
			if isWrappableTarget(p, vetoPath) {
				candidates = append(candidates, wrapCandidate{path: p, pm: pm, source: "bun"})
			}
		}
	}

	// 5) User-supplied --dir entries.
	for _, dir := range opts.dirs {
		for _, pm := range wrappedManagers {
			if !pmFilter(pm) {
				continue
			}
			p := filepath.Join(dir, pm)
			if isWrappableTarget(p, vetoPath) {
				candidates = append(candidates, wrapCandidate{path: p, pm: pm, source: "user"})
			}
		}
	}

	return candidates, nil
}

// globMiseBinDirs returns every `<tool>/<version>/bin` directory under
// the given root (mise's installs root, or asdf's). We do this by
// listing the two intermediate levels rather than using filepath.Glob
// so we get reasonable behavior when the tree is empty or partial.
func globMiseBinDirs(root string) []string {
	out := []string{}
	tools, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	for _, tool := range tools {
		if !tool.IsDir() {
			continue
		}
		toolDir := filepath.Join(root, tool.Name())
		versions, err := os.ReadDir(toolDir)
		if err != nil {
			continue
		}
		for _, v := range versions {
			if !v.IsDir() {
				continue
			}
			binDir := filepath.Join(toolDir, v.Name(), "bin")
			if info, err := os.Stat(binDir); err == nil && info.IsDir() {
				out = append(out, binDir)
			}
		}
	}
	return out
}

// pointsAtVeto is a local alias for vetopath.PointsAt. Kept for
// readability at call sites in this file; the shared helper lives in
// internal/vetopath so doctor.go, install_claude_hook.go, and the
// interposer recursion-guard can use the same physical-path identity
// check.
func pointsAtVeto(linkPath, vetoPath string) bool {
	return vetopath.PointsAt(linkPath, vetoPath)
}

// isWrappableTarget reports whether the path is something we should
// wrap: it exists, is not a directory, is executable, and is not
// already our own veto wrapper.
//
// "Already ours" is decided by pointsAtVeto (strict physical-path
// identity), NOT by name substring matching — see that helper for the
// rationale.
//
// TODO: emit a debug log on each silent-false return so the operator
// can diagnose `veto install-wrappers: no candidate PM binaries found`
// without re-running with strace. Requires plumbing a logger through
// the discovery layer; surfaced in PR #1 review, deferred to a
// follow-up because the plumbing is invasive.
func isWrappableTarget(p, vetoPath string) bool {
	info, err := os.Lstat(p)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// Existing symlink. If it provably points at veto, skip — we
		// installed it. Otherwise it's a real-binary alias (homebrew's
		// canonical layout, mise's shim, etc.) and is wrappable.
		if pointsAtVeto(p, vetoPath) {
			return false
		}
		// Verify the symlink resolves to something we can exec.
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			return false
		}
		info2, err := os.Stat(resolved)
		if err != nil || info2.IsDir() || info2.Mode()&0o111 == 0 {
			return false
		}
		return true
	}
	// Regular file. Must be executable.
	return info.Mode()&0o111 != 0
}

// wrapResult carries the side-channel data the caller needs to
// populate a wrapperEntry without re-statting the filesystem.
type wrapResult struct {
	action         wrapAction
	sha256         string // hex sha256 of the .veto-original contents at install time
	originalTarget string // os.Readlink(c.path) when c.path was a symlink; "" otherwise
}

// applyWrapper installs one wrapper at c.path. The flow is:
//
//  1. Detect "already wrapped" (idempotent re-install).
//  2. Detect partial-state: a veto symlink at c.path WITH no
//     .veto-original sibling, or with a sibling that is itself a veto
//     symlink. Refuse loudly — clobbering would lose the only path
//     back to a working PM.
//  3. Refuse to clobber an existing .veto-original unless --force.
//  4. Capture os.Readlink(c.path) before the rename (M1 — restores
//     unwrap --force when the symlink target has moved).
//  5. Rename the real binary aside (atomic at the syscall level).
//  6. Compute sha256 of the .veto-original contents (H4 — integrity
//     pin verified before exec).
//  7. Atomic temp-symlink-then-rename swap so a concurrent reader
//     never sees ENOENT between (a) removing the renamed file and (b)
//     putting the symlink there. macOS has no portable renameat2 from
//     Go's stdlib, so the temp-link-then-rename pattern is the
//     portable shape that gives us atomicity at the c.path inode.
//
// On step 7 failure we roll the rename in step 5 back so the user's
// PM stays callable.
func applyWrapper(c wrapCandidate, vetoPath string, dryRun, force bool) (wrapResult, error) {
	res := wrapResult{}
	original := c.path + wrapperSuffix

	existing, statErr := os.Lstat(c.path)
	isExistingSymlink := statErr == nil && existing.Mode()&os.ModeSymlink != 0
	isExistingVetoSymlink := isExistingSymlink && pointsAtVeto(c.path, vetoPath)

	if isExistingVetoSymlink {
		// Wrapper symlink already pointing at veto. The .veto-original
		// must exist AND not itself be a veto symlink — otherwise we'd
		// recurse on exec and `findRealBinary` would loop until the
		// daemon ran out of file descriptors.
		origInfo, origErr := os.Lstat(original)
		switch {
		case origErr != nil:
			return res, errors.WithNew(
				"wrapper symlink exists but .veto-original is missing — refusing to overwrite; "+
					"restore .veto-original manually or remove the symlink before retrying").
				Set("path", c.path).
				Set("original", original)
		case origInfo.Mode()&os.ModeSymlink != 0 && pointsAtVeto(original, vetoPath):
			return res, errors.WithNew(
				".veto-original is itself a veto symlink — refusing to overwrite; "+
					"this state would cause findRealBinary to loop on exec").
				Set("path", c.path).
				Set("original", original)
		default:
			res.action = wrapperActionSkipAlreadyOurs
			return res, nil
		}
	}

	if _, err := os.Lstat(original); err == nil && !force {
		return res, errors.WithNew(".veto-original already exists; pass --force to overwrite").
			Set("path", original)
	}

	if dryRun {
		res.action = wrapperActionSkipDryRun
		return res, nil
	}

	if isExistingSymlink {
		if target, rerr := os.Readlink(c.path); rerr == nil {
			res.originalTarget = target
		}
	}

	if err := os.Rename(c.path, original); err != nil {
		return res, errors.With(err, "rename real binary aside").Set("from", c.path, "to", original)
	}

	sum, hashErr := sha256File(original)
	if hashErr != nil {
		_ = os.Rename(original, c.path)
		return res, errors.With(hashErr, "hash .veto-original").Set("path", original)
	}
	res.sha256 = sum

	tmpLink := c.path + ".veto-tmp"
	_ = os.Remove(tmpLink) // any stragglers from a previous crash
	if err := os.Symlink(vetoPath, tmpLink); err != nil {
		_ = os.Rename(original, c.path)
		return res, errors.With(err, "create temp veto symlink").Set("path", tmpLink)
	}
	if err := os.Rename(tmpLink, c.path); err != nil {
		_ = os.Remove(tmpLink)
		_ = os.Rename(original, c.path)
		return res, errors.With(err, "rename temp veto symlink into place").Set("path", c.path)
	}

	res.action = wrapperActionWrapped
	return res, nil
}

// sha256File returns the hex sha256 of the file at path, following
// symlinks (so homebrew's Cellar-target shape hashes the real binary
// content, not the symlink bytes).
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// unwrap reverses one wrapper entry. Symmetric with applyWrapper: it
// removes the veto symlink at Path, then renames the
// `.veto-original` sibling back to Path. Errors short-circuit;
// dry-run skips the actual filesystem operations.
//
// vetoPath is the current location of the veto binary, resolved once
// by the caller. We require strict physical-path identity (via
// pointsAtVeto) before removing — if the symlink at w.Path has been
// replaced by a brew upgrade or by a third party, we bail out rather
// than clobber it. Name-substring matching (the prior pattern) would
// have accepted an attacker-planted symlink to /tmp/veto-evil.
//
// force semantics (M1): when true and pointsAtVeto fails because
// EvalSymlinks can't resolve (the wrapped binary moved, the symlink
// target is dangling), we fall back to comparing os.Readlink(w.Path)
// against w.OriginalTarget. This lets `uninstall-wrappers --force`
// recover state when the upstream toolchain renamed its install dir
// under us; without it the user is stranded with no clean unwrap path.
func unwrap(w wrapperEntry, vetoPath string, dryRun, force bool) error {
	if dryRun {
		return nil
	}
	info, err := os.Lstat(w.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errors.With(err, "lstat").Set("path", w.Path)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// pointsAtVeto requires both sides to resolve via
		// EvalSymlinks. When the wrapped binary's filesystem moved
		// out from under us the resolved target is unavailable and
		// the check fails — fall back to the recorded
		// OriginalTarget when --force lets us.
		if !pointsAtVeto(w.Path, vetoPath) {
			current, _ := os.Readlink(w.Path)
			if force && w.OriginalTarget != "" && current == w.OriginalTarget {
				// Symlink still points at the recorded original
				// target (e.g. unwrap after an EvalSymlinks-failing
				// reinstall). Treat as recognisable state.
			} else if force {
				return errors.WithNew(
					"path no longer points at veto (resolved target unavailable: %v); "+
						"pass --force to remove anyway, or restore the original veto path manually").
					Set("path", w.Path, "current_target", current, "expected_veto", vetoPath)
			} else {
				return errors.WithNew("path no longer points at veto; refusing to overwrite").
					Set("path", w.Path, "current_target", current, "expected_veto", vetoPath)
			}
		}
		// TOCTOU note: there is a small window between the
		// pointsAtVeto check above and the os.Remove below in which
		// an attacker could race-swap the symlink target. Not
		// exploitable for bypass — os.Remove on a symlink unlinks
		// the symlink inode without following the target, so a
		// race-swap to /etc/passwd just removes a symlink the
		// attacker would have to have created in c.path's directory
		// (which would require write access there to begin with).
		// The worst case is unwrap fails noisily on the next
		// boot when the user re-runs install-wrappers; no privilege
		// boundary is crossed. (PR #1 review.)
		if err := os.Remove(w.Path); err != nil {
			return errors.With(err, "remove veto symlink").Set("path", w.Path)
		}
	}
	if _, err := os.Lstat(w.OriginalPath); err == nil {
		if err := os.Rename(w.OriginalPath, w.Path); err != nil {
			return errors.With(err, "restore real binary").Set("from", w.OriginalPath, "to", w.Path)
		}
	}
	return nil
}

// add inserts entry into state if no record with the same Path
// already exists (idempotent re-install).
func (s *wrapperState) add(entry wrapperEntry) {
	for i, w := range s.Wrappers {
		if w.Path == entry.Path {
			s.Wrappers[i] = entry
			return
		}
	}
	s.Wrappers = append(s.Wrappers, entry)
}

// loadWrapperState reads the state file. Missing file is not an error;
// it just means no wrappers have been installed yet.
func loadWrapperState(cfg config) (wrapperState, error) {
	path := filepath.Join(cfg.CacheDir, stateFileName)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return wrapperState{}, nil
	}
	if err != nil {
		return wrapperState{}, errors.With(err, "read wrapper state").Set("path", path)
	}
	var state wrapperState
	if err := json.Unmarshal(data, &state); err != nil {
		return wrapperState{}, errors.With(err, "parse wrapper state").Set("path", path)
	}
	return state, nil
}

// saveWrapperState writes state atomically (tmp + rename) so a crash
// can't strand a half-written JSON.
func saveWrapperState(cfg config, state wrapperState) error {
	if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
		return errors.With(err, "mkdir cache dir")
	}
	path := filepath.Join(cfg.CacheDir, stateFileName)
	buf, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return errors.With(err, "marshal state")
	}
	buf = append(buf, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), "wrappers.json.tmp.")
	if err != nil {
		return errors.With(err, "tmpfile")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
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
	return os.Rename(tmpPath, path)
}
