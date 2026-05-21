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
//   1. atomically move the real binary to `<bin>.bouncer-original`, and
//   2. replace `<bin>` with a symlink to the bouncer binary.
//
// Any caller naming the original absolute path — bare-name, full-path,
// `subprocess.run` with no env, `os.execvp` from inside an LSP — hits
// bouncer. The gate runs, then execReal's resolver (in main.go) finds
// the `.bouncer-original` sibling and exec's it.
//
// Tradeoffs documented for users:
//
//   - Brew / mise / asdf upgrades will overwrite our symlink. Re-run
//     `bouncer install-wrappers` after upgrading toolchain versions.
//     `bouncer doctor` flags unwrapped install dirs so a stale state
//     is visible, not silent.
//   - SIP-protected binaries (`/usr/bin/pip3`) can't be wrapped — the
//     dirs are read-only even to root. Layer 3 hits the same wall.
//   - Wrapping requires write access to the candidate dirs. Homebrew
//     and mise install dirs are user-owned by default; `/usr/local/bin`
//     on Intel Macs may need sudo.

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

// wrapperSuffix is the rename target. `.bouncer-original` is verbose on
// purpose — a colleague who finds it during debugging needs to see
// what made it instead of guessing.
const wrapperSuffix = ".bouncer-original"

// stateFileName is the JSON registry of every wrapper bouncer has
// installed. Kept alongside the intel cache so a single
// BOUNCER_CACHE_DIR override moves both. uninstall-wrappers replays
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
	// Path is the absolute path where the bouncer symlink lives.
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
}

// wrappedManagers is the set of PM names we wrap. Same list as
// shimmedManagers (defined in shims.go); duplicated here as a guard
// against the two ever drifting silently.
var wrappedManagers = []string{
	"npm", "pnpm", "yarn", "bun",
	"npx", "pnpx", "bunx",
	"pip", "pip3", "uv", "uvx", "poetry", "pipx", "pdm",
}

// runInstallWrappers implements `bouncer install-wrappers [--dry-run] [--force]`.
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
		fmt.Fprintf(os.Stderr, "bouncer install-wrappers: %v\n", err)
		return exitUsage
	}

	bouncerPath, err := resolveBouncerBinary()
	if err != nil {
		logger.Error().Err(err).Msg("locate bouncer binary")
		return exitInternal
	}

	candidates, err := discoverWrapCandidates(opts)
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
			fmt.Printf("bouncer install-wrappers: %d wrapper%s already installed — nothing new to wrap.\n",
				existing, pluralS(existing))
			fmt.Println("Re-run after `brew upgrade` / `mise install` / `asdf install` to re-wrap binaries that toolchain")
			fmt.Println("upgrades replaced. `bouncer doctor` will flag any wrapper that drifted.")
			return exitOK
		}
		fmt.Fprintln(os.Stderr, "bouncer install-wrappers: no candidate PM binaries found in known dirs.")
		fmt.Fprintln(os.Stderr, "Checked: /opt/homebrew/bin, /usr/local/bin, ~/.local/share/mise/installs/*/*/bin,")
		fmt.Fprintln(os.Stderr, "         ~/.asdf/installs/*/*/bin, ~/.bun/bin.")
		fmt.Fprintln(os.Stderr, "Pass --dir to add more discovery roots, or skip Layer 4 if no PMs are installed locally.")
		return exitOK
	}

	stats := wrapperStats{}
	for _, c := range candidates {
		switch action, err := applyWrapper(c, bouncerPath, opts.dryRun, opts.force); {
		case err != nil:
			stats.failed++
			fmt.Fprintf(os.Stderr, "  %-10s  FAIL  %s — %v\n", c.pm, c.path, err)
		case action == wrapperActionSkipAlreadyOurs:
			stats.alreadyOurs++
			if opts.verbose {
				fmt.Printf("  %-10s  ok    already wrapped: %s\n", c.pm, c.path)
			}
		case action == wrapperActionSkipDryRun:
			stats.wouldWrap++
			fmt.Printf("  %-10s  ok    would wrap: %s\n", c.pm, c.path)
		case action == wrapperActionWrapped:
			stats.wrapped++
			fmt.Printf("  %-10s  ok    wrapped: %s\n", c.pm, c.path)
			state.add(wrapperEntry{
				Path:         c.path,
				OriginalPath: c.path + wrapperSuffix,
				PM:           c.pm,
				Source:       c.source,
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
		fmt.Fprintf(os.Stderr, "bouncer uninstall-wrappers: %v\n", err)
		return exitUsage
	}

	state, err := loadWrapperState(cfg)
	if err != nil {
		logger.Error().Err(err).Msg("load wrapper state")
		return exitInternal
	}
	if len(state.Wrappers) == 0 {
		fmt.Println("bouncer uninstall-wrappers: no wrappers recorded; nothing to do.")
		return exitOK
	}

	remaining := []wrapperEntry{}
	failed := 0
	removed := 0
	for _, w := range state.Wrappers {
		switch err := unwrap(w, opts.dryRun); {
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
// real files (not already bouncer symlinks).
func discoverWrapCandidates(opts wrapperFlags) ([]wrapCandidate, error) {
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
			if isWrappableTarget(p) {
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
				if isWrappableTarget(p) {
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
				if isWrappableTarget(p) {
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
			if isWrappableTarget(p) {
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
			if isWrappableTarget(p) {
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

// isWrappableTarget reports whether the path is something we should
// wrap: it exists, is not a directory, is executable, and is not
// already a symlink we own (any symlink whose target name contains
// "bouncer" is treated as ours).
func isWrappableTarget(p string) bool {
	info, err := os.Lstat(p)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// Existing symlink. If it points at bouncer, it's already ours
		// and we skip. Otherwise it's a real-binary alias (homebrew's
		// canonical layout) and is wrappable.
		target, err := os.Readlink(p)
		if err != nil {
			return false
		}
		if strings.Contains(target, "bouncer") {
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

// applyWrapper does the rename + symlink dance for one candidate.
// Idempotent against already-installed wrappers (returns
// wrapperActionSkipAlreadyOurs); refuses to clobber an existing
// non-bouncer file unless --force was passed.
//
// Atomicity: we rename the original BEFORE creating the symlink. If
// the symlink-create step fails we've still left the system in a
// recoverable state: the user can move .bouncer-original back manually,
// or re-run install-wrappers to retry.
func applyWrapper(c wrapCandidate, bouncerPath string, dryRun, force bool) (wrapAction, error) {
	original := c.path + wrapperSuffix

	// Already wrapped? `c.path` is a bouncer symlink AND
	// `<c.path>.bouncer-original` exists. That's a no-op.
	if existing, err := os.Lstat(c.path); err == nil && existing.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(c.path); err == nil && strings.Contains(target, "bouncer") {
			if _, err := os.Lstat(original); err == nil {
				return wrapperActionSkipAlreadyOurs, nil
			}
		}
	}

	// Refuse to clobber if `.bouncer-original` already exists and we
	// didn't ask for --force. This protects against the partial-state
	// case where a previous wrap moved the original but failed to
	// install the symlink.
	if _, err := os.Lstat(original); err == nil && !force {
		return wrapperActionWrapped, errors.WithNew(".bouncer-original already exists; pass --force to overwrite").
			Set("path", original)
	}

	if dryRun {
		return wrapperActionSkipDryRun, nil
	}

	// 1) Move the real binary aside.
	if err := os.Rename(c.path, original); err != nil {
		return wrapperActionWrapped, errors.With(err, "rename real binary aside").Set("from", c.path, "to", original)
	}
	// 2) Install the symlink at the original path.
	if err := os.Symlink(bouncerPath, c.path); err != nil {
		// Best-effort rollback so we don't strand the user with a
		// PM that's invisible.
		_ = os.Rename(original, c.path)
		return wrapperActionWrapped, errors.With(err, "create bouncer symlink").Set("path", c.path)
	}
	return wrapperActionWrapped, nil
}

// unwrap reverses one wrapper entry. Symmetric with applyWrapper: it
// removes the bouncer symlink at Path, then renames the
// `.bouncer-original` sibling back to Path. Errors short-circuit;
// dry-run skips the actual filesystem operations.
func unwrap(w wrapperEntry, dryRun bool) error {
	if dryRun {
		return nil
	}
	// Confirm Path is still a bouncer symlink before touching it.
	info, err := os.Lstat(w.Path)
	if err != nil {
		// Path is gone (maybe an upgrade reinstalled it). If the
		// `.bouncer-original` is also gone we have nothing to do; if
		// it exists we leave it for the user.
		if os.IsNotExist(err) {
			return nil
		}
		return errors.With(err, "lstat").Set("path", w.Path)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(w.Path)
		if err != nil {
			return errors.With(err, "readlink")
		}
		if !strings.Contains(target, "bouncer") {
			// Someone else (brew upgrade?) replaced our symlink. Don't
			// clobber their work — bail out and let the user decide.
			return errors.WithNew("path no longer points at bouncer; refusing to overwrite").
				Set("path", w.Path, "current_target", target)
		}
		if err := os.Remove(w.Path); err != nil {
			return errors.With(err, "remove bouncer symlink").Set("path", w.Path)
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

