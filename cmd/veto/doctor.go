// `veto doctor`: one-stop verification of the gate's defense layers.
//
// The README documents a six-step verification checklist; this command
// runs it. Reading the manual list and copy-pasting commands is the
// kind of friction that lets people quietly run an unguarded install
// and assume veto is in front of it. The doctor closes that gap.
//
// Each check produces one line with a status (PASS/WARN/FAIL) plus a
// short explanation. WARN means coverage is partial but not dangerously
// broken (e.g. one PM shim missing). FAIL means the gate is not in front
// of installs in some meaningful way — the user should fix it before
// trusting veto.
//
// Exit codes: 0 if no FAILs, 1 if any FAIL was emitted. WARN doesn't
// affect the exit code so the command is still usable as a tripwire in
// CI.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/intel"
)

// status is the per-check outcome. PASS = green; WARN = yellow; FAIL =
// red. Strictly speaking PASS could be silent and only WARN/FAIL printed,
// but printing every result makes "did the check even run?" answerable.
type status int

const (
	statusPass status = iota
	statusWarn
	statusFail
)

// checkResult is one row in the doctor's output table.
type checkResult struct {
	status   status
	label    string
	detail   string
	howToFix string // shown only on WARN/FAIL
}

// runDoctor implements `veto doctor`. No flags today — the checklist
// is fixed.
func runDoctor(logger zerolog.Logger, cfg config, args []string) int {
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "veto doctor: unexpected arguments: %v\n", args)
		return exitUsage
	}

	// Resolve the running veto binary once; the layer checks compare
	// every wrapper/shim symlink against this canonical path. Empty on
	// resolution failure — pointsAtVeto handles that fail-closed.
	vetoPath, vetoErr := resolveVetoBinary()
	if vetoErr != nil {
		vetoPath = ""
	}

	results := []checkResult{}
	results = append(results, checkVetoOnPath())
	results = append(results, checkShimDir(vetoPath)...)
	results = append(results, checkClaudeHook())
	results = append(results, checkInterposer()...)
	results = append(results, checkWrappers(cfg, vetoPath)...)
	intelResults := checkIntel(logger, cfg)
	results = append(results, intelResults...)

	printResults(os.Stdout, results)
	printVersionManagerFooters(os.Stdout, results)

	failures := 0
	warnings := 0
	for _, r := range results {
		switch r.status {
		case statusFail:
			failures++
		case statusWarn:
			warnings++
		}
	}
	fmt.Fprintf(os.Stdout, "\nSummary: %d passed, %d warnings, %d failures\n",
		len(results)-failures-warnings, warnings, failures)

	if failures > 0 {
		return exitRefused // exit 1 — same as a malware refusal so the
		// signal is "do not trust this install path"
	}
	return exitOK
}

// checkVetoOnPath: the foundational invariant. If veto itself
// isn't resolvable, every layer below is meaningless.
func checkVetoOnPath() checkResult {
	path, err := exec.LookPath("veto")
	if err != nil {
		return checkResult{
			status: statusFail,
			label:  "veto on PATH",
			detail: "not found",
			howToFix: "Run `make install` in the veto repo, or place the " +
				"veto binary somewhere in PATH (e.g. ~/.local/bin).",
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return checkResult{
			status: statusFail,
			label:  "veto on PATH",
			detail: fmt.Sprintf("stat %s: %v", path, err),
		}
	}
	if info.Mode()&0o111 == 0 {
		return checkResult{
			status: statusFail,
			label:  "veto on PATH",
			detail: fmt.Sprintf("%s is not executable", path),
		}
	}
	return checkResult{
		status: statusPass,
		label:  "veto on PATH",
		detail: path,
	}
}

// checkShimDir verifies the PATH shim layer. Two facets:
//   - the shim directory itself is on PATH (otherwise none of the shims
//     get reached);
//   - each PM either has a working shim, or doesn't conflict with a real
//     binary earlier in PATH (which would shadow our shim).
//
// We don't refuse to PASS the shim-dir check just because mise/homebrew
// is earlier in PATH for SOME binary — that's per-PM granularity, surfaced
// as per-shim WARN/FAIL.
func checkShimDir(vetoPath string) []checkResult {
	home, err := os.UserHomeDir()
	if err != nil {
		return []checkResult{{status: statusFail, label: "shim dir", detail: "cannot resolve home: " + err.Error()}}
	}
	shimDir := filepath.Join(home, ".local", "bin")
	pathParts := filepath.SplitList(os.Getenv("PATH"))

	shimIdx := -1
	for i, p := range pathParts {
		if absEqual(p, shimDir) {
			shimIdx = i
			break
		}
	}
	out := []checkResult{}
	if shimIdx < 0 {
		out = append(out, checkResult{
			status: statusWarn,
			label:  "shim dir on PATH",
			detail: shimDir + " is NOT in PATH",
			howToFix: "Add `export PATH=$HOME/.local/bin:$PATH` to your shell rc, " +
				"in FRONT of mise/homebrew/asdf entries.",
		})
	} else {
		out = append(out, checkResult{
			status: statusPass,
			label:  "shim dir on PATH",
			detail: fmt.Sprintf("%s (position %d of %d)", shimDir, shimIdx+1, len(pathParts)),
		})
	}

	for _, name := range shimmedManagers {
		shimPath := filepath.Join(shimDir, name)
		info, err := os.Lstat(shimPath)
		if err != nil {
			out = append(out, checkResult{
				status:   statusWarn,
				label:    "shim:" + name,
				detail:   "not installed",
				howToFix: "Run `veto install-shims` to create missing shims.",
			})
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 {
			out = append(out, checkResult{
				status:   statusFail,
				label:    "shim:" + name,
				detail:   shimPath + " exists but is not a symlink",
				howToFix: "Move the real file aside and run `veto install-shims --force`.",
			})
			continue
		}
		// Verify the shim points at the veto binary. Strict
		// physical-path identity (not name substring) — see
		// pointsAtVeto in install_wrappers.go for the attack model.
		target, _ := os.Readlink(shimPath)
		if !pointsAtVeto(shimPath, vetoPath) {
			out = append(out, checkResult{
				status:   statusFail,
				label:    "shim:" + name,
				detail:   fmt.Sprintf("%s → %s (not a veto shim)", shimPath, target),
				howToFix: "Run `veto install-shims --force` to repoint.",
			})
			continue
		}
		// Earlier-in-PATH conflict: a real PM lives in a dir that comes
		// before the shim dir. The shim never gets reached for this PM.
		if shimIdx >= 0 {
			shadow := earlierRealBinary(name, pathParts, shimIdx, vetoPath)
			if shadow != "" {
				// Mise (and asdf, pyenv, nvm, ...) typically own a
				// version-pinned shim/install dir that the user
				// reasonably wants to keep. Naming the offender lets
				// the user route directly to the recipe footer below
				// instead of guessing what's wrong.
				vm := detectVersionManager(shadow)
				detail := fmt.Sprintf("real %s at %s appears before shim dir; shim is shadowed", name, shadow)
				fix := "Reorder PATH so the shim dir is first, or remove the conflicting binary."
				if vm != "" {
					detail = fmt.Sprintf("%s install at %s shadows the veto shim", vm, shadow)
					fix = fmt.Sprintf("PATH order: %s wins. See the %s footer at the end for the one-liner fix.", vm, vm)
				}
				out = append(out, checkResult{
					status:   statusFail,
					label:    "shim:" + name,
					detail:   detail,
					howToFix: fix,
				})
				continue
			}
		}
		out = append(out, checkResult{
			status: statusPass,
			label:  "shim:" + name,
			detail: fmt.Sprintf("%s → %s", shimPath, target),
		})
	}
	return out
}

// detectVersionManager classifies a shadowing path by which version
// manager owns it. Returns "" when the path doesn't look like a
// known version-manager dir, in which case the caller falls back to
// the generic reorder advice. Today we name mise explicitly because
// it's the documented motivating case; asdf and pyenv follow the
// same recipe so we recognize them too.
func detectVersionManager(shadowPath string) string {
	// Substring matches catch both shim dirs (.../mise/shims/<pm>) and
	// install dirs (.../mise/installs/<tool>/<v>/bin/<pm>). The user's
	// reported failure was in installs/, but newer mise modes also
	// expose shims/ — handle both with one match.
	switch {
	case strings.Contains(shadowPath, "/mise/installs/"),
		strings.Contains(shadowPath, "/mise/shims/"):
		return "mise"
	case strings.Contains(shadowPath, "/.asdf/installs/"),
		strings.Contains(shadowPath, "/.asdf/shims/"):
		return "asdf"
	case strings.Contains(shadowPath, "/.pyenv/shims/"),
		strings.Contains(shadowPath, "/.pyenv/versions/"):
		return "pyenv"
	case strings.Contains(shadowPath, "/.nvm/versions/"),
		strings.Contains(shadowPath, "/nvm/versions/node/"):
		// `.nvm/` is the home-dir install; some setups use a system-wide
		// nvm install whose path still ends in `versions/node/<v>/bin`.
		return "nvm"
	}
	return ""
}

// earlierRealBinary returns the path of a real `name` binary earlier in
// PATH than the shim dir, or "" if none. Used to detect when a shim is
// silently shadowed by mise/homebrew.
func earlierRealBinary(name string, pathParts []string, shimIdx int, vetoPath string) string {
	for i := 0; i < shimIdx; i++ {
		candidate := filepath.Join(pathParts[i], name)
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}
		// Don't flag if the earlier entry is itself a veto-pointing
		// symlink (some users wire a system-wide veto outside ~/.local/bin).
		// Strict physical-path identity — substring matching here would
		// silently accept an attacker-planted /usr/local/bin/<pm> →
		// /tmp/veto-malware.
		if vetoPath != "" && pointsAtVeto(candidate, vetoPath) {
			continue
		}
		return candidate
	}
	return ""
}

// checkClaudeHook reads ~/.claude/settings.json and confirms a veto
// hook entry exists under PreToolUse[Bash][hooks]. WARN (not FAIL) when
// settings.json itself is missing — the user may legitimately not run
// Claude Code.
func checkClaudeHook() checkResult {
	home, err := os.UserHomeDir()
	if err != nil {
		return checkResult{status: statusWarn, label: "Claude hook", detail: "cannot resolve home: " + err.Error()}
	}
	path := filepath.Join(home, ".claude", "settings.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return checkResult{
			status:   statusWarn,
			label:    "Claude hook",
			detail:   path + " not present (Claude Code not configured?)",
			howToFix: "If you use Claude Code, run `veto install-claude-hook`.",
		}
	}
	if err != nil {
		return checkResult{status: statusFail, label: "Claude hook", detail: "read settings: " + err.Error()}
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		return checkResult{
			status:   statusFail,
			label:    "Claude hook",
			detail:   "settings.json failed to parse: " + err.Error(),
			howToFix: "Fix the JSON syntax in " + path + " before running install-claude-hook.",
		}
	}
	if hasVetoClaudeHook(settings) {
		return checkResult{status: statusPass, label: "Claude hook", detail: path}
	}
	return checkResult{
		status:   statusFail,
		label:    "Claude hook",
		detail:   "no veto hook entry in " + path,
		howToFix: "Run `veto install-claude-hook`.",
	}
}

// hasVetoClaudeHook walks the settings tree looking for a Bash
// PreToolUse hook whose command references veto. We match by
// substring rather than exact command shape so old python-shebang
// installs (`/path/veto-hook.py`) and new in-binary installs
// (`/path/veto hook claude-code`) both register as "the gate is wired."
func hasVetoClaudeHook(settings map[string]any) bool {
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false
	}
	pre, ok := hooks["PreToolUse"].([]any)
	if !ok {
		return false
	}
	for _, raw := range pre {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if matcher, _ := entry["matcher"].(string); matcher != "Bash" {
			continue
		}
		inner, _ := entry["hooks"].([]any)
		for _, h := range inner {
			hm, ok := h.(map[string]any)
			if !ok {
				continue
			}
			cmd, _ := hm["command"].(string)
			if isDoctorVetoHookCommand(cmd) {
				return true
			}
		}
	}
	return false
}

// isDoctorVetoHookCommand recognises any command string we'd accept
// as "this hook routes through veto." Kept here (not in a shared
// helper) to avoid a dependency on a sister file that may move during
// the project's ongoing refactoring.
func isDoctorVetoHookCommand(cmd string) bool {
	if cmd == "" {
		return false
	}
	if strings.Contains(cmd, "veto hook claude-code") {
		return true
	}
	if strings.Contains(cmd, "veto-hook.py") {
		return true
	}
	if strings.HasSuffix(cmd, "/veto-hook") {
		return true
	}
	return false
}

// checkInterposer validates the native-interposer layer. Three checks:
//   - the preload env var (DYLD_INSERT_LIBRARIES / LD_PRELOAD) is set;
//   - VETO_PATH is set and points at the veto binary;
//   - the dylib file the env var references actually exists.
//
// These are WARN (not FAIL) because layer 3 is opt-in — users can
// legitimately ship without it and rely on layers 1+2.
func checkInterposer() []checkResult {
	envVar := "DYLD_INSERT_LIBRARIES"
	if runtime.GOOS != "darwin" {
		envVar = "LD_PRELOAD"
	}
	preload := os.Getenv(envVar)
	vetoPath := os.Getenv("VETO_PATH")

	out := []checkResult{}
	if preload == "" {
		out = append(out, checkResult{
			status:   statusWarn,
			label:    "interposer env",
			detail:   envVar + " is NOT set",
			howToFix: "Run `veto install-preload --lib ./libveto_interpose.* --shell-rc auto` to wire layer 3.",
		})
	} else {
		out = append(out, checkResult{
			status: statusPass,
			label:  "interposer env",
			detail: envVar + "=" + preload,
		})
		// Library file should exist and be readable.
		if _, err := os.Stat(preload); err != nil {
			out = append(out, checkResult{
				status:   statusFail,
				label:    "interposer library",
				detail:   "stat " + preload + ": " + err.Error(),
				howToFix: "Rebuild with `make interposer` and reinstall.",
			})
		} else {
			out = append(out, checkResult{
				status: statusPass,
				label:  "interposer library",
				detail: preload,
			})
		}
	}
	if preload != "" && vetoPath == "" {
		out = append(out, checkResult{
			status:   statusFail,
			label:    "VETO_PATH env",
			detail:   "interposer is loaded but VETO_PATH is unset; interposer can't reach the gate",
			howToFix: "Re-run `veto install-preload --shell-rc auto`.",
		})
	} else if vetoPath != "" {
		out = append(out, checkResult{
			status: statusPass,
			label:  "VETO_PATH env",
			detail: vetoPath,
		})
	}
	return out
}

// checkWrappers validates the Layer 4 real-binary wrappers. The state
// file lists every wrap we've installed; for each one we confirm the
// path is still a veto symlink and the .veto-original sibling is
// still present and executable. Drift (brew upgrade replaced our
// symlink) is FAIL — the path now executes unguarded.
//
// If no state file exists at all we emit a single WARN line, since
// Layer 4 is opt-in: a user running with just Layers 1-3 is in a valid
// configuration, just not the strongest one.
func checkWrappers(cfg config, vetoPath string) []checkResult {
	state, err := loadWrapperState(cfg)
	if err != nil {
		return []checkResult{{
			status:   statusFail,
			label:    "wrapper state",
			detail:   "load wrapper state: " + err.Error(),
			howToFix: "Inspect " + filepath.Join(cfg.CacheDir, stateFileName) + " — JSON may be corrupted.",
		}}
	}
	if len(state.Wrappers) == 0 {
		return []checkResult{{
			status: statusWarn,
			label:  "real-binary wrappers",
			detail: "Layer 4 not installed — absolute-path invocations like /opt/homebrew/bin/npm bypass the gate",
			howToFix: "Run `veto install-wrappers` to wrap homebrew/mise/asdf PM binaries with veto symlinks. " +
				"This catches `subprocess.run([abs_path, ...])` even when DYLD_INSERT_LIBRARIES is unset.",
		}}
	}

	out := []checkResult{}
	healthy := 0
	for _, w := range state.Wrappers {
		// Is `Path` still a symlink pointing at veto?
		info, err := os.Lstat(w.Path)
		if err != nil {
			out = append(out, checkResult{
				status: statusFail,
				label:  "wrapper:" + w.PM,
				detail: fmt.Sprintf("%s gone — upgrade may have removed it", w.Path),
				howToFix: "Re-run `veto install-wrappers` to restore. Toolchain upgrades " +
					"(brew, mise install) wipe wrapper symlinks; this is expected.",
			})
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 {
			out = append(out, checkResult{
				status:   statusFail,
				label:    "wrapper:" + w.PM,
				detail:   fmt.Sprintf("%s is no longer a symlink — wrapper has been replaced by a real binary (likely after upgrade)", w.Path),
				howToFix: "Re-run `veto install-wrappers --force` to re-wrap.",
			})
			continue
		}
		target, _ := os.Readlink(w.Path)
		// Strict physical-path identity (not name substring) — substring
		// matching here would silently accept an attacker-planted
		// /opt/homebrew/bin/npm → /tmp/veto-malware. See pointsAtVeto
		// in install_wrappers.go for the attack model.
		if !pointsAtVeto(w.Path, vetoPath) {
			out = append(out, checkResult{
				status: statusFail,
				label:  "wrapper:" + w.PM,
				detail: fmt.Sprintf("%s points at %s, not veto — wrapper subverted", w.Path, target),
				howToFix: "Re-run `veto install-wrappers --force`. If this happens repeatedly, " +
					"investigate what is rewriting the symlink.",
			})
			continue
		}
		// `.veto-original` must still exist for execReal to find.
		if _, err := os.Stat(w.OriginalPath); err != nil {
			out = append(out, checkResult{
				status:   statusFail,
				label:    "wrapper:" + w.PM,
				detail:   fmt.Sprintf("%s missing — wrapper would execute as veto with nothing to delegate to", w.OriginalPath),
				howToFix: "Run `veto uninstall-wrappers` to clean state and `veto install-wrappers` to re-wrap.",
			})
			continue
		}
		healthy++
	}
	if healthy > 0 {
		out = append(out, checkResult{
			status: statusPass,
			label:  "real-binary wrappers",
			detail: fmt.Sprintf("%d/%d healthy", healthy, len(state.Wrappers)),
		})
	}
	return out
}

// checkIntel validates the malware-intel layer: the store can refresh,
// has data above the sanity floor, and each configured source is
// reachable. We use a short timeout because doctor must feel snappy;
// users running it as part of "did my install work?" expect <30s.
func checkIntel(logger zerolog.Logger, cfg config) []checkResult {
	out := []checkResult{}
	store, err := buildStore(logger, cfg)
	if err != nil {
		return append(out, checkResult{
			status:   statusFail,
			label:    "intel store",
			detail:   "build store: " + err.Error(),
			howToFix: "Check VETO_SOURCES is valid (default: aikido,openssf,osv,pypa).",
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := store.Refresh(ctx); err != nil {
		out = append(out, checkResult{
			status:   statusFail,
			label:    "intel refresh",
			detail:   err.Error(),
			howToFix: "Network connectivity issue? Try `veto sync` and check upstream feeds.",
		})
		return out
	}

	count := store.ReportCount()
	if count < minHealthyReportCount {
		out = append(out, checkResult{
			status:   statusFail,
			label:    "intel store size",
			detail:   fmt.Sprintf("%d reports (floor: %d)", count, minHealthyReportCount),
			howToFix: "Run `veto sync` to rebuild; if it still shows low, upstream feeds may be broken.",
		})
	} else {
		out = append(out, checkResult{
			status: statusPass,
			label:  "intel store size",
			detail: fmt.Sprintf("%d reports across %d sources", count, len(store.SourceIDs())),
		})
	}
	// Cache freshness — each source's cache dir contains files; the
	// newest mtime is "last refreshed." 24h is the staleness window.
	if freshness, ok := newestCacheMtime(cfg.CacheDir); ok {
		age := time.Since(freshness)
		switch {
		case age < 24*time.Hour:
			out = append(out, checkResult{status: statusPass, label: "intel freshness", detail: freshness.Format(time.RFC3339)})
		case age < 7*24*time.Hour:
			out = append(out, checkResult{
				status:   statusWarn,
				label:    "intel freshness",
				detail:   fmt.Sprintf("last refreshed %s (%s ago)", freshness.Format(time.RFC3339), age.Round(time.Hour)),
				howToFix: "Run `veto sync` to pull the latest feeds.",
			})
		default:
			out = append(out, checkResult{
				status:   statusFail,
				label:    "intel freshness",
				detail:   fmt.Sprintf("last refreshed %s — more than a week stale", freshness.Format(time.RFC3339)),
				howToFix: "Run `veto sync`.",
			})
		}
	}

	// Per-bucket retention surface. The retention pipeline can keep a
	// bucket alive across many refreshes when its upstream is wedged;
	// without this surface, an operator running doctor sees "intel
	// store size: ok" and cannot distinguish "fresh data" from "data
	// retained from a week ago after the upstream went dark." Emit a
	// row per bucket that is older than 24h (PASS rows would clutter
	// the output without adding signal — the aggregate freshness line
	// above covers the everything-is-fresh case) and flag any bucket
	// past MaxRetentionAge as the LOUD failure mode the retention cap
	// guarantees on the NEXT failed refresh.
	const staleWarnAge = 24 * time.Hour
	for _, b := range store.BucketStatus() {
		if b.LastRefreshedAt.IsZero() || b.RetainedFor < staleWarnAge {
			continue
		}
		label := fmt.Sprintf("intel bucket:%s/%s", b.SourceID, b.Ecosystem)
		switch {
		case b.IsStale:
			out = append(out, checkResult{
				status: statusFail,
				label:  label,
				detail: fmt.Sprintf("retained for %s (last fresh fetch %s); past MaxRetentionAge — next failed refresh will surface this",
					b.RetainedFor.Round(time.Hour), b.LastRefreshedAt.Format(time.RFC3339)),
				howToFix: "Investigate the upstream feed; this bucket has not received a successful refresh in over " +
					intel.MaxRetentionAge.String() + ".",
			})
		default:
			out = append(out, checkResult{
				status: statusWarn,
				label:  label,
				detail: fmt.Sprintf("retained for %s (last fresh fetch %s); within MaxRetentionAge",
					b.RetainedFor.Round(time.Hour), b.LastRefreshedAt.Format(time.RFC3339)),
				howToFix: "Run `veto sync` and check that the upstream feed is reachable.",
			})
		}
	}
	return out
}

// newestCacheMtime walks cfg.CacheDir and returns the newest non-dir file
// mtime. Used as the staleness clock — once a source writes its etag
// file or payload, the cache "version" is the time of that write.
func newestCacheMtime(dir string) (time.Time, bool) {
	var newest time.Time
	found := false
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if !found || info.ModTime().After(newest) {
			newest = info.ModTime()
			found = true
		}
		return nil
	})
	return newest, found
}

// intel.Source — referenced only to keep the import alive across
// possible future doctor tests that build a Source directly. Safe to
// remove if it ever surfaces as unused.
var _ intel.Source = nil

// printVersionManagerFooters emits one recipe block per detected version
// manager whose shims are shadowing veto. Centralizing this here
// keeps the per-shim FAIL lines tight ("mise install at … shadows the
// veto shim") while still giving the user a single copy-pasteable
// fix to follow.
//
// We dedupe by manager: ten shadowed PMs from mise → one mise footer.
func printVersionManagerFooters(w io.Writer, results []checkResult) {
	seen := map[string]bool{}
	for _, r := range results {
		if r.status != statusFail {
			continue
		}
		for _, vm := range []string{"mise", "asdf", "pyenv", "nvm"} {
			if strings.HasPrefix(r.detail, vm+" install") || strings.HasPrefix(r.detail, vm+" shim") {
				if !seen[vm] {
					seen[vm] = true
					fmt.Fprint(w, versionManagerFooter(vm))
				}
			}
		}
	}
}

// versionManagerFooter returns the copy-pasteable recipe for the named
// version manager. Mise has the most detail because that's the one we
// actually field-tested; the others get a short pointer to the same
// pattern.
func versionManagerFooter(vm string) string {
	switch vm {
	case "mise":
		return `
─── mise PATH-ordering recipe ──────────────────────────────────────────

mise prepends its shim/install dir to PATH at ` + "`mise activate`" + ` time.
For veto's shims to win, ~/.local/bin must come AFTER mise activate:

    # ~/.zshrc  (or ~/.bashrc, etc.)
    eval "$(mise activate zsh)"            # mise prepends ITS dirs
    export PATH="$HOME/.local/bin:$PATH"   # then veto takes the front

Trace of ` + "`npm install foo`" + `:
  1. shell → ~/.local/bin/npm  (veto shim)
  2. veto gates, allows
  3. veto's findRealBinary walks PATH, skips itself, hits mise's shim
  4. mise's shim resolves the project-pinned npm and exec's it

If mise's chpwd hook re-prepends and undoes the reorder on every ` + "`cd`" + `,
add this precmd to pin the order:

    _veto_pin_path() { case ":$PATH:" in
      ":$HOME/.local/bin:"*) ;;
      *) PATH="$HOME/.local/bin:${PATH//$HOME\/.local\/bin:/}" ;;
    esac }
    precmd_functions+=(_veto_pin_path)

Verify with ` + "`veto doctor`" + ` — the shim:* FAIL lines should clear.
`
	case "asdf":
		return `
─── asdf PATH-ordering recipe ──────────────────────────────────────────
asdf prepends ~/.asdf/shims to PATH on activate. Add this AFTER asdf's
initialization in your shell rc:
    export PATH="$HOME/.local/bin:$PATH"
The same trace as the mise recipe applies; see that footer for details.
`
	case "pyenv":
		return `
─── pyenv PATH-ordering recipe ─────────────────────────────────────────
pyenv prepends ~/.pyenv/shims via ` + "`pyenv init`" + `. Add AFTER it:
    export PATH="$HOME/.local/bin:$PATH"
`
	case "nvm":
		return `
─── nvm PATH-ordering recipe ───────────────────────────────────────────
nvm prepends ~/.nvm/versions/node/<v>/bin via ` + "`nvm use`" + `. After every
` + "`nvm use`" + `, veto's shim dir must be re-prepended. The cleanest
fix is a shell function that wraps nvm use to reapply the order.
`
	}
	return ""
}

// printResults renders the checklist with PASS/WARN/FAIL markers and a
// trailing how-to-fix hint where applicable. Colors are ANSI codes —
// most terminals handle them; piping to a non-TTY just shows the codes,
// which is acceptable (and grep-friendly).
func printResults(w io.Writer, results []checkResult) {
	fmt.Fprintln(w, "veto doctor — verifying defense layers and intel state")
	fmt.Fprintln(w)
	for _, r := range results {
		marker := "[\x1b[32mPASS\x1b[0m]"
		switch r.status {
		case statusWarn:
			marker = "[\x1b[33mWARN\x1b[0m]"
		case statusFail:
			marker = "[\x1b[31mFAIL\x1b[0m]"
		}
		fmt.Fprintf(w, "  %s  %-26s  %s\n", marker, r.label, r.detail)
		if r.howToFix != "" && r.status != statusPass {
			fmt.Fprintf(w, "         → %s\n", r.howToFix)
		}
	}
}
