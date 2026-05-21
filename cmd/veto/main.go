// Command veto is a command-level malware scanner for package-manager
// invocations.
//
// Usage:
//
//	veto <pm> <pm-args...>     gate an install command, then exec the real PM
//	veto sync                  refresh the intel store from all sources
//	veto status                show source health and store size
//	veto help                  print this message
//
// The "<pm> <pm-args...>" form is the same shape safe-chain uses, so shims
// can route invocations transparently.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"

	"github.com/brynbellomy/veto/internal/daemon"
	"github.com/brynbellomy/veto/internal/gate"
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/aikido"
	"github.com/brynbellomy/veto/internal/intel/sources/openssf"
	"github.com/brynbellomy/veto/internal/intel/sources/osv"
	"github.com/brynbellomy/veto/internal/intel/sources/pypa"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/bun"
	pmexec "github.com/brynbellomy/veto/internal/packagemanager/exec"
	"github.com/brynbellomy/veto/internal/packagemanager/jslock"
	"github.com/brynbellomy/veto/internal/packagemanager/jsmanifest"
	"github.com/brynbellomy/veto/internal/packagemanager/npm"
	"github.com/brynbellomy/veto/internal/packagemanager/pdm"
	"github.com/brynbellomy/veto/internal/packagemanager/pip"
	"github.com/brynbellomy/veto/internal/packagemanager/pnpm"
	"github.com/brynbellomy/veto/internal/packagemanager/poetry"
	"github.com/brynbellomy/veto/internal/packagemanager/pylock"
	"github.com/brynbellomy/veto/internal/packagemanager/pymanifest"
	"github.com/brynbellomy/veto/internal/packagemanager/pyreq"
	"github.com/brynbellomy/veto/internal/packagemanager/uv"
	"github.com/brynbellomy/veto/internal/packagemanager/yarn"
)

const (
	exitOK         = 0
	exitUsage      = 64
	exitRefused    = 1
	exitInternal   = 70
	// syncTimeout bounds a full refresh across all sources. OpenSSF alone can
	// take ~10s on first sync (35 MB tarball + 454k entries); allow generous
	// headroom so the first-time experience isn't surprising. Subsequent
	// refreshes short-circuit via etag in milliseconds.
	syncTimeout = 5 * time.Minute

	// minHealthyReportCount is the sanity floor below which we treat the
	// intel store as broken and refuse to gate. Aikido alone publishes
	// >120k npm entries today; OpenSSF and OSV add hundreds of thousands
	// more. A value under this floor means either every source is empty,
	// a CDN returned [] for every feed, or the user pointed VETO_SOURCES
	// at a non-source name and got the NopSource fallback. None of these
	// states are safe to gate against.
	minHealthyReportCount = 1000
)

func main() {
	args := os.Args[1:]
	// Shim dispatch: when invoked as a symlink whose basename matches a
	// known package manager (e.g. ~/.local/bin/npm → veto), prepend the
	// PM name so `npm install foo` behaves like `veto npm install foo`.
	// This is the integration path for Codex and any other agent/CI that
	// doesn't expose a per-tool hook protocol.
	if self := filepath.Base(os.Args[0]); isShimName(self) {
		args = append([]string{self}, args...)
	}
	os.Exit(run(args))
}

func run(args []string) int {
	logger := newLogger()

	if len(args) == 0 {
		printUsage(os.Stderr)
		return exitUsage
	}

	cfg, err := loadConfig()
	if err != nil {
		logger.Error().Err(err).Msg("load config")
		return exitInternal
	}

	switch args[0] {
	case "help", "--help", "-h":
		printUsage(os.Stdout)
		return exitOK
	case "sync":
		return runSync(logger, cfg)
	case "status":
		return runStatus(logger, cfg)
	case "install-shims":
		return runInstallShims(logger, args[1:])
	case "uninstall-shims":
		return runUninstallShims(logger, args[1:])
	case "hook":
		return runHook(logger, args[1:])
	case "install-claude-hook":
		return runInstallClaudeHook(logger, args[1:])
	case "uninstall-claude-hook":
		return runUninstallClaudeHook(logger, args[1:])
	case "install-codex":
		return runInstallCodex(logger, args[1:])
	case "install-cursor":
		return runInstallCursor(logger, args[1:])
	case "install-preload":
		return runInstallPreload(logger, args[1:])
	case "uninstall-preload":
		return runUninstallPreload(logger, args[1:])
	case "install-wrappers":
		return runInstallWrappers(logger, cfg, args[1:])
	case "uninstall-wrappers":
		return runUninstallWrappers(logger, cfg, args[1:])
	case "doctor":
		return runDoctor(logger, cfg, args[1:])
	case "daemon":
		return runDaemon(logger, cfg, args[1:])
	}

	return runGate(logger, cfg, args)
}

// isShimName reports whether basename matches one of the package-manager
// binaries veto shadows via PATH shims. Kept in main.go so shim dispatch
// stays fast and dependency-free (no config or store touched on the hot path).
func isShimName(basename string) bool {
	switch basename {
	case "npm", "pnpm", "yarn", "bun",
		"npx", "pnpx", "bunx",
		"pip", "pip3", "uv", "uvx", "poetry", "pipx", "pdm":
		return true
	}
	return false
}

// runGate handles the `veto <pm> <args...>` path. When the veto
// daemon is reachable on its Unix socket, the request is forwarded to it
// — that's the kernel-enforcement path inside a sandbox-exec'd agent.
// Otherwise we fall back to running the gate in-process and exec'ing the
// real PM ourselves, which is the "daemon-less courtesy mode" for users
// who haven't set up launchd yet but still want their interactive shell
// to be soft-gated via PATH shims.
func runGate(logger zerolog.Logger, cfg config, args []string) int {
	if socketPath, err := daemon.SocketPath(); err == nil && daemonSocketExists(socketPath) {
		return daemonClient(logger, socketPath, args[0], args[1:])
	}
	return runGateInProcess(logger, cfg, args)
}

// runGateInProcess is the legacy in-process gate path. Used when the
// daemon socket isn't reachable (no launchd install, or development
// without the daemon running). Same gate logic, same intel store, just
// invoked in the veto CLI process directly.
func runGateInProcess(logger zerolog.Logger, cfg config, args []string) int {
	pmName, pmArgs := args[0], args[1:]
	pms := buildPackageManagers()
	pm, ok := pms[pmName]
	if !ok {
		logger.Warn().Str("pm", pmName).Msg("unknown package manager; passing through")
		return execReal(pmName, pmArgs)
	}

	installs := pm.ParseInstalls(pmArgs)
	manifestRefs := pm.ManifestRefs(pmArgs)
	if installs == nil && len(manifestRefs) == 0 {
		// Not an install verb — pass through immediately, no intel needed.
		return execReal(pmName, pmArgs)
	}

	store, err := buildStore(logger, cfg)
	if err != nil {
		logger.Error().Err(err).Msg("build intel store")
		return exitInternal
	}

	// Refresh synchronously before gating; the cache layer keeps this fast on
	// the common path.
	ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
	defer cancel()
	if err := store.Refresh(ctx); err != nil {
		// Don't fail open: if we have zero intel, we can't gate. Refuse with
		// a clear message rather than letting an install through unchecked.
		logger.Error().Err(err).Msg("intel refresh failed — refusing to gate without data")
		fmt.Fprintln(os.Stderr, "veto: INTERNAL ERROR — intel refresh failed; install aborted fail-closed.")
		return exitInternal
	}

	// Sanity floor on store health. An empty store means every lookup would
	// return "clean," which is worse than useless — it's silently allowing
	// packages through under the appearance of being gated. Either upstream
	// is broken or compromised. Fail closed loudly.
	if reportCount := store.ReportCount(); reportCount < minHealthyReportCount {
		logger.Error().
			Int("reports", reportCount).
			Int("floor", minHealthyReportCount).
			Msg("intel store below sanity floor — refusing to gate")
		fmt.Fprintf(os.Stderr, "veto: INTERNAL ERROR — intel store has only %d reports (expected at least %d); install aborted fail-closed.\n", reportCount, minHealthyReportCount)
		fmt.Fprintln(os.Stderr, "Check that your sources are configured correctly and reachable: `veto status` and `veto sync`.")
		return exitInternal
	}

	policy := gate.DefaultPolicy()
	policy.ManifestExpander = newCompoundExpander()
	// VETO_ALLOW_OPAQUE=1 opts URL/git/tarball/github-shorthand specs
	// through the gate. The default refuses them — see
	// gate.DefaultPolicy docs for why.
	if cfg.AllowOpaqueRemote {
		policy.AllowOpaqueRemote = true
		logger.Warn().Msg("VETO_ALLOW_OPAQUE=1 set; opaque remote specs (URL/git/tarball) will NOT be refused")
	}
	g := gate.New(store, policy).WithLogger(logger)
	decision := g.Evaluate(installs, manifestRefs...)

	switch decision.Outcome {
	case gate.OutcomePassThrough, gate.OutcomeAllow:
		return execReal(pmName, pmArgs)
	case gate.OutcomeRefuse:
		printRefusal(os.Stderr, decision)
		return exitRefused
	case gate.OutcomeAbort:
		printAbort(os.Stderr, decision)
		return exitInternal
	}

	logger.Error().Str("outcome", string(decision.Outcome)).Msg("unknown gate outcome")
	return exitInternal
}

func runSync(logger zerolog.Logger, cfg config) int {
	store, err := buildStore(logger, cfg)
	if err != nil {
		logger.Error().Err(err).Msg("build intel store")
		return exitInternal
	}
	ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
	defer cancel()
	if err := store.Refresh(ctx); err != nil {
		logger.Error().Err(err).Msg("refresh")
		return exitInternal
	}
	fmt.Printf("veto: synced sources %v\n", store.SourceIDs())
	return exitOK
}

func runStatus(logger zerolog.Logger, cfg config) int {
	store, err := buildStore(logger, cfg)
	if err != nil {
		logger.Error().Err(err).Msg("build intel store")
		return exitInternal
	}
	fmt.Printf("veto: configured sources: %v\n", store.SourceIDs())
	fmt.Printf("veto: cache dir: %s\n", cfg.CacheDir)
	return exitOK
}

// printRefusal writes a human-readable explanation of a refusal to w.
func printRefusal(w io.Writer, decision gate.Decision) {
	fmt.Fprintln(w, "veto: install refused — malware intelligence flagged the following:")
	for _, v := range decision.Flagged() {
		fmt.Fprintf(w, "  - %s@%s (ecosystem: %s)\n", v.Ref.Name, displayVersion(v.Ref.Version), v.Ref.Ecosystem)
		for _, r := range v.Reports {
			reason := r.Reason
			if reason == "" {
				reason = "flagged"
			}
			fmt.Fprintf(w, "      [%s] %s\n", r.SourceID, reason)
		}
	}
	fmt.Fprintln(w, "\nTo override (you really shouldn't), set VETO_BYPASS=1 and re-invoke the package manager directly.")
}

// printAbort writes a loud, distinct error when the gate could not make a
// confident decision (e.g., a manifest file failed to parse). Distinguishing
// this from a malware-driven refusal matters: a colleague seeing "refused"
// might assume a package was flagged, but Abort means veto's own
// machinery couldn't reach a verdict and refused to take the risk.
func printAbort(w io.Writer, decision gate.Decision) {
	fmt.Fprintln(w, "veto: INTERNAL ERROR — install aborted fail-closed.")
	fmt.Fprintln(w, "  The gate could not make a confident safety decision and refused to run the package manager.")
	if len(decision.Errors) > 0 {
		fmt.Fprintln(w, "  Underlying errors:")
		for _, e := range decision.Errors {
			fmt.Fprintf(w, "    - %v\n", e)
		}
	}
	fmt.Fprintln(w, "\nThis is not a malware block — it's a veto-side failure. Investigate before retrying.")
}

func displayVersion(v string) string {
	if v == "" {
		return "<any>"
	}
	return v
}

// execReal replaces the current process with the real package-manager binary.
// Returns an exit code only on errors before exec; on success it never returns.
//
// Resolution preference order:
//
//  1. Sibling `<argv[0]>.veto-original` — set by `veto
//     install-wrappers`, which atomically moves a real PM binary aside
//     and replaces the original path with a veto symlink. This is
//     Layer 4: it catches absolute-path invocations
//     (`/opt/homebrew/bin/npm install …`) that bypass PATH lookup
//     entirely.
//  2. PATH lookup, skipping any candidates whose target IS veto
//     (avoids the shim chain re-entering itself).
//
// The sibling check happens first so an attacker can't bypass Layer 4
// by manipulating PATH inside the process.
func execReal(name string, args []string) int {
	realPath, err := findRealBinary(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "veto: cannot find real %s: %v\n", name, err)
		return exitInternal
	}
	if err := syscall.Exec(realPath, append([]string{name}, args...), os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "veto: exec %s: %v\n", realPath, err)
		return exitInternal
	}
	// syscall.Exec doesn't return on success.
	return exitInternal
}

// findWrappedOriginal returns the path to a `.veto-original` sibling
// of argv[0] when veto was invoked through a real-binary wrapper, or
// ("", false) otherwise. Layer 4 (`veto install-wrappers`) plants
// these sibling files; the resolver here unwraps them.
//
// argv[0] must contain a path separator — a bare-name shim invocation
// (e.g. from a ~/.local/bin/<pm> resolved through PATH) does not point
// at a real-binary wrapper site, even though os.Args[0] may be the
// resolved absolute path on some platforms. We err on the side of
// false-negative here and let the PATH walk handle bare names.
func findWrappedOriginal(argv0 string) (string, bool) {
	if argv0 == "" || !strings.ContainsRune(argv0, '/') {
		return "", false
	}
	abs, err := filepath.Abs(argv0)
	if err != nil {
		return "", false
	}
	original := abs + ".veto-original"
	info, err := os.Stat(original)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return "", false
	}
	return original, true
}

// findRealBinary returns the path veto should exec to satisfy a
// gated install. Prefers a wrapped-original sibling (Layer 4), then
// falls back to a PATH walk that skips any veto-pointing entries.
func findRealBinary(name string) (string, error) {
	if wrapped, ok := findWrappedOriginal(os.Args[0]); ok {
		return wrapped, nil
	}
	self, err := os.Executable()
	if err != nil {
		return "", errors.With(err, "resolve self")
	}
	selfReal, err := filepath.EvalSymlinks(self)
	if err != nil {
		selfReal = self
	}

	pathEnv := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		if info.Mode()&0o111 == 0 {
			continue
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			resolved = candidate
		}
		if resolved == selfReal {
			// This PATH entry IS veto (either a Layer 2 shim or a
			// Layer 4 wrapper). If a `.veto-original` sibling exists,
			// that's the wrapped real binary — use it instead of
			// continuing the PATH walk. Without this check, a system
			// where every PATH entry has been wrapped would yield
			// "not found in PATH" because every candidate gets skipped.
			if sibling := candidate + ".veto-original"; isExecutableRegularOrSymlink(sibling) {
				return sibling, nil
			}
			continue
		}
		return candidate, nil
	}
	return "", errors.WithNew("not found in PATH").Set("name", name)
}

// isExecutableRegularOrSymlink returns true if `p` exists, is not a
// directory, and resolves to an executable file (resolving symlinks).
// Used by findRealBinary's `.veto-original` sibling lookup —
// homebrew wrappers leave a symlink-into-Cellar as the original, so
// we must follow symlinks here, not just stat.
func isExecutableRegularOrSymlink(p string) bool {
	info, err := os.Stat(p) // Stat follows symlinks
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}

type config struct {
	CacheDir          string
	Sources           []string // enabled source IDs
	AllowOpaqueRemote bool     // VETO_ALLOW_OPAQUE=1 opts URL/git/tarball specs through
}

func loadConfig() (config, error) {
	v := viper.New()
	v.SetEnvPrefix("VETO")
	v.AutomaticEnv()
	v.SetDefault("cache_dir", defaultCacheDir())
	v.SetDefault("sources", []string{"aikido", "openssf", "osv", "pypa"})
	v.SetDefault("allow_opaque", false)
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(filepath.Join(defaultCacheDir(), ".."))
	_ = v.ReadInConfig() // optional config file

	cfg := config{
		CacheDir:          v.GetString("cache_dir"),
		Sources:           v.GetStringSlice("sources"),
		AllowOpaqueRemote: v.GetBool("allow_opaque"),
	}
	if cfg.CacheDir == "" {
		return cfg, errors.New("cache_dir resolved empty")
	}
	return cfg, nil
}

func defaultCacheDir() string {
	if x := os.Getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, "veto")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "veto")
	}
	return filepath.Join(home, ".cache", "veto")
}

// buildStore constructs the intel store from the configured sources. Unknown
// source IDs in config log a warning and are skipped — the user can mistype
// and still get a working store.
func buildStore(logger zerolog.Logger, cfg config) (intel.Store, error) {
	var sources []intel.Source
	for _, id := range cfg.Sources {
		src, err := buildSource(logger, cfg, id)
		if err != nil {
			logger.Warn().Err(err).Str("source", id).Msg("skip source")
			continue
		}
		sources = append(sources, src)
	}
	if len(sources) == 0 {
		return nil, errors.New("no usable sources configured")
	}
	return intel.NewStore(logger, sources...), nil
}

func buildSource(logger zerolog.Logger, cfg config, id string) (intel.Source, error) {
	switch id {
	case "aikido":
		return aikido.New(aikido.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "aikido"),
			Logger:   logger,
		})
	case "openssf":
		return openssf.New(openssf.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "openssf"),
		})
	case "osv":
		return osv.New(osv.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "osv"),
		})
	case "pypa":
		return pypa.New(pypa.Options{
			CacheDir: filepath.Join(cfg.CacheDir, "pypa"),
			Logger:   logger,
		})
	default:
		return nil, errors.WithNew("unknown source").Set("id", id)
	}
}

// compoundExpander dispatches manifest refs to the leaf expander that owns
// the kind. Keeping the dispatch in one place lets each leaf expander stay
// scoped to its own kinds and testable in isolation.
type compoundExpander struct {
	pyReq  *pyreq.Expander
	js     *jsmanifest.Expander
	pyPrj  *pymanifest.Expander
	jsLock *jslock.Expander
	pyLock *pylock.Expander
}

// newCompoundExpander wires the leaf expanders behind a single
// gate.ManifestExpander.
func newCompoundExpander() *compoundExpander {
	return &compoundExpander{
		pyReq:  pyreq.New(),
		js:     jsmanifest.New(),
		pyPrj:  pymanifest.New(),
		jsLock: jslock.New(),
		pyLock: pylock.New(),
	}
}

var _ gate.ManifestExpander = (*compoundExpander)(nil)

// Expand implements gate.ManifestExpander by dispatching on ref.Kind. Unknown
// kinds are a no-op; the gate already tolerates a nil, nil return.
func (c *compoundExpander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	switch ref.Kind {
	case packagemanager.ManifestKindRequirements, packagemanager.ManifestKindConstraint:
		return c.pyReq.Expand(ref)
	case packagemanager.ManifestKindPackageJSON:
		return c.js.Expand(ref)
	case packagemanager.ManifestKindPyProject:
		return c.pyPrj.Expand(ref)
	case packagemanager.ManifestKindPackageLockJSON,
		packagemanager.ManifestKindNpmShrinkwrap,
		packagemanager.ManifestKindPnpmLockYAML,
		packagemanager.ManifestKindYarnLock:
		return c.jsLock.Expand(ref)
	case packagemanager.ManifestKindUvLock,
		packagemanager.ManifestKindPoetryLock,
		packagemanager.ManifestKindPdmLock:
		return c.pyLock.Expand(ref)
	default:
		return nil, nil
	}
}

// buildPackageManagers returns the registry of supported PMs keyed by binary
// name. Adding a new PM = one entry here plus the impl subpackage.
func buildPackageManagers() map[string]packagemanager.PackageManager {
	return map[string]packagemanager.PackageManager{
		"npm":    npm.New(),
		"pnpm":   pnpm.New(),
		"yarn":   yarn.New(),
		"bun":    bun.New(),
		"pip":    pip.New("pip"),
		"pip3":   pip.New("pip3"),
		"uv":     uv.New(),
		"poetry": poetry.New(),
		"pdm":    pdm.New(),

		// Fetch-and-run binaries — every non-help invocation is treated as install.
		"npx":  pmexec.New(pmexec.Options{Name: "npx", Ecosystem: intel.EcosystemNPM, FlagsWithValues: pmexec.NpxFlagsWithValues, SpecFlags: pmexec.NpxSpecFlags}),
		"pnpx": pmexec.New(pmexec.Options{Name: "pnpx", Ecosystem: intel.EcosystemNPM, FlagsWithValues: pmexec.PnpxFlagsWithValues, SpecFlags: pmexec.PnpxSpecFlags}),
		"bunx": pmexec.New(pmexec.Options{Name: "bunx", Ecosystem: intel.EcosystemNPM, FlagsWithValues: pmexec.BunxFlagsWithValues}),
		"uvx":  pmexec.New(pmexec.Options{Name: "uvx", Ecosystem: intel.EcosystemPyPI, FlagsWithValues: pmexec.UvxFlagsWithValues}),
		"pipx": pmexec.New(pmexec.Options{Name: "pipx", Ecosystem: intel.EcosystemPyPI, PipxStyle: true, FlagsWithValues: pmexec.PipxFlagsWithValues, SpecFlags: pmexec.PipxSpecFlags}),
	}
}

func newLogger() zerolog.Logger {
	level := zerolog.InfoLevel
	if strings.EqualFold(os.Getenv("VETO_LOG"), "debug") {
		level = zerolog.DebugLevel
	}
	return zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		Level(level).
		With().
		Timestamp().
		Logger()
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `veto — command-level malware scanner for package managers

Usage:
  veto <pm> <pm-args...>    gate a package-manager invocation, then exec it
  veto sync                 refresh malware intel from all configured sources
  veto status               print configured sources and cache location
  veto doctor               verify defense layers + intel state (run after install)
  veto help                 this message

Layer 1 — Claude Code hook (Bash tool interception):
  veto install-claude-hook [--project] [--settings PATH] [--print]
                               wire veto into ~/.claude/settings.json
  veto uninstall-claude-hook [--settings PATH]
                               remove the veto hook entry (preserves siblings)
  veto hook claude-code     read PreToolUse JSON from stdin, write a deny
                               decision to stdout if the command reaches a PM

Layer 2 — PATH shims (any agent shell, Codex, CI):
  veto install-shims [--dir DIR] [--force]
                               symlinks ~/.local/bin/{npm,pip,…} → veto
  veto uninstall-shims [--dir DIR]
                               remove veto-managed symlinks
  veto install-codex        install-shims + a ~/.codex/config.toml scan
                               for env-policy gotchas
  veto install-cursor [--project-dir DIR] [--shim-dir DIR] [--skip-shims] [--force]
                               install-shims + write .cursor/rules/veto.mdc
                               so Cursor's agent prefixes installs with `+"`veto`"+`

Layer 3 — native execve interposer (catches direct child-process spawns):
  veto install-preload --lib PATH [--shell-rc PATH|auto] [--install-to DIR] [--print]
                               install the libveto_interpose.{dylib,so}
                               and export DYLD_INSERT_LIBRARIES / LD_PRELOAD +
                               VETO_PATH from your shell rc. Build the
                               artifact first with `+"`make interposer`"+`.
  veto uninstall-preload [--shell-rc PATH|auto] [--install-to DIR]
                               strip the managed shell-rc block and remove
                               the installed library

Layer 4 — real-binary wrappers (catches absolute-path invocations):
  veto install-wrappers [--dry-run] [--force] [--dir DIR] [--only PM]
                               atomically replace /opt/homebrew/bin/<pm>,
                               mise install dirs, etc. with veto symlinks.
                               Catches `+"`subprocess.run([abs_path,…])`"+` even
                               when DYLD_INSERT_LIBRARIES is stripped.
  veto uninstall-wrappers   reverse every wrapper recorded in state

Supported package managers:
  npm, pnpm, yarn, bun, pip, pip3, uv, poetry, pdm,
  npx, pnpx, bunx, uvx, pipx

Environment:
  VETO_CACHE_DIR     override cache location (default: $XDG_CACHE_HOME/veto)
  VETO_SOURCES       comma-separated source IDs (default: aikido,openssf,osv,pypa)
  VETO_LOG           set to "debug" for verbose logging
  VETO_BYPASS        prepend `+"`VETO_BYPASS=1 `"+` to skip the gate for one invocation
  VETO_ALLOW_OPAQUE  set to 1 to opt URL/git/tarball/github-shorthand specs
                        through; refused by default (see README)
  VETO_PATH          set by install-preload; consumed by the interposer
`)
}
