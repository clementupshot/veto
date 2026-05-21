// Command bouncer is a command-level malware scanner for package-manager
// invocations.
//
// Usage:
//
//	bouncer <pm> <pm-args...>     gate an install command, then exec the real PM
//	bouncer sync                  refresh the intel store from all sources
//	bouncer status                show source health and store size
//	bouncer help                  print this message
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

	"github.com/brynbellomy/package-bouncer/internal/gate"
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/intel/sources/aikido"
	"github.com/brynbellomy/package-bouncer/internal/intel/sources/openssf"
	"github.com/brynbellomy/package-bouncer/internal/intel/sources/osv"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/bun"
	pmexec "github.com/brynbellomy/package-bouncer/internal/packagemanager/exec"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/npm"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pdm"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pip"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pnpm"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/poetry"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/uv"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/yarn"
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
)

func main() {
	os.Exit(run(os.Args[1:]))
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
	}

	return runGate(logger, cfg, args)
}

// runGate handles the `bouncer <pm> <args...>` path: gate the install, then
// exec the real PM.
func runGate(logger zerolog.Logger, cfg config, args []string) int {
	pmName, pmArgs := args[0], args[1:]
	pms := buildPackageManagers()
	pm, ok := pms[pmName]
	if !ok {
		logger.Warn().Str("pm", pmName).Msg("unknown package manager; passing through")
		return execReal(pmName, pmArgs)
	}

	installs := pm.ParseInstalls(pmArgs)
	if installs == nil {
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
		fmt.Fprintln(os.Stderr, "bouncer: intel refresh failed; install refused to fail closed")
		return exitInternal
	}

	g := gate.New(store, gate.DefaultPolicy())
	decision := g.Evaluate(installs)

	switch decision.Outcome {
	case gate.OutcomePassThrough, gate.OutcomeAllow:
		return execReal(pmName, pmArgs)
	case gate.OutcomeRefuse:
		printRefusal(os.Stderr, decision)
		return exitRefused
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
	fmt.Printf("bouncer: synced sources %v\n", store.SourceIDs())
	return exitOK
}

func runStatus(logger zerolog.Logger, cfg config) int {
	store, err := buildStore(logger, cfg)
	if err != nil {
		logger.Error().Err(err).Msg("build intel store")
		return exitInternal
	}
	fmt.Printf("bouncer: configured sources: %v\n", store.SourceIDs())
	fmt.Printf("bouncer: cache dir: %s\n", cfg.CacheDir)
	return exitOK
}

// printRefusal writes a human-readable explanation of a refusal to w.
func printRefusal(w io.Writer, decision gate.Decision) {
	fmt.Fprintln(w, "bouncer: install refused — malware intelligence flagged the following:")
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
	fmt.Fprintln(w, "\nTo override (you really shouldn't), set BOUNCER_BYPASS=1 and re-invoke the package manager directly.")
}

func displayVersion(v string) string {
	if v == "" {
		return "<any>"
	}
	return v
}

// execReal replaces the current process with the real package-manager binary.
// Returns an exit code only on errors before exec; on success it never returns.
func execReal(name string, args []string) int {
	realPath, err := findRealBinary(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bouncer: cannot find real %s: %v\n", name, err)
		return exitInternal
	}
	if err := syscall.Exec(realPath, append([]string{name}, args...), os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "bouncer: exec %s: %v\n", realPath, err)
		return exitInternal
	}
	// syscall.Exec doesn't return on success.
	return exitInternal
}

// findRealBinary returns the first executable named `name` in PATH that is
// not the bouncer binary itself (so shims that point at bouncer don't recurse).
func findRealBinary(name string) (string, error) {
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
			continue
		}
		return candidate, nil
	}
	return "", errors.WithNew("not found in PATH").Set("name", name)
}

type config struct {
	CacheDir string
	Sources  []string // enabled source IDs
}

func loadConfig() (config, error) {
	v := viper.New()
	v.SetEnvPrefix("BOUNCER")
	v.AutomaticEnv()
	v.SetDefault("cache_dir", defaultCacheDir())
	v.SetDefault("sources", []string{"aikido", "openssf", "osv"})
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(filepath.Join(defaultCacheDir(), ".."))
	_ = v.ReadInConfig() // optional config file

	cfg := config{
		CacheDir: v.GetString("cache_dir"),
		Sources:  v.GetStringSlice("sources"),
	}
	if cfg.CacheDir == "" {
		return cfg, errors.New("cache_dir resolved empty")
	}
	return cfg, nil
}

func defaultCacheDir() string {
	if x := os.Getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, "package-bouncer")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "package-bouncer")
	}
	return filepath.Join(home, ".cache", "package-bouncer")
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
	default:
		return nil, errors.WithNew("unknown source").Set("id", id)
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
		"npx":  pmexec.New(pmexec.Options{Name: "npx", Ecosystem: intel.EcosystemNPM}),
		"pnpx": pmexec.New(pmexec.Options{Name: "pnpx", Ecosystem: intel.EcosystemNPM}),
		"bunx": pmexec.New(pmexec.Options{Name: "bunx", Ecosystem: intel.EcosystemNPM}),
		"uvx":  pmexec.New(pmexec.Options{Name: "uvx", Ecosystem: intel.EcosystemPyPI}),
		"pipx": pmexec.New(pmexec.Options{Name: "pipx", Ecosystem: intel.EcosystemPyPI, PipxStyle: true}),
	}
}

func newLogger() zerolog.Logger {
	level := zerolog.InfoLevel
	if strings.EqualFold(os.Getenv("BOUNCER_LOG"), "debug") {
		level = zerolog.DebugLevel
	}
	return zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		Level(level).
		With().
		Timestamp().
		Logger()
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `bouncer — command-level malware scanner for package managers

Usage:
  bouncer <pm> <pm-args...>    gate a package-manager invocation, then exec it
  bouncer sync                 refresh malware intel from all configured sources
  bouncer status               print configured sources and cache location
  bouncer help                 this message

Supported package managers:
  npm, pnpm, yarn, bun, pip, pip3, uv, poetry, pdm,
  npx, pnpx, bunx, uvx, pipx

Environment:
  BOUNCER_CACHE_DIR    override cache location (default: $XDG_CACHE_HOME/package-bouncer)
  BOUNCER_SOURCES      comma-separated source IDs (default: aikido)
  BOUNCER_LOG          set to "debug" for verbose logging
`)
}
