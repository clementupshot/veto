// Package npm implements packagemanager.PackageManager for the npm CLI.
//
// All real parsing lives in jsspec; this package just declares npm's install
// verb set, the flag-with-value table, and wires the binary name. Same shape
// for pnpm/yarn/bun.
package npm

import (
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
	"github.com/brynbellomy/veto/internal/packagemanager/jsspec"
)

const binaryName = "npm"

var installVerbs = map[string]struct{}{
	"install": {}, "i": {}, "add": {},
	"ci":     {}, // clean install from lockfile; no explicit specs
	"update": {}, "up": {}, "upgrade": {},
}

// execSpecFlags is the subset of flagsWithValues whose VALUE is the
// package spec to gate for `npm exec`. Mirrors NpxSpecFlags: `npm exec
// --package=foo -- some-cmd` fetches `foo` and runs `some-cmd` from it.
var execSpecFlags = argv.FlagsWithValues{
	"--package": {},
	"-p":        {},
}

// alwaysReadsManifest names the install verbs that consult package.json /
// package-lock.json regardless of argv. `ci` is the canonical case: it always
// resolves from the lockfile and refuses to accept positional specs.
var alwaysReadsManifest = map[string]struct{}{
	"ci": {},
}

// flagsWithValues lists npm flags whose next argv token is the flag's
// value, drawn from `npm --help` plus the common config-overriding flags
// agents and CI scripts actually reach for. Keeping this slim is fine —
// the goal is to stop the parser from mistaking values for the verb, not
// to model the full npm flag surface.
var flagsWithValues = argv.FlagsWithValues{
	"--prefix":       {},
	"--registry":     {},
	"--userconfig":   {},
	"--globalconfig": {},
	"--tag":          {},
	"--workspace":    {},
	"-w":             {},
	"--omit":         {},
	"--include":      {},
	"--cache":        {},
	"--logfile":      {},
	"--loglevel":     {},
	"--depth":        {},
	"--save-prefix":  {},
	"--access":       {},
	// `npm exec` accepts -p / --package to name the package to fetch
	// independently of the trailing command. Listed here so the parser
	// doesn't read the value as the verb or as a positional spec.
	"--package": {},
	"-p":        {},
	// `--call` (-c) takes a shell string; without this, an `-c "evil"`
	// would be read as a positional.
	"--call": {},
	"-c":     {},
}

// Manager parses npm install commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds an npm manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemNPM }

// ParseInstalls implements packagemanager.PackageManager.
//
// `npm exec` is special-cased: it shares npx's "fetch-and-run a package"
// semantics, so we follow the same precedence — a `--package`/`-p` value
// wins over the trailing positional (which is just a binary name inside
// the fetched package). Everything else routes through the shared
// install-verb parser.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	if installs, ok := parseExec(args); ok {
		return installs
	}
	return jsspec.ParseInstallArgs(args, installVerbs, flagsWithValues)
}

// parseExec returns (installs, true) when args describe `npm exec [...]`,
// otherwise (nil, false). When the user names `--package=foo` (or repeats it),
// the trailing positional is the binary name and we gate the flag values
// instead. Otherwise the first positional after `exec` is the spec —
// matching npx semantics.
func parseExec(args []string) ([]packagemanager.Install, bool) {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok || verb != "exec" {
		return nil, false
	}
	// Spec-via-flag wins. `npm exec -p evil-pkg some-cmd` fetches evil-pkg
	// and runs some-cmd from it.
	if flagSpecs := argv.CollectFlagValues(rest, execSpecFlags, flagsWithValues); len(flagSpecs) > 0 {
		out := make([]packagemanager.Install, 0, len(flagSpecs))
		for _, s := range flagSpecs {
			out = append(out, jsspec.Parse(s))
		}
		return out, true
	}
	specs := argv.CollectPositionalsWithTable(rest, flagsWithValues)
	if len(specs) == 0 {
		// `npm exec` with no args/flags re-executes the script from the
		// nearest package.json — no fetch, nothing to gate.
		return nil, true
	}
	switch specs[0] {
	case "help", "--help", "-h", "--version", "-v":
		return nil, true
	}
	return []packagemanager.Install{jsspec.Parse(specs[0])}, true
}

// ManifestRefs implements packagemanager.PackageManager. Emits a package.json
// ref when the install verb would derive its work from the local manifest —
// `npm install` / `npm i` with no specs, `npm ci` regardless of args — so the
// gate's expander can read the file and gate its direct dependencies.
func (Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
	return jsspec.PackageJSONManifestRefs(args, installVerbs, alwaysReadsManifest, flagsWithValues)
}
