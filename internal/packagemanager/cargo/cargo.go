// Package cargo implements packagemanager.PackageManager for the Cargo CLI.
package cargo

import (
	"strings"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
)

const binaryName = "cargo"

// flagsWithValues lists Cargo flags whose next argv token is the value. Cargo
// accepts global flags before the verb and command-specific flags after it;
// one table keeps values like --manifest-path and --features from being read
// as dependency specs.
var flagsWithValues = argv.FlagsWithValues{
	"--color":          {},
	"--config":         {},
	"-Z":               {},
	"--manifest-path":  {},
	"--lockfile-path":  {},
	"--target":         {},
	"--target-dir":     {},
	"--package":        {},
	"-p":               {},
	"--features":       {},
	"-F":               {},
	"--jobs":           {},
	"-j":               {},
	"--profile":        {},
	"--message-format": {},
	"--example":        {},
	"--bin":            {},
	"--test":           {},
	"--bench":          {},
	"--index":          {},
	"--registry":       {},
	"--version":        {},
	"--vers":           {},
	"--git":            {},
	"--tag":            {},
	"--rev":            {},
	"--branch":         {},
	"--path":           {},
	"--root":           {},
	"--precise":        {},
	"--aggressive":     {},
	"--rename":         {},
}

// Manager parses Cargo dependency-fetching commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a Cargo manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemCrates }

// ParseInstalls implements packagemanager.PackageManager.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return nil
	}
	switch verb {
	case "add":
		return parseAdd(rest)
	case "install":
		return parseInstall(rest)
	case "update", "fetch":
		return []packagemanager.Install{}
	default:
		return nil
	}
}

// ManifestRefs implements packagemanager.PackageManager.
func (Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
	verb, _, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return nil
	}
	switch verb {
	case "add", "update", "fetch":
		return cargoProjectRefs()
	default:
		return nil
	}
}

func parseAdd(rest []string) []packagemanager.Install {
	specs := argv.CollectPositionalsWithTable(rest, flagsWithValues)
	out := make([]packagemanager.Install, 0, len(specs)+1)
	for _, spec := range specs {
		if ins, ok := parseCrateSpec(spec); ok {
			out = append(out, ins)
		}
	}
	if gitURL, ok := firstFlagValue(rest, "--git"); ok {
		out = markInstallsOpaque(out, gitURL)
	}
	if pathValue, ok := firstFlagValue(rest, "--path"); ok {
		out = markInstallsLocal(out, pathValue)
	}
	if len(out) == 0 {
		return []packagemanager.Install{}
	}
	return out
}

func parseInstall(rest []string) []packagemanager.Install {
	specs := argv.CollectPositionalsWithTable(rest, flagsWithValues)
	out := make([]packagemanager.Install, 0, len(specs))
	for _, spec := range specs {
		ins, ok := parseCrateSpec(spec)
		if ok {
			out = append(out, ins)
		}
	}
	if gitURL, ok := firstFlagValue(rest, "--git"); ok {
		out = markInstallsOpaque(out, gitURL)
	}
	if pathValue, ok := firstFlagValue(rest, "--path"); ok {
		out = markInstallsLocal(out, pathValue)
	}
	if len(out) == 0 {
		return []packagemanager.Install{}
	}
	return out
}

func markInstallsOpaque(installs []packagemanager.Install, raw string) []packagemanager.Install {
	if len(installs) == 0 {
		return []packagemanager.Install{{
			Ref:          intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: raw},
			RawSpec:      raw,
			OpaqueRemote: true,
		}}
	}
	for i := range installs {
		installs[i].OpaqueRemote = true
		installs[i].RawSpec += " (" + raw + ")"
	}
	return installs
}

func markInstallsLocal(installs []packagemanager.Install, raw string) []packagemanager.Install {
	if len(installs) == 0 {
		return []packagemanager.Install{{
			Ref:       intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: raw},
			RawSpec:   raw,
			LocalPath: true,
		}}
	}
	for i := range installs {
		installs[i].LocalPath = true
		installs[i].RawSpec += " (" + raw + ")"
	}
	return installs
}

func parseCrateSpec(spec string) (packagemanager.Install, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return packagemanager.Install{}, false
	}
	if isLocalSpec(spec) {
		return packagemanager.Install{
			Ref:       intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: spec},
			RawSpec:   spec,
			LocalPath: true,
		}, true
	}
	if isOpaqueRemoteSpec(spec) {
		return packagemanager.Install{
			Ref:          intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: spec},
			RawSpec:      spec,
			OpaqueRemote: true,
		}, true
	}
	name, version := splitCrateVersion(spec)
	if name == "" {
		return packagemanager.Install{}, false
	}
	return packagemanager.Install{
		Ref:     intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: name, Version: version},
		RawSpec: spec,
	}, true
}

func splitCrateVersion(spec string) (string, string) {
	name, version, ok := strings.Cut(spec, "@")
	if !ok {
		return spec, ""
	}
	return name, version
}

func isLocalSpec(spec string) bool {
	return spec == "." || spec == ".." || strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "file:")
}

func isOpaqueRemoteSpec(spec string) bool {
	for _, prefix := range []string{"git+", "git://", "http://", "https://"} {
		if strings.HasPrefix(spec, prefix) {
			return true
		}
	}
	return false
}

func firstFlagValue(args []string, flag string) (string, bool) {
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "--" {
			return "", false
		}
		if value, ok := strings.CutPrefix(tok, flag+"="); ok {
			return value, true
		}
		if tok == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func cargoProjectRefs() []packagemanager.ManifestRef {
	return []packagemanager.ManifestRef{
		{Path: "Cargo.toml", Kind: packagemanager.ManifestKindCargoToml},
		{Path: "Cargo.lock", Kind: packagemanager.ManifestKindCargoLock},
	}
}
