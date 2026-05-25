// Package golang implements packagemanager.PackageManager for the Go CLI.
package golang

import (
	"strings"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/argv"
)

const binaryName = "go"

// flagsWithValues lists Go flags whose next argv token is the value. The Go
// command accepts many command-specific flags after the verb, so this table is
// intentionally shared across the phase-1 verbs to avoid mistaking flag values
// for module specs.
var flagsWithValues = argv.FlagsWithValues{
	"-C":            {},
	"-mod":          {},
	"-modfile":      {},
	"-overlay":      {},
	"-tags":         {},
	"-exec":         {},
	"-asmflags":     {},
	"-gcflags":      {},
	"-ldflags":      {},
	"-gccgoflags":   {},
	"-toolexec":     {},
	"-pkgdir":       {},
	"-p":            {},
	"-o":            {},
	"-buildmode":    {},
	"-compiler":     {},
	"-coverpkg":     {},
	"-coverprofile": {},
	"-run":          {},
	"-bench":        {},
	"-benchtime":    {},
	"-count":        {},
	"-cpu":          {},
	"-list":         {},
	"-parallel":     {},
	"-timeout":      {},
	"-vet":          {},
	"-reuse":        {},
}

// Manager parses Go dependency-fetching commands.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a Go manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemGo }

// ParseInstalls implements packagemanager.PackageManager.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return nil
	}
	switch verb {
	case "get":
		return parseModuleSpecs(rest, parseAllPositionals)
	case "install":
		return parseModuleSpecs(rest, parseAllPositionals)
	case "run":
		return parseModuleSpecs(rest, parseFirstRemoteVersioned)
	case "mod":
		subVerb, subRest, subOK := argv.FirstNonFlagWithTable(rest, flagsWithValues)
		if !subOK {
			return nil
		}
		switch subVerb {
		case "download":
			return parseModuleSpecs(subRest, parseAllPositionals)
		case "tidy":
			return []packagemanager.Install{}
		}
	}
	return nil
}

// ManifestRefs implements packagemanager.PackageManager.
func (Manager) ManifestRefs(args []string) []packagemanager.ManifestRef {
	verb, rest, ok := argv.FirstNonFlagWithTable(args, flagsWithValues)
	if !ok {
		return nil
	}
	switch verb {
	case "get":
		if removalOnly(rest) {
			return nil
		}
		if len(argv.CollectPositionalsWithTable(rest, flagsWithValues)) == 0 {
			return nil
		}
		return goModuleRefs()
	case "mod":
		subVerb, _, subOK := argv.FirstNonFlagWithTable(rest, flagsWithValues)
		if !subOK {
			return nil
		}
		switch subVerb {
		case "download", "tidy":
			return goModuleRefs()
		}
	}
	return nil
}

type parseMode int

const (
	parseAllPositionals parseMode = iota
	parseFirstRemoteVersioned
)

func parseModuleSpecs(rest []string, mode parseMode) []packagemanager.Install {
	specs := argv.CollectPositionalsWithTable(rest, flagsWithValues)
	if len(specs) == 0 {
		return nil
	}
	if mode == parseFirstRemoteVersioned {
		_, _, hasVersion := splitModuleVersion(specs[0])
		if !hasVersion {
			return nil
		}
		ins, ok := parseModuleSpec(specs[0])
		if !ok || ins.LocalPath || ins.OpaqueRemote {
			return nil
		}
		return []packagemanager.Install{ins}
	}
	out := make([]packagemanager.Install, 0, len(specs))
	for _, spec := range specs {
		ins, ok := parseModuleSpec(spec)
		if ok {
			out = append(out, ins)
		}
	}
	if len(out) == 0 {
		return []packagemanager.Install{}
	}
	return out
}

func parseModuleSpec(spec string) (packagemanager.Install, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "all" {
		return packagemanager.Install{}, false
	}
	if isOpaqueRemoteSpec(spec) {
		return packagemanager.Install{
			Ref:          intel.PackageRef{Ecosystem: intel.EcosystemGo, Name: spec},
			RawSpec:      spec,
			OpaqueRemote: true,
		}, true
	}
	name, version, hasVersion := splitModuleVersion(spec)
	if version == "none" {
		return packagemanager.Install{}, false
	}
	if strings.HasSuffix(name, "/...") {
		name = strings.TrimSuffix(name, "/...")
	}
	if isLocalGoSpec(name) {
		return packagemanager.Install{
			Ref:       intel.PackageRef{Ecosystem: intel.EcosystemGo, Name: name},
			RawSpec:   spec,
			LocalPath: true,
		}, true
	}
	if !hasVersion && !looksLikeRemoteModulePath(name) {
		return packagemanager.Install{}, false
	}
	if !isExactGoVersion(version) {
		version = ""
	}
	return packagemanager.Install{
		Ref:     intel.PackageRef{Ecosystem: intel.EcosystemGo, Name: name, Version: version},
		RawSpec: spec,
	}, true
}

func splitModuleVersion(spec string) (string, string, bool) {
	idx := strings.LastIndex(spec, "@")
	if idx <= 0 || idx == len(spec)-1 {
		return spec, "", false
	}
	return spec[:idx], spec[idx+1:], true
}

func isExactGoVersion(version string) bool {
	version = strings.TrimPrefix(version, "v")
	if version == "" {
		return false
	}
	return version[0] >= '0' && version[0] <= '9'
}

func isLocalGoSpec(spec string) bool {
	return spec == "." || spec == ".." || strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || strings.HasPrefix(spec, "/") || strings.HasSuffix(spec, ".go")
}

func isOpaqueRemoteSpec(spec string) bool {
	for _, prefix := range []string{"git+", "git://", "http://", "https://"} {
		if strings.HasPrefix(spec, prefix) {
			return true
		}
	}
	return false
}

func looksLikeRemoteModulePath(name string) bool {
	first, _, _ := strings.Cut(name, "/")
	return strings.Contains(first, ".")
}

func removalOnly(rest []string) bool {
	specs := argv.CollectPositionalsWithTable(rest, flagsWithValues)
	if len(specs) == 0 {
		return false
	}
	for _, spec := range specs {
		_, version, ok := splitModuleVersion(spec)
		if !ok || version != "none" {
			return false
		}
	}
	return true
}

func goModuleRefs() []packagemanager.ManifestRef {
	return []packagemanager.ManifestRef{
		{Path: "go.mod", Kind: packagemanager.ManifestKindGoMod},
		{Path: "go.sum", Kind: packagemanager.ManifestKindGoSum},
	}
}
