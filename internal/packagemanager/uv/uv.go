// Package uv implements packagemanager.PackageManager for uv.
package uv

import (
	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/argv"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pyspec"
)

const binaryName = "uv"

// Manager parses uv install commands. Handles both `uv pip install ...` and
// `uv add ...` shapes.
type Manager struct{}

var _ packagemanager.PackageManager = (*Manager)(nil)

// New builds a uv manager.
func New() *Manager { return &Manager{} }

// Name implements packagemanager.PackageManager.
func (Manager) Name() string { return binaryName }

// Ecosystem implements packagemanager.PackageManager.
func (Manager) Ecosystem() intel.Ecosystem { return intel.EcosystemPyPI }

// ParseInstalls implements packagemanager.PackageManager.
func (Manager) ParseInstalls(args []string) []packagemanager.Install {
	verb, rest, ok := argv.FirstNonFlag(args)
	if !ok {
		return nil
	}

	// `uv pip install ...` — strip the pip subcommand.
	if verb == "pip" {
		subVerb, subRest, subOK := argv.FirstNonFlag(rest)
		if !subOK || subVerb != "install" {
			return nil
		}
		return parseSpecs(subRest)
	}

	switch verb {
	case "add", "sync", "install":
		return parseSpecs(rest)
	}
	return nil
}

func parseSpecs(rest []string) []packagemanager.Install {
	specs := argv.CollectPositionals(rest)
	installs := make([]packagemanager.Install, 0, len(specs))
	for _, spec := range specs {
		installs = append(installs, pyspec.Parse(spec))
	}
	return installs
}
