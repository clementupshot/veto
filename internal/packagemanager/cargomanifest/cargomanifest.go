// Package cargomanifest reads Cargo.toml direct dependency declarations and
// emits Install records for project scans.
//
// Cargo.toml carries requirements, not resolved pins. Plain versions such as
// "1.0.0" are caret requirements in Cargo, so this expander leaves Version
// empty unless the requirement is explicitly exact (`=1.0.0`). Cargo.lock is
// the resolved transitive source for exact crate versions.
package cargomanifest

import (
	"errors"
	"io/fs"
	"os"
	"strings"

	vetoerrors "github.com/brynbellomy/go-utils/errors"
	"github.com/pelletier/go-toml/v2"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

// Expander handles Cargo.toml files. Stateless and safe for concurrent use.
type Expander struct{}

// New returns the default Expander.
func New() *Expander { return &Expander{} }

// Expand reads Cargo.toml and returns direct dependency declarations. Missing
// files and unknown kinds return nil, nil.
func (e *Expander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	if ref.Kind != packagemanager.ManifestKindCargoToml {
		return nil, nil
	}
	data, err := os.ReadFile(ref.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, vetoerrors.With(err, "read Cargo.toml").Set("path", ref.Path)
	}
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, vetoerrors.With(err, "parse Cargo.toml").Set("path", ref.Path)
	}
	seen := map[string]struct{}{}
	var out []packagemanager.Install
	collectDependencyTables(doc, func(deps map[string]any) {
		for name, raw := range deps {
			ins, ok := installFromDependency(name, raw)
			if !ok {
				continue
			}
			key := ins.Ref.Name + "@" + ins.Ref.Version
			if ins.LocalPath {
				key += ":path"
			}
			if ins.OpaqueRemote {
				key += ":opaque"
			}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, ins)
		}
	})
	return out, nil
}

func collectDependencyTables(doc map[string]any, visit func(map[string]any)) {
	visitDirectDependencyTables(doc, visit)

	if workspace, ok := tableValue(doc["workspace"]); ok {
		if deps, ok := tableValue(workspace["dependencies"]); ok {
			visit(deps)
		}
	}

	if targets, ok := tableValue(doc["target"]); ok {
		for _, rawTarget := range targets {
			target, ok := tableValue(rawTarget)
			if !ok {
				continue
			}
			visitDirectDependencyTables(target, visit)
		}
	}
}

func visitDirectDependencyTables(node map[string]any, visit func(map[string]any)) {
	for _, key := range []string{"dependencies", "dev-dependencies", "build-dependencies"} {
		deps, ok := tableValue(node[key])
		if ok {
			visit(deps)
		}
	}
}

func tableValue(raw any) (map[string]any, bool) {
	child, ok := raw.(map[string]any)
	return child, ok
}

func installFromDependency(name string, raw any) (packagemanager.Install, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return packagemanager.Install{}, false
	}
	ins := packagemanager.Install{
		Ref:     intel.PackageRef{Ecosystem: intel.EcosystemCrates, Name: name},
		RawSpec: name + " (from Cargo.toml)",
	}
	switch v := raw.(type) {
	case string:
		ins.Ref.Version = exactCargoVersion(v)
		return ins, true
	case map[string]any:
		if pkg, ok := stringValue(v["package"]); ok && pkg != "" {
			ins.Ref.Name = pkg
		}
		if _, ok := v["path"]; ok {
			ins.LocalPath = true
			return ins, true
		}
		if _, ok := v["git"]; ok {
			ins.OpaqueRemote = true
			return ins, true
		}
		if version, ok := stringValue(v["version"]); ok {
			ins.Ref.Version = exactCargoVersion(version)
		}
		return ins, true
	default:
		return ins, true
	}
}

func exactCargoVersion(req string) string {
	req = strings.TrimSpace(req)
	if !strings.HasPrefix(req, "=") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(req, "="))
}

func stringValue(raw any) (string, bool) {
	s, ok := raw.(string)
	return strings.TrimSpace(s), ok
}

var _ interface {
	Expand(packagemanager.ManifestRef) ([]packagemanager.Install, error)
} = (*Expander)(nil)
