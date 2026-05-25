// Package cargolock reads Cargo.lock and emits Install records for the
// resolved Rust dependency graph.
package cargolock

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

// Expander handles Cargo.lock files. Stateless and safe for concurrent use.
type Expander struct{}

// New returns the default Expander.
func New() *Expander { return &Expander{} }

// Expand reads Cargo.lock and returns its registry package entries. Missing
// files and unknown kinds return nil, nil.
func (e *Expander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	if ref.Kind != packagemanager.ManifestKindCargoLock {
		return nil, nil
	}
	data, err := os.ReadFile(ref.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, vetoerrors.With(err, "read Cargo.lock").Set("path", ref.Path)
	}
	var lf lockfile
	if err := toml.Unmarshal(data, &lf); err != nil {
		return nil, vetoerrors.With(err, "parse Cargo.lock").Set("path", ref.Path)
	}
	out := make([]packagemanager.Install, 0, len(lf.Package))
	for _, p := range lf.Package {
		if p.Name == "" || p.Version == "" {
			continue
		}
		ins := packagemanager.Install{
			Ref: intel.PackageRef{
				Ecosystem: intel.EcosystemCrates,
				Name:      p.Name,
				Version:   p.Version,
			},
			RawSpec: p.Name + "@" + p.Version,
		}
		switch {
		case p.Source == "":
			ins.LocalPath = true
		case isCratesIOSource(p.Source):
			// Official crates.io registry entry; leave it eligible for intel lookup.
		default:
			ins.OpaqueRemote = true
			ins.RawSpec += " (" + p.Source + ")"
		}
		out = append(out, ins)
	}
	return out, nil
}

func isCratesIOSource(source string) bool {
	source = strings.TrimRight(strings.TrimSpace(source), "/")
	return strings.Contains(source, "github.com/rust-lang/crates.io-index") || strings.Contains(source, "index.crates.io")
}

type lockfile struct {
	Package []packageEntry `toml:"package"`
}

type packageEntry struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	Source  string `toml:"source"`
}

var _ interface {
	Expand(packagemanager.ManifestRef) ([]packagemanager.Install, error)
} = (*Expander)(nil)
