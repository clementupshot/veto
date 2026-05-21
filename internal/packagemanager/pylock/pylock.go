// Package pylock reads Python-ecosystem lockfiles (uv.lock, poetry.lock,
// pdm.lock) and emits Install records against the resolved transitive tree.
//
// All three formats share a near-identical TOML schema — an array of
// `[[package]]` tables, each with `name` and `version`. The leaf differences
// (extras, source URLs, hashes) don't affect name-keyed gating.
//
// Missing files return (nil, nil) — the package-manager parsers emit lock
// refs speculatively and the expander tolerates absence.
package pylock

import (
	"errors"
	"io/fs"
	"os"

	bouncererrors "github.com/brynbellomy/go-utils/errors"
	"github.com/pelletier/go-toml/v2"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
)

// Expander handles uv/poetry/pdm lockfile kinds. Stateless; safe for
// concurrent use.
type Expander struct{}

// New returns the default Expander.
func New() *Expander { return &Expander{} }

// Expand dispatches by kind. Returns (nil, nil) for unknown kinds and for
// missing files.
func (e *Expander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	switch ref.Kind {
	case packagemanager.ManifestKindUvLock,
		packagemanager.ManifestKindPoetryLock,
		packagemanager.ManifestKindPdmLock:
		return expand(ref.Path)
	default:
		return nil, nil
	}
}

// lockfile is the minimal TOML shape we care about. All three tools
// emit `[[package]]` arrays; the difference is in surrounding metadata
// (which we ignore).
type lockfile struct {
	Package []packageEntry `toml:"package"`
}

type packageEntry struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

func expand(path string) ([]packagemanager.Install, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, bouncererrors.With(err, "read lockfile").Set("path", path)
	}
	var lf lockfile
	if err := toml.Unmarshal(data, &lf); err != nil {
		return nil, bouncererrors.With(err, "parse lockfile TOML").Set("path", path)
	}
	out := make([]packagemanager.Install, 0, len(lf.Package))
	for _, p := range lf.Package {
		if p.Name == "" || p.Version == "" {
			continue
		}
		out = append(out, packagemanager.Install{
			Ref: intel.PackageRef{
				Ecosystem: intel.EcosystemPyPI,
				Name:      p.Name,
				Version:   p.Version,
			},
			RawSpec: p.Name + "==" + p.Version,
		})
	}
	return out, nil
}
