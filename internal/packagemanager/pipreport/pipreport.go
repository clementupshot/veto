// Package pipreport reads pip --dry-run --report JSON output and emits Install
// records for the resolved Python dependency set.
package pipreport

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"

	vetoerrors "github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

// Expander handles pip resolver report files. Stateless and safe for concurrent
// use.
type Expander struct{}

// New returns the default Expander.
func New() *Expander { return &Expander{} }

// Expand reads a pip --report JSON file. Missing files and unknown kinds return
// nil, nil.
func (e *Expander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	if ref.Kind != packagemanager.ManifestKindPipReportJSON {
		return nil, nil
	}
	data, err := os.ReadFile(ref.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, vetoerrors.With(err, "read pip resolver report").Set("path", ref.Path)
	}
	var report resolverReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, vetoerrors.With(err, "parse pip resolver report").Set("path", ref.Path)
	}
	out := make([]packagemanager.Install, 0, len(report.Install))
	for _, entry := range report.Install {
		if entry.Metadata.Name == "" || entry.Metadata.Version == "" {
			continue
		}
		out = append(out, packagemanager.Install{
			Ref: intel.PackageRef{
				Ecosystem: intel.EcosystemPyPI,
				Name:      entry.Metadata.Name,
				Version:   entry.Metadata.Version,
			},
			RawSpec: entry.Metadata.Name + "==" + entry.Metadata.Version,
		})
	}
	return out, nil
}

type resolverReport struct {
	Install []installEntry `json:"install"`
}

type installEntry struct {
	Metadata packageMetadata `json:"metadata"`
}

type packageMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

var _ interface {
	Expand(packagemanager.ManifestRef) ([]packagemanager.Install, error)
} = (*Expander)(nil)
