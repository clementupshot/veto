// Package gomod reads Go module files and emits Install records for project
// scans.
//
// go.mod is the authoritative selected module set. go.sum can contain stale
// historical module checksums, but it is useful exposure evidence when scanning
// an existing checkout after an incident.
package gomod

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"strings"

	vetoerrors "github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

// Expander handles go.mod and go.sum files. Stateless and safe for concurrent
// use.
type Expander struct{}

// New returns the default Expander.
func New() *Expander { return &Expander{} }

// Expand dispatches by manifest kind. Missing files return nil, nil.
func (e *Expander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	switch ref.Kind {
	case packagemanager.ManifestKindGoMod:
		return expandGoMod(ref.Path)
	case packagemanager.ManifestKindGoSum:
		return expandGoSum(ref.Path)
	default:
		return nil, nil
	}
}

func expandGoMod(path string) ([]packagemanager.Install, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, vetoerrors.With(err, "read go.mod").Set("path", path)
	}
	defer f.Close()

	var out []packagemanager.Install
	inRequireBlock := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := stripLineComment(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if inRequireBlock {
			if fields[0] == ")" {
				inRequireBlock = false
				continue
			}
			if ins, ok := installFromFields(fields); ok {
				out = append(out, ins)
			}
			continue
		}
		if fields[0] != "require" {
			continue
		}
		if len(fields) >= 2 && fields[1] == "(" {
			inRequireBlock = true
			continue
		}
		if ins, ok := installFromFields(fields[1:]); ok {
			out = append(out, ins)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, vetoerrors.With(err, "scan go.mod").Set("path", path)
	}
	return out, nil
}

func expandGoSum(path string) ([]packagemanager.Install, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, vetoerrors.With(err, "read go.sum").Set("path", path)
	}
	defer f.Close()

	seen := map[string]struct{}{}
	var out []packagemanager.Install
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		version := strings.TrimSuffix(fields[1], "/go.mod")
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, install(name, version))
	}
	if err := scanner.Err(); err != nil {
		return nil, vetoerrors.With(err, "scan go.sum").Set("path", path)
	}
	return out, nil
}

func installFromFields(fields []string) (packagemanager.Install, bool) {
	if len(fields) < 2 {
		return packagemanager.Install{}, false
	}
	name := fields[0]
	version := fields[1]
	if name == "" || version == "" {
		return packagemanager.Install{}, false
	}
	return install(name, version), true
}

func install(name, version string) packagemanager.Install {
	return packagemanager.Install{
		Ref: intel.PackageRef{
			Ecosystem: intel.EcosystemGo,
			Name:      name,
			Version:   version,
		},
		RawSpec: name + "@" + version,
	}
}

func stripLineComment(line string) string {
	if idx := strings.Index(line, "//"); idx >= 0 {
		return line[:idx]
	}
	return line
}

var _ interface {
	Expand(packagemanager.ManifestRef) ([]packagemanager.Install, error)
} = (*Expander)(nil)
