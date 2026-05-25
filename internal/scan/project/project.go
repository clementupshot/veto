// Package project scans project trees for manifests and lockfiles.
package project

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/gate"
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/scan"
)

// Options configures a project Scanner.
type Options struct {
	Roots    []string
	Store    intel.Store
	Expander gate.ManifestExpander
}

// Scanner scans project roots for supported manifests and lockfiles.
type Scanner struct {
	roots    []string
	store    intel.Store
	expander gate.ManifestExpander
}

var _ scan.Scanner = (*Scanner)(nil)

// New builds a project scanner.
func New(opts Options) *Scanner {
	return &Scanner{
		roots:    append([]string{}, opts.Roots...),
		store:    opts.Store,
		expander: opts.Expander,
	}
}

// Scan implements scan.Scanner.
func (s *Scanner) Scan(ctx context.Context) scan.Result {
	result := scan.Result{}
	if s.store == nil || s.expander == nil {
		result.Errors = append(result.Errors, errors.New("project scanner requires store and expander"))
		return result
	}
	for _, root := range s.roots {
		if err := ctx.Err(); err != nil {
			result.Errors = append(result.Errors, err)
			return result
		}
		if root == "" {
			continue
		}
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				result.Errors = append(result.Errors, errors.With(walkErr, "walk project path").Set("path", path))
				if entry != nil && entry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				if shouldPruneDir(entry.Name()) {
					return fs.SkipDir
				}
				return nil
			}
			kind, ok := manifestKind(path)
			if !ok {
				return nil
			}
			result.FilesScanned++
			findings, checked, err := s.scanManifest(path, kind)
			result.PackagesChecked += checked
			result.Findings = append(result.Findings, findings...)
			if err != nil {
				result.Errors = append(result.Errors, err)
			}
			return nil
		}); err != nil {
			result.Errors = append(result.Errors, errors.With(err, "walk project root").Set("root", root))
		}
	}
	return result
}

func (s *Scanner) scanManifest(path string, kind packagemanager.ManifestKind) ([]scan.Finding, int, error) {
	installs, err := s.expander.Expand(packagemanager.ManifestRef{Path: path, Kind: kind})
	if err != nil {
		return []scan.Finding{{
			ID:          findingID(scan.SurfaceProject, "parse-error", path, ""),
			Surface:     scan.SurfaceProject,
			Severity:    scan.SeverityHigh,
			Path:        path,
			Title:       "manifest could not be parsed",
			Evidence:    []scan.Evidence{{Label: "error", Value: err.Error()}},
			Remediation: "Inspect or remove the malformed manifest before trusting this dependency tree.",
		}}, 0, err
	}

	findings := []scan.Finding{}
	for _, install := range installs {
		if install.Ref.Name == "" {
			continue
		}
		if install.OpaqueRemote {
			ref := install.Ref
			findings = append(findings, scan.Finding{
				ID:          findingID(scan.SurfaceProject, "opaque", path, install.RawSpec),
				Surface:     scan.SurfaceProject,
				Severity:    scan.SeverityMedium,
				Path:        path,
				Title:       "manifest references opaque remote dependency",
				PackageRef:  &ref,
				Evidence:    []scan.Evidence{{Label: "spec", Value: install.RawSpec}},
				Remediation: "Replace URL/git/tarball dependencies with registry packages or verify the source out of band.",
			})
			continue
		}
		if install.LocalPath {
			continue
		}
		verdict := s.store.Lookup(install.Ref)
		if !verdict.Flagged() {
			continue
		}
		ref := install.Ref
		v := verdict
		findings = append(findings, scan.Finding{
			ID:          findingID(scan.SurfaceProject, "malware", path, install.RawSpec),
			Surface:     scan.SurfaceProject,
			Severity:    scan.SeverityHigh,
			Path:        path,
			Title:       "manifest or lockfile contains flagged package",
			PackageRef:  &ref,
			Verdict:     &v,
			Evidence:    []scan.Evidence{{Label: "spec", Value: install.RawSpec}},
			Remediation: "Remove or upgrade the dependency and regenerate the lockfile.",
		})
	}
	return findings, len(installs), nil
}

func manifestKind(path string) (packagemanager.ManifestKind, bool) {
	base := filepath.Base(path)
	switch base {
	case "package.json":
		return packagemanager.ManifestKindPackageJSON, true
	case "package-lock.json":
		return packagemanager.ManifestKindPackageLockJSON, true
	case "npm-shrinkwrap.json":
		return packagemanager.ManifestKindNpmShrinkwrap, true
	case "pnpm-lock.yaml":
		return packagemanager.ManifestKindPnpmLockYAML, true
	case "yarn.lock":
		return packagemanager.ManifestKindYarnLock, true
	case "pyproject.toml":
		return packagemanager.ManifestKindPyProject, true
	case "uv.lock":
		return packagemanager.ManifestKindUvLock, true
	case "poetry.lock":
		return packagemanager.ManifestKindPoetryLock, true
	case "pdm.lock":
		return packagemanager.ManifestKindPdmLock, true
	case "go.mod":
		return packagemanager.ManifestKindGoMod, true
	case "go.sum":
		return packagemanager.ManifestKindGoSum, true
	case "Cargo.toml":
		return packagemanager.ManifestKindCargoToml, true
	case "Cargo.lock":
		return packagemanager.ManifestKindCargoLock, true
	}
	lower := strings.ToLower(base)
	if strings.HasPrefix(lower, "requirements") && strings.HasSuffix(lower, ".txt") {
		return packagemanager.ManifestKindRequirements, true
	}
	if strings.HasPrefix(lower, "constraints") && strings.HasSuffix(lower, ".txt") {
		return packagemanager.ManifestKindConstraint, true
	}
	return "", false
}

func shouldPruneDir(name string) bool {
	switch name {
	case ".git", "node_modules", ".venv", "venv", "env", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", "target", ".next", ".turbo":
		return true
	default:
		return false
	}
}

func findingID(surface scan.Surface, kind, path, spec string) string {
	return fmt.Sprintf("%s:%s:%s:%s", surface, kind, path, spec)
}
