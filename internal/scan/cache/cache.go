// Package cache scans package-manager caches for existing exposure.
package cache

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/scan"
)

// Options configures a cache Scanner.
type Options struct {
	Roots []string
	Store intel.Store
}

// Scanner scans package-manager cache roots for package metadata.
type Scanner struct {
	roots []string
	store intel.Store
}

var _ scan.Scanner = (*Scanner)(nil)

// New builds a cache scanner.
func New(opts Options) *Scanner {
	return &Scanner{roots: append([]string{}, opts.Roots...), store: opts.Store}
}

// DefaultRoots returns known package-manager cache roots for the current user.
func DefaultRoots(home string) []string {
	if home == "" {
		return nil
	}
	return []string{
		filepath.Join(home, ".npm"),
		filepath.Join(home, ".cache", "npm"),
		filepath.Join(home, "Library", "pnpm", "store"),
		filepath.Join(home, ".pnpm-store"),
		filepath.Join(home, ".local", "share", "pnpm", "store"),
		filepath.Join(home, ".bun", "install", "cache"),
		filepath.Join(home, "Library", "Caches", "pip"),
		filepath.Join(home, ".cache", "pip"),
		filepath.Join(home, ".cache", "uv"),
		filepath.Join(home, "Library", "Caches", "pypoetry"),
		filepath.Join(home, ".cache", "pypoetry"),
	}
}

// Scan implements scan.Scanner.
func (s *Scanner) Scan(ctx context.Context) scan.Result {
	result := scan.Result{}
	if s.store == nil {
		result.Errors = append(result.Errors, errors.New("cache scanner requires store"))
		return result
	}
	seen := map[string]struct{}{}
	for _, root := range s.roots {
		if err := ctx.Err(); err != nil {
			result.Errors = append(result.Errors, err)
			return result
		}
		if root == "" {
			continue
		}
		cleanRoot := filepath.Clean(root)
		if _, dup := seen[cleanRoot]; dup {
			continue
		}
		seen[cleanRoot] = struct{}{}
		info, err := os.Stat(cleanRoot)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			result.Errors = append(result.Errors, errors.With(err, "stat cache root").Set("root", cleanRoot))
			continue
		}
		if !info.IsDir() {
			continue
		}
		if err := filepath.WalkDir(cleanRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				result.Errors = append(result.Errors, errors.With(walkErr, "walk cache path").Set("path", path))
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
			findings, checked, scanned, err := s.scanCacheFile(cleanRoot, path)
			if scanned {
				result.FilesScanned++
			}
			result.PackagesChecked += checked
			result.Findings = append(result.Findings, findings...)
			if err != nil {
				result.Errors = append(result.Errors, err)
			}
			return nil
		}); err != nil {
			result.Errors = append(result.Errors, errors.With(err, "walk cache root").Set("root", cleanRoot))
		}
	}
	return result
}

func (s *Scanner) scanCacheFile(root, path string) ([]scan.Finding, int, bool, error) {
	base := filepath.Base(path)
	switch {
	case base == "package.json":
		meta, err := readPackageJSON(path)
		if err != nil {
			return nil, 0, true, err
		}
		return s.findingsForMeta(root, path, meta, isNpxPath(path)), 1, true, nil
	case base == "METADATA" && strings.Contains(path, ".dist-info"+string(filepath.Separator)):
		meta, err := readPythonMetadata(path)
		if err != nil {
			return nil, 0, true, err
		}
		return s.findingsForMeta(root, path, meta, false), 1, true, nil
	default:
		return nil, 0, false, nil
	}
}

type packageMeta struct {
	Ecosystem intel.Ecosystem
	Name      string
	Version   string
}

func readPackageJSON(path string) (packageMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return packageMeta{}, errors.With(err, "read cached package.json").Set("path", path)
	}
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return packageMeta{}, errors.With(err, "parse cached package.json").Set("path", path)
	}
	return packageMeta{Ecosystem: intel.EcosystemNPM, Name: pkg.Name, Version: pkg.Version}, nil
}

func readPythonMetadata(path string) (packageMeta, error) {
	file, err := os.Open(path)
	if err != nil {
		return packageMeta{}, errors.With(err, "read cached Python metadata").Set("path", path)
	}
	defer file.Close()
	meta := packageMeta{Ecosystem: intel.EcosystemPyPI}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			meta.Name = strings.TrimSpace(value)
		case "version":
			meta.Version = strings.TrimSpace(value)
		}
		if meta.Name != "" && meta.Version != "" {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return packageMeta{}, errors.With(err, "scan cached Python metadata").Set("path", path)
	}
	return meta, nil
}

func (s *Scanner) findingsForMeta(root, path string, meta packageMeta, npxResidue bool) []scan.Finding {
	if meta.Name == "" {
		return nil
	}
	ref := intel.PackageRef{Ecosystem: meta.Ecosystem, Name: meta.Name, Version: meta.Version}
	verdict := s.store.Lookup(ref)
	if verdict.Flagged() {
		v := verdict
		confidence := "confirmed"
		purgePath := purgeCandidate(path)
		if meta.Version == "" && !allVersionsVerdict(verdict) {
			confidence = "name-only"
			purgePath = ""
		}
		return []scan.Finding{{
			ID:          findingID("malware", path, ref.Name),
			Surface:     scan.SurfaceCache,
			Severity:    scan.SeverityHigh,
			Path:        path,
			Title:       "package-manager cache contains flagged package artifact",
			PackageRef:  &ref,
			Verdict:     &v,
			Evidence:    []scan.Evidence{{Label: "cache_root", Value: root}, {Label: "confidence", Value: confidence}},
			Remediation: "Run `veto quarantine-cache --dry-run` to review removal candidates, then purge if appropriate.",
			PurgePath:   purgePath,
		}}
	}
	if npxResidue && looksLikeMCPTool(meta.Name) {
		return []scan.Finding{{
			ID:         findingID("npx-mcp", path, ref.Name),
			Surface:    scan.SurfaceCache,
			Severity:   scan.SeverityLow,
			Path:       path,
			Title:      "npm _npx cache contains MCP-like fetch-and-run package",
			PackageRef: &ref,
			Evidence: []scan.Evidence{
				{Label: "cache_root", Value: root},
				{Label: "signal", Value: "_npx cache residue"},
			},
			Remediation: "Inspect the MCP config that spawned this package; purge cache residue if it is no longer needed.",
			PurgePath:   purgeCandidate(path),
		}}
	}
	return nil
}

func allVersionsVerdict(verdict intel.Verdict) bool {
	for _, report := range verdict.Reports {
		if report.Version == "" && report.Range == nil {
			return true
		}
		if report.Range != nil && report.Range.IsUnbounded() {
			return true
		}
	}
	return false
}

func isNpxPath(path string) bool {
	sep := string(filepath.Separator)
	return strings.Contains(path, sep+"_npx"+sep)
}

func looksLikeMCPTool(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "mcp") || strings.Contains(lower, "modelcontextprotocol")
}

func purgeCandidate(packageJSONPath string) string {
	dir := filepath.Dir(packageJSONPath)
	if filepath.Base(dir) == "node_modules" {
		return packageJSONPath
	}
	return dir
}

func shouldPruneDir(name string) bool {
	switch name {
	case ".git", ".cache", "__pycache__":
		return true
	default:
		return false
	}
}

func findingID(kind, path, name string) string {
	return fmt.Sprintf("cache:%s:%s:%s", kind, path, name)
}

// PlanPurge turns confirmed cache findings into purge actions. Only findings
// backed by a flagged intel verdict are eligible; IOC-only residue is reported
// but not deleted by this first implementation.
func PlanPurge(findings []scan.Finding, roots []string, purge bool) []scan.PurgeAction {
	resolvedRoots := resolveExistingRoots(roots)
	actions := []scan.PurgeAction{}
	for _, f := range findings {
		if f.Surface != scan.SurfaceCache || f.PurgePath == "" || f.Verdict == nil || !f.Verdict.Flagged() {
			continue
		}
		action := scan.PurgeAction{
			Path:      f.PurgePath,
			Reason:    f.Title,
			FindingID: f.ID,
			Status:    "planned",
		}
		resolved, ok, err := safeCachePath(f.PurgePath, resolvedRoots)
		if err != nil {
			action.Status = "failed"
			action.Error = err.Error()
			actions = append(actions, action)
			continue
		}
		if !ok {
			action.Status = "skipped"
			action.Error = "path is outside known cache roots or no longer exists"
			actions = append(actions, action)
			continue
		}
		action.Path = resolved
		if purge {
			if err := os.RemoveAll(resolved); err != nil {
				action.Status = "failed"
				action.Error = err.Error()
			} else {
				action.Status = "deleted"
			}
		}
		actions = append(actions, action)
	}
	return actions
}

func resolveExistingRoots(roots []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, root := range roots {
		if root == "" {
			continue
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		resolved = filepath.Clean(resolved)
		if _, ok := seen[resolved]; ok {
			continue
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}
	return out
}

func safeCachePath(path string, roots []string) (string, bool, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	resolved = filepath.Clean(resolved)
	for _, root := range roots {
		rel, err := filepath.Rel(root, resolved)
		if err != nil {
			continue
		}
		if rel == "." || rel == "" {
			return "", false, nil
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return resolved, true, nil
	}
	return "", false, nil
}
