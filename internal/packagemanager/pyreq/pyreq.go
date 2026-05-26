// Package pyreq reads requirements.txt and constraints.txt files and turns
// their contents into Install records.
//
// This is the I/O side of pip/uv's `-r requirements.txt` flow. The package
// manager (pip/uv) returns ManifestRefs from argv; the gate's expander —
// implemented here — opens the files, strips comments/blank lines, recurses
// into nested -r/-c references (relative to the referencing file), and
// returns []Install via pyspec.
//
// Recursion is capped at maxRecursionDepth to defend against pathological
// cyclic includes.
package pyreq

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/pyspec"
)

// maxRecursionDepth caps `-r` / `-c` chasing inside requirements files.
// Real-world pyproject ecosystems rarely go past depth 3; 8 leaves headroom
// for unusual layouts while still bounding mistakes.
const maxRecursionDepth = 8

// Expander reads pip/uv-style requirements and constraints files and emits
// Install records the gate can look up.
//
// Implementations are safe for concurrent use; the default Expander returned
// by New() holds no state.
type Expander struct{}

// New returns the default Expander.
func New() *Expander { return &Expander{} }

// Expand reads ref.Path and returns the []Install its contents resolve to.
//
// Path resolution: ref.Path is taken as given (caller is expected to pass it
// absolute, or relative to whatever cwd makes sense). Nested -r/-c
// references inside the file are resolved relative to the directory of the
// file that contains them, matching pip's behavior.
//
// Returns wrapped errors (with the offending path attached as a field) when
// a file cannot be read. Malformed lines are skipped — pip itself is
// lenient — so this errors only on I/O failures, not parse failures.
func (e *Expander) Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	switch ref.Kind {
	case packagemanager.ManifestKindRequirements, packagemanager.ManifestKindConstraint:
		// Both kinds share the requirements.txt grammar.
	default:
		// Unknown kind; nothing we can do here.
		return nil, nil
	}
	return expandFile(ref.Path, 0)
}

// expandFile reads path, parses each non-comment/non-blank line as a pyspec,
// and recursively follows `-r path` / `--requirement path` / `-c path` /
// `--constraint path` references. depth tracks recursion to bound chase.
func expandFile(path string, depth int) ([]packagemanager.Install, error) {
	if depth >= maxRecursionDepth {
		// Bail quietly: depth bound exists for safety, not because the caller
		// needs to surface this. Producing partial expansion is preferable to
		// a hard error mid-gate.
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, errors.With(err, "reading requirements file").Set("path", path)
	}
	defer f.Close()

	baseDir := filepath.Dir(path)
	var installs []packagemanager.Install

	// Phase 1.7: glue backslash line-continuations BEFORE parsing.
	// The previous "won't do" stance let an attacker hide a spec on
	// a continuation line:
	//   legit==1.0 \
	//   evil==9.9.9
	// pip installed both; veto saw only legit. The accumulator below
	// joins continuations into a single logical line, then strips
	// embedded comments per-line as before.
	scanner := bufio.NewScanner(f)
	var acc strings.Builder
	for scanner.Scan() {
		raw := scanner.Text()
		trimmedR := strings.TrimRight(raw, "\r")
		// Continuation: trailing `\` (not inside a comment).
		stripped := stripComment(trimmedR)
		if strings.HasSuffix(stripped, `\`) && !lineIsEntirelyComment(trimmedR) {
			acc.WriteString(strings.TrimSuffix(stripped, `\`))
			acc.WriteString(" ")
			continue
		}
		acc.WriteString(stripped)
		line := strings.TrimSpace(acc.String())
		acc.Reset()
		if line == "" {
			continue
		}

		if include, kind, ok := parseIncludeDirective(line); ok {
			resolved := include
			if !filepath.IsAbs(resolved) {
				resolved = filepath.Join(baseDir, resolved)
			}
			nested, err := expandFile(resolved, depth+1)
			if err != nil {
				return nil, errors.With(err, "expanding included file").Set("kind", string(kind))
			}
			installs = append(installs, nested...)
			continue
		}

		// Editable installs (`-e <spec>` / `--editable <spec>`) carry a real
		// spec — typically a git+url or local path — and must be parsed
		// through pyspec so OpaqueRemote / LocalPath get flagged. Without
		// this, a line like `-e git+https://evil/repo` would fall through
		// the leading-dash skip below and be silently ignored.
		if rest, ok := stripEditablePrefix(line); ok {
			install := pyspec.Parse(rest)
			if install.Ref.Name == "" {
				continue
			}
			installs = append(installs, install)
			continue
		}

		// Skip lines that begin with a flag we don't model. pip allows
		// per-line flags like "--hash=sha256:...", "--index-url=...", etc.
		// These never resolve to a package spec.
		if strings.HasPrefix(line, "-") {
			continue
		}

		install := pyspec.Parse(line)
		if install.Ref.Name == "" {
			// Defensive: an unparseable line yields an empty-name Install.
			// Don't pollute the result.
			continue
		}
		installs = append(installs, install)
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.With(err, "scanning requirements file").Set("path", path)
	}
	return installs, nil
}

// stripEditablePrefix detects pip's editable-install directives (`-e <spec>`
// and `--editable <spec>`, plus the `=` form `--editable=<spec>`) and returns
// the spec body with the prefix removed. Returns ("", false) when the line
// is not an editable directive.
//
// Editable specs are typically git+urls or local paths; pyspec.Parse will
// flag them OpaqueRemote / LocalPath. Without this special case the leading
// `-` would cause expandFile to silently drop them.
func stripEditablePrefix(line string) (string, bool) {
	for _, prefix := range []string{"-e ", "--editable ", "--editable="} {
		if rest, ok := strings.CutPrefix(line, prefix); ok {
			rest = strings.TrimSpace(rest)
			if rest == "" {
				return "", false
			}
			return rest, true
		}
	}
	return "", false
}

// parseIncludeDirective recognizes the pip include directives inside a
// requirements file: `-r path`, `--requirement path`, `-c path`,
// `--constraint path`, and their `=` forms. Returns the referenced path,
// its ManifestKind, and ok=true when the line matches.
func parseIncludeDirective(line string) (string, packagemanager.ManifestKind, bool) {
	candidates := []struct {
		prefix string
		kind   packagemanager.ManifestKind
	}{
		{"-r ", packagemanager.ManifestKindRequirements},
		{"--requirement ", packagemanager.ManifestKindRequirements},
		{"--requirement=", packagemanager.ManifestKindRequirements},
		{"-c ", packagemanager.ManifestKindConstraint},
		{"--constraint ", packagemanager.ManifestKindConstraint},
		{"--constraint=", packagemanager.ManifestKindConstraint},
	}
	for _, c := range candidates {
		if strings.HasPrefix(line, c.prefix) {
			return strings.TrimSpace(line[len(c.prefix):]), c.kind, true
		}
	}
	return "", "", false
}

// stripComment removes a "# ..." trailing comment from line. A '#' inside
// a quoted environment-marker string can be missed by this — we accept that
// edge case since requirements.txt almost never embeds quoted hashes.
func stripComment(line string) string {
	before, _, _ := strings.Cut(line, "#")
	return before
}

// lineIsEntirelyComment reports whether line (raw, with comments
// intact) is just a comment after leading whitespace. Used by the
// continuation accumulator so a `#` at end of a content line is
// still treated as comment-with-no-continuation.
func lineIsEntirelyComment(raw string) bool {
	t := strings.TrimSpace(raw)
	return strings.HasPrefix(t, "#")
}
