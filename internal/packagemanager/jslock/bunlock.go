package jslock

import (
	"encoding/json"
	"strings"

	"github.com/brynbellomy/go-utils/errors"
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

// expandBunLock parses bun.lock (text JSONC) and extracts the resolved
// (name, version) tuples for transitive gating. The bun.lockb binary
// form is intentionally NOT supported — callers must use the text
// lockfile.
//
// Lockfile shape (lockfileVersion 1):
//
//	{
//	  "lockfileVersion": 1,
//	  "packages": {
//	    "lodash": ["lodash@4.17.21", "lodash-4.17.21-..."],
//	    "express": ["express@4.18.2", ""],
//	    ...
//	  }
//	}
//
// We accept JSONC (// line comments and /* block comments */) and
// extract entries[0] as the resolved spec.
func expandBunLock(data []byte) ([]packagemanager.Install, error) {
	clean := stripJSONComments(data)
	var doc struct {
		Packages map[string][]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(clean, &doc); err != nil {
		return nil, errors.With(err, "parse bun.lock")
	}
	out := make([]packagemanager.Install, 0, len(doc.Packages))
	for name, entries := range doc.Packages {
		if len(entries) == 0 {
			continue
		}
		// entries[0] is the resolved spec, e.g. "lodash@4.17.21" or
		// "@scope/pkg@1.2.3". Extract version after the last `@`,
		// honoring scoped names (which begin with `@`).
		var spec string
		if err := json.Unmarshal(entries[0], &spec); err != nil {
			continue
		}
		if spec == "" {
			continue
		}
		version := versionFromBunSpec(spec)
		out = append(out, packagemanager.Install{
			Ref:     intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: name, Version: version},
			RawSpec: spec,
		})
	}
	return out, nil
}

// versionFromBunSpec extracts the version portion of a bun.lock spec.
// Specs look like "name@version" or "@scope/name@version". Use the
// LAST `@` so scoped names (leading `@`) don't fool the split.
// Returns "" when the format doesn't match.
func versionFromBunSpec(spec string) string {
	at := strings.LastIndexByte(spec, '@')
	if at <= 0 {
		return ""
	}
	return spec[at+1:]
}

// stripJSONComments removes // line comments and /* ... */ block
// comments so encoding/json can decode a JSONC document. Quoted
// strings are skipped to preserve embedded `/` characters.
func stripJSONComments(in []byte) []byte {
	out := make([]byte, 0, len(in))
	i := 0
	inString := false
	for i < len(in) {
		c := in[i]
		if inString {
			out = append(out, c)
			if c == '\\' && i+1 < len(in) {
				out = append(out, in[i+1])
				i += 2
				continue
			}
			if c == '"' {
				inString = false
			}
			i++
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			i++
			continue
		}
		if c == '/' && i+1 < len(in) {
			if in[i+1] == '/' {
				for i < len(in) && in[i] != '\n' {
					i++
				}
				continue
			}
			if in[i+1] == '*' {
				i += 2
				for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
					i++
				}
				if i+1 < len(in) {
					i += 2
				}
				continue
			}
		}
		out = append(out, c)
		i++
	}
	return out
}
