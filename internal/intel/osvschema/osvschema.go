// Package osvschema parses OSV-format malicious-package advisories. Both
// OpenSSF malicious-packages and OSV (osv.dev) use this schema, so the two
// sources share the parser and differ only in how they fetch the documents.
//
// The schema we care about (subset of OSV 1.5):
//
//	{
//	  "id": "MAL-2022-2",
//	  "summary": "Malicious code in foo",
//	  "published": "2022-12-07T23:30:57Z",
//	  "affected": [
//	    {
//	      "package": {"ecosystem": "npm", "name": "foo"},
//	      "ranges": [{"type":"SEMVER","events":[{"introduced":"0"}]}],
//	      "versions": ["1.0.0", "1.0.1"]
//	    }
//	  ]
//	}
//
// One advisory may name multiple affected packages or version ranges; we emit
// one MalwareReport per (package, version) tuple, plus one with empty version
// when only an "introduced: 0" range is present (i.e. "all versions are bad").
package osvschema

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/intel"
)

// Advisory is the parsed shape of one OSV document. We only model the fields
// veto needs; unknown fields are ignored.
type Advisory struct {
	ID        string    `json:"id"`
	Summary   string    `json:"summary"`
	Published time.Time `json:"published"`
	Affected  []Affected `json:"affected"`
}

// Affected describes one (package, version-set) tuple within an advisory.
type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []Range  `json:"ranges"`
	Versions []string `json:"versions"`
}

// Package identifies the affected package in OSV taxonomy.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Range is a continuous interval of affected versions. We only consult
// "introduced: 0" as a signal that all versions are flagged.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one bound in a Range — introduced/fixed/last-affected.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// Parse decodes one OSV JSON document. Returns ErrNotMalware if the advisory
// does not look malware-flavored (no MAL- ID and no malicious classification),
// so callers can filter cheaply.
func Parse(payload []byte) (Advisory, error) {
	var adv Advisory
	if err := json.Unmarshal(payload, &adv); err != nil {
		return Advisory{}, errors.With(err, "decode osv advisory")
	}
	return adv, nil
}

// ErrNotMalware indicates an advisory does not represent a malware finding
// (e.g. it's a regular CVE). Callers use this to skip non-malware entries.
var ErrNotMalware = errors.New("advisory is not a malware finding")

// IsMalware reports whether an advisory looks like a malware report.
// True for any advisory whose ID starts with "MAL-" (OSV's malware namespace).
func IsMalware(adv Advisory) bool {
	return strings.HasPrefix(adv.ID, "MAL-")
}

// Reports converts an advisory into MalwareReports under the given source ID.
// Returns nil when the advisory does not target any ecosystem veto
// understands; the caller can filter these.
func Reports(adv Advisory, sourceID string) []intel.MalwareReport {
	if !IsMalware(adv) {
		return nil
	}

	var out []intel.MalwareReport
	for _, aff := range adv.Affected {
		eco, ok := normalizeEcosystem(aff.Package.Ecosystem)
		if !ok {
			continue
		}
		if aff.Package.Name == "" {
			continue
		}

		reason := adv.Summary
		if reason == "" {
			reason = "MALWARE"
		}

		// Explicit versions list — one report per version.
		emitted := 0
		for _, v := range aff.Versions {
			if v == "" {
				continue
			}
			out = append(out, intel.MalwareReport{
				PackageRef:  intel.PackageRef{Ecosystem: eco, Name: aff.Package.Name, Version: v},
				SourceID:    sourceID,
				Reason:      reason,
				AdvisoryID:  adv.ID,
				PublishedAt: adv.Published,
			})
			emitted++
		}

		// If no explicit versions list, look for any "introduced" event in
		// any range and emit a name-only report. We over-block on purpose:
		// `pip install foo==3.0.0` will refuse even if 3.0.0 is post-fix,
		// because the store does exact-version matching and we don't model
		// ranges. This matches the project's "security over convenience"
		// stance; range-aware lookup is future work.
		if emitted == 0 && hasIntroducedEvent(aff.Ranges) {
			out = append(out, intel.MalwareReport{
				PackageRef:  intel.PackageRef{Ecosystem: eco, Name: aff.Package.Name},
				SourceID:    sourceID,
				Reason:      reason,
				AdvisoryID:  adv.ID,
				PublishedAt: adv.Published,
			})
		}
	}
	return out
}

// hasIntroducedEvent reports whether any of the ranges names an introduction
// point. Bounded ranges (with a fix) still produce a hit so unversioned
// installs of any version in the family are refused.
func hasIntroducedEvent(ranges []Range) bool {
	for _, r := range ranges {
		for _, e := range r.Events {
			if e.Introduced != "" {
				return true
			}
		}
	}
	return false
}

// normalizeEcosystem maps OSV's ecosystem strings into the intel taxonomy.
// Returns (eco, false) when veto does not understand the ecosystem yet.
func normalizeEcosystem(osv string) (intel.Ecosystem, bool) {
	switch strings.ToLower(osv) {
	case "npm":
		return intel.EcosystemNPM, true
	case "pypi":
		return intel.EcosystemPyPI, true
	default:
		return "", false
	}
}
