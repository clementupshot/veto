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
// one MalwareReport per (package, version) tuple from the explicit `versions`
// list, and one MalwareReport per parsed range interval (with the range
// attached as the report's Range field and Version left empty). The Store's
// Lookup consults the per-ecosystem version comparator to test interval
// membership at query time.
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
	// Withdrawn is set to the timestamp at which the upstream retracted the
	// advisory — typically because it was a false positive or got superseded.
	// IsMalware returns false for withdrawn advisories so a withdrawn entry
	// can't keep gating after the upstream has retracted it.
	Withdrawn time.Time `json:"withdrawn"`
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

// Parse decodes one OSV JSON document. Callers filter to malware findings
// via IsMalware (cheaper than tagging the verdict here, since most callers
// already need the full Advisory for reporting).
func Parse(payload []byte) (Advisory, error) {
	var adv Advisory
	if err := json.Unmarshal(payload, &adv); err != nil {
		return Advisory{}, errors.With(err, "decode osv advisory")
	}
	return adv, nil
}

// IsMalware reports whether an advisory looks like an actionable malware
// report: MAL-* ID AND not withdrawn. Withdrawn advisories have been
// explicitly retracted by the upstream (usually as false positives) and
// must not gate, even though the entry remains in the feed for audit
// continuity. Filtering at this boundary closes the false-positive case
// where a withdrawn MAL-* keeps refusing a clean package indefinitely.
func IsMalware(adv Advisory) bool {
	if !strings.HasPrefix(adv.ID, "MAL-") {
		return false
	}
	if !adv.Withdrawn.IsZero() {
		return false
	}
	return true
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
		}

		// Ranges — emit one report per parsed interval with Range set and
		// Version empty. Store.Lookup tests interval membership at query
		// time via the per-ecosystem comparator; an unbounded interval
		// (`{introduced: "0"}` with no upper bound) short-circuits the
		// comparator and refuses every version, which is what the
		// pre-range-aware emitter was doing too.
		for _, r := range aff.Ranges {
			// GIT ranges are commit-SHA intervals and don't map onto the
			// (eco, name, version) lookup model — skip rather than mint
			// an entry that can never match a sensible install ref.
			if strings.EqualFold(r.Type, "GIT") {
				continue
			}
			for _, vr := range parseRangeEvents(r.Events) {
				out = append(out, intel.MalwareReport{
					PackageRef:  intel.PackageRef{Ecosystem: eco, Name: aff.Package.Name},
					SourceID:    sourceID,
					Reason:      reason,
					AdvisoryID:  adv.ID,
					PublishedAt: adv.Published,
					Range:       &vr,
				})
			}
		}
	}
	return out
}

// parseRangeEvents walks an OSV range's event list and reconstructs the
// implied intervals. The OSV spec encodes intervals as an ordered
// sequence: an `introduced` event opens an interval, the next `fixed`
// (exclusive upper bound) or `last_affected` (inclusive upper bound)
// event closes it, and a subsequent `introduced` opens the next one.
//
// Real-world feeds occasionally emit unusual shapes — multiple
// `introduced` events without an interleaved closer, a closer with no
// preceding `introduced`. We emit a best-effort interval per
// `introduced` (or per stray closer) rather than silently dropping
// data: a malformed feed should over-block, not under-block.
func parseRangeEvents(events []Event) []intel.VersionRange {
	var out []intel.VersionRange
	cur := intel.VersionRange{}
	have := false
	flush := func() {
		if have {
			out = append(out, cur)
		}
		cur = intel.VersionRange{}
		have = false
	}
	for _, e := range events {
		switch {
		case e.Introduced != "":
			// New interval opens. Flush whatever was in progress.
			flush()
			cur.Introduced = e.Introduced
			have = true
		case e.Fixed != "":
			cur.Fixed = e.Fixed
			have = true
			flush()
		case e.LastAffected != "":
			cur.LastAffected = e.LastAffected
			have = true
			flush()
		}
	}
	flush()
	return out
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
