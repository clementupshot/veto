package intel

import (
	"github.com/Masterminds/semver/v3"
	"github.com/rs/zerolog/log"
)

// VersionRange is a contiguous interval of affected versions. Mirrors
// OSV's range events: Introduced is the inclusive lower bound; one of
// Fixed (exclusive) or LastAffected (inclusive) is the upper bound.
// An empty Introduced or "0" means "from the start." Both Fixed and
// LastAffected empty means "open-ended on the right" (all versions
// from Introduced onward).
//
// VersionRange lives at the intel boundary (not in a specific source
// package) because the Store consults it on every Lookup and we don't
// want a source-specific type leaking into the lookup hot path. Sources
// translate their own range representations into this shape on ingest.
type VersionRange struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

// IsUnbounded reports whether this range covers every version
// (Introduced is "0" or "" and no upper bound). Used as a cheap
// short-circuit so callers don't need to invoke an ecosystem
// version-comparator for the very common "all versions" case —
// most OSV malicious-package advisories use `{introduced: "0"}` to
// flag every version of a package, and short-circuiting here avoids
// touching the per-ecosystem parser for those entries.
func (r VersionRange) IsUnbounded() bool {
	return (r.Introduced == "" || r.Introduced == "0") && r.Fixed == "" && r.LastAffected == ""
}

// InRange reports whether version v falls within rng under the
// comparison rules for ecosystem eco.
//
// Semantics:
//   - rng.IsUnbounded() short-circuits to true without parsing.
//   - Introduced empty or "0" → no lower bound.
//   - Fixed (exclusive) and LastAffected (inclusive) are alternative
//     upper bounds; if both are present we prefer Fixed (OSV spec
//     forbids the combination, but if a feed produces it we pick
//     the tighter bound to stay conservative).
//   - Parse errors → true (over-block). For a malware gate, refusing
//     a clean install is annoying; allowing a flagged install is the
//     failure mode the gate exists to prevent.
//
// npm uses Masterminds/semver/v3 which handles pre-release ordering
// per the semver 2.0.0 spec. PyPI is not implemented today and returns
// true conservatively while logging a debug-level note. That means an
// opt-in vulnerability feed with a bounded PyPI range may over-block
// until PEP 440 range matching lands, but it will not under-block.
//
// InRange lives in the intel package — rather than a sub-package —
// so the Store's Lookup can call it without introducing an import
// cycle through the shared VersionRange/Ecosystem types.
func InRange(eco Ecosystem, v string, rng VersionRange) bool {
	if rng.IsUnbounded() {
		return true
	}
	switch eco {
	case EcosystemNPM:
		return inRangeSemver(v, rng)
	case EcosystemGo:
		return inRangeSemver(NormalizeVersion(eco, v), normalizeRangeVersions(eco, rng))
	case EcosystemCrates:
		return inRangeSemver(v, rng)
	case EcosystemPyPI:
		log.Debug().
			Str("version", v).
			Interface("range", rng).
			Msg("intel.InRange: PyPI bounded-range matching not implemented; over-blocking")
		return true
	default:
		log.Debug().
			Str("ecosystem", string(eco)).
			Str("version", v).
			Interface("range", rng).
			Msg("intel.InRange: unknown ecosystem; over-blocking")
		return true
	}
}

func normalizeRangeVersions(eco Ecosystem, rng VersionRange) VersionRange {
	rng.Introduced = NormalizeVersion(eco, rng.Introduced)
	rng.Fixed = NormalizeVersion(eco, rng.Fixed)
	rng.LastAffected = NormalizeVersion(eco, rng.LastAffected)
	return rng
}

// inRangeSemver answers InRange for ecosystems that follow semver
// 2.0.0. Returns true on any parse error so a malformed query or feed value
// over-blocks.
func inRangeSemver(v string, rng VersionRange) bool {
	ver, err := semver.NewVersion(v)
	if err != nil {
		log.Debug().
			Err(err).
			Str("version", v).
			Msg("intel.InRange: failed to parse query version; over-blocking")
		return true
	}

	// Lower bound — inclusive on Introduced. Empty or "0" means no lower bound.
	if rng.Introduced != "" && rng.Introduced != "0" {
		lo, err := semver.NewVersion(rng.Introduced)
		if err != nil {
			log.Debug().
				Err(err).
				Str("introduced", rng.Introduced).
				Msg("intel.InRange: failed to parse Introduced; over-blocking")
			return true
		}
		if ver.LessThan(lo) {
			return false
		}
	}

	// Upper bound — prefer Fixed (exclusive) when both are set.
	if rng.Fixed != "" {
		hi, err := semver.NewVersion(rng.Fixed)
		if err != nil {
			log.Debug().
				Err(err).
				Str("fixed", rng.Fixed).
				Msg("intel.InRange: failed to parse Fixed; over-blocking")
			return true
		}
		// Fixed is exclusive: v < hi means in-range.
		if !ver.LessThan(hi) {
			return false
		}
		return true
	}
	if rng.LastAffected != "" {
		hi, err := semver.NewVersion(rng.LastAffected)
		if err != nil {
			log.Debug().
				Err(err).
				Str("last_affected", rng.LastAffected).
				Msg("intel.InRange: failed to parse LastAffected; over-blocking")
			return true
		}
		// LastAffected is inclusive: v <= hi means in-range.
		if ver.GreaterThan(hi) {
			return false
		}
		return true
	}

	// No upper bound — open-ended.
	return true
}
