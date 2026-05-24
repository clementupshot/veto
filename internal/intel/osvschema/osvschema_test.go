package osvschema_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/osvschema"
)

const advisoryAllVersions = `{
  "id": "MAL-2022-2",
  "summary": "Malicious code in --hiljson (npm)",
  "published": "2022-12-07T23:30:57Z",
  "affected": [
    {
      "package": {"ecosystem": "npm", "name": "--hiljson"},
      "ranges": [
        {"type": "SEMVER", "events": [{"introduced": "0"}]}
      ]
    }
  ]
}`

const advisoryExplicitVersions = `{
  "id": "MAL-2024-5",
  "summary": "evil pkg",
  "published": "2024-05-01T00:00:00Z",
  "affected": [
    {
      "package": {"ecosystem": "PyPI", "name": "evil-py"},
      "versions": ["1.0.0", "1.0.1"]
    }
  ]
}`

const advisoryNotMalware = `{
  "id": "GHSA-1234-5678-90ab",
  "summary": "regular CVE",
  "affected": [
    {"package": {"ecosystem": "npm", "name": "vulnerable"}, "versions": ["1.0.0"]}
  ]
}`

const advisoryUnknownEcosystem = `{
  "id": "MAL-2024-7",
  "summary": "rust thing",
  "affected": [
    {
      "package": {"ecosystem": "crates.io", "name": "evil-crate"},
      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
    }
  ]
}`

const advisoryRangeWithFix = `{
  "id": "MAL-2024-8",
  "summary": "introduced and fixed",
  "affected": [
    {
      "package": {"ecosystem": "npm", "name": "later-good"},
      "ranges": [
        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}
      ]
    }
  ]
}`

func TestReportsAllVersions(t *testing.T) {
	adv, err := osvschema.Parse([]byte(advisoryAllVersions))
	require.NoError(t, err)
	reports := osvschema.Reports(adv, "openssf")
	require.Len(t, reports, 1)
	require.Equal(t, "openssf", reports[0].SourceID)
	require.Equal(t, intel.EcosystemNPM, reports[0].Ecosystem)
	require.Equal(t, "--hiljson", reports[0].Name)
	require.Empty(t, reports[0].Version, "ranged reports must leave Version empty; the interval is on Range")
	require.NotNil(t, reports[0].Range, "all-versions advisory now carries an unbounded Range")
	require.True(t, reports[0].Range.IsUnbounded())
	require.Equal(t, "MAL-2022-2", reports[0].AdvisoryID)
}

func TestReportsExplicitVersions(t *testing.T) {
	adv, err := osvschema.Parse([]byte(advisoryExplicitVersions))
	require.NoError(t, err)
	reports := osvschema.Reports(adv, "osv")
	require.Len(t, reports, 2)
	require.Equal(t, intel.EcosystemPyPI, reports[0].Ecosystem)
	require.Equal(t, "1.0.0", reports[0].Version)
	require.Equal(t, "1.0.1", reports[1].Version)
}

func TestReportsSkipsNonMalware(t *testing.T) {
	adv, err := osvschema.Parse([]byte(advisoryNotMalware))
	require.NoError(t, err)
	require.False(t, osvschema.IsMalware(adv))
	reports := osvschema.Reports(adv, "osv")
	require.Empty(t, reports)
}

func TestVulnerabilityReportsIncludesNonMalware(t *testing.T) {
	adv, err := osvschema.Parse([]byte(advisoryNotMalware))
	require.NoError(t, err)
	reports := osvschema.VulnerabilityReports(adv, "ghsa")
	require.Len(t, reports, 1)
	require.Equal(t, "ghsa", reports[0].SourceID)
	require.Equal(t, "GHSA-1234-5678-90ab", reports[0].AdvisoryID)
	require.Equal(t, "regular CVE", reports[0].Reason)
	require.Equal(t, intel.EcosystemNPM, reports[0].Ecosystem)
	require.Equal(t, "vulnerable", reports[0].Name)
	require.Equal(t, "1.0.0", reports[0].Version)
}

const advisoryWithdrawn = `{
  "id": "MAL-2024-2929",
  "summary": "Malicious code in react (npm)",
  "published": "2024-06-25T12:22:49Z",
  "withdrawn": "2024-07-01T03:32:00Z",
  "affected": [
    {
      "package": {"ecosystem": "npm", "name": "react"},
      "versions": ["35.0.0", "1.0.0"]
    }
  ]
}`

// TestReportsSkipsWithdrawn: an upstream-retracted MAL-* advisory must
// not gate. The OSV `withdrawn` field is the canonical retraction
// signal — the advisory stays in the feed for audit continuity but
// callers must treat it as inactive. Surfaced by a real false positive:
// MAL-2024-2929 ("Malicious code in react") was withdrawn one week after
// publication with details saying "False positive caused by problematic
// ingestion", but the entry kept refusing every `npm install react`
// until this filter landed.
func TestReportsSkipsWithdrawn(t *testing.T) {
	adv, err := osvschema.Parse([]byte(advisoryWithdrawn))
	require.NoError(t, err)
	require.False(t, adv.Withdrawn.IsZero(), "fixture should parse the withdrawn timestamp")
	require.False(t, osvschema.IsActive(adv), "withdrawn advisory must not be active")
	require.False(t, osvschema.IsMalware(adv), "withdrawn advisory must not be treated as malware")
	reports := osvschema.Reports(adv, "osv")
	require.Empty(t, reports, "withdrawn advisory must produce zero reports")
	vulnReports := osvschema.VulnerabilityReports(adv, "ghsa")
	require.Empty(t, vulnReports, "withdrawn vulnerability advisory must produce zero reports")
}

func TestReportsSkipsUnknownEcosystem(t *testing.T) {
	adv, err := osvschema.Parse([]byte(advisoryUnknownEcosystem))
	require.NoError(t, err)
	reports := osvschema.Reports(adv, "osv")
	require.Empty(t, reports)
}

func TestReportsBoundedRangeEmitsRangeReport(t *testing.T) {
	// "introduced: 0, fixed: 2.0.0" means versions <2.0.0 are bad.
	// Range-aware emission attaches the interval to the report so
	// Lookup can test membership at query time. Version stays empty
	// (the report applies to a set of versions, not one specifically).
	adv, err := osvschema.Parse([]byte(advisoryRangeWithFix))
	require.NoError(t, err)
	reports := osvschema.Reports(adv, "osv")
	require.Len(t, reports, 1)
	r := reports[0]
	require.Empty(t, r.Version, "ranged reports must leave Version empty; the interval is on Range")
	require.Equal(t, "later-good", r.Name)
	require.NotNil(t, r.Range, "bounded range must attach a Range")
	require.Equal(t, "0", r.Range.Introduced)
	require.Equal(t, "2.0.0", r.Range.Fixed)
	require.Empty(t, r.Range.LastAffected)
	require.False(t, r.Range.IsUnbounded(), "bounded range must not report IsUnbounded")
}

const advisoryLastAffected = `{
  "id": "MAL-2024-9",
  "summary": "last_affected upper bound",
  "affected": [
    {
      "package": {"ecosystem": "npm", "name": "incl-upper"},
      "ranges": [
        {"type": "SEMVER", "events": [{"introduced": "1.1.5"}, {"last_affected": "1.1.6"}]}
      ]
    }
  ]
}`

func TestReportsLastAffectedRange(t *testing.T) {
	adv, err := osvschema.Parse([]byte(advisoryLastAffected))
	require.NoError(t, err)
	reports := osvschema.Reports(adv, "osv")
	require.Len(t, reports, 1)
	require.NotNil(t, reports[0].Range)
	require.Equal(t, "1.1.5", reports[0].Range.Introduced)
	require.Empty(t, reports[0].Range.Fixed)
	require.Equal(t, "1.1.6", reports[0].Range.LastAffected)
}

const advisoryMultipleEventsPerRange = `{
  "id": "MAL-2024-10",
  "summary": "two intervals in one range",
  "affected": [
    {
      "package": {"ecosystem": "npm", "name": "twin"},
      "ranges": [
        {"type": "SEMVER", "events": [
          {"introduced": "1.161.12"}, {"fixed": "1.161.13"},
          {"introduced": "1.161.9"},  {"fixed": "1.161.13"}
        ]}
      ]
    }
  ]
}`

func TestReportsMultipleEventsPerRange(t *testing.T) {
	// One OSV range whose event list interleaves two [introduced,
	// fixed] pairs must emit TWO interval reports — the dedup key
	// includes the range bounds so each interval survives into the
	// index.
	adv, err := osvschema.Parse([]byte(advisoryMultipleEventsPerRange))
	require.NoError(t, err)
	reports := osvschema.Reports(adv, "osv")
	require.Len(t, reports, 2)
	require.Equal(t, "1.161.12", reports[0].Range.Introduced)
	require.Equal(t, "1.161.13", reports[0].Range.Fixed)
	require.Equal(t, "1.161.9", reports[1].Range.Introduced)
	require.Equal(t, "1.161.13", reports[1].Range.Fixed)
}

const advisoryMultipleRangesPerAffected = `{
  "id": "MAL-2024-11",
  "summary": "two ranges per affected entry",
  "affected": [
    {
      "package": {"ecosystem": "npm", "name": "double"},
      "ranges": [
        {"type": "SEMVER", "events": [{"introduced": "0"}]},
        {"type": "SEMVER", "events": [{"introduced": "1.0.4"}]}
      ]
    }
  ]
}`

func TestReportsMultipleRangesPerAffected(t *testing.T) {
	adv, err := osvschema.Parse([]byte(advisoryMultipleRangesPerAffected))
	require.NoError(t, err)
	reports := osvschema.Reports(adv, "osv")
	require.Len(t, reports, 2)
	require.True(t, reports[0].Range.IsUnbounded())
	require.Equal(t, "1.0.4", reports[1].Range.Introduced)
}

func TestReportsUnboundedRangeIsUnbounded(t *testing.T) {
	adv, err := osvschema.Parse([]byte(advisoryAllVersions))
	require.NoError(t, err)
	reports := osvschema.Reports(adv, "openssf")
	require.Len(t, reports, 1)
	require.NotNil(t, reports[0].Range, "unbounded range must still attach a Range so Lookup's path is uniform")
	require.True(t, reports[0].Range.IsUnbounded(), "introduced=0 with no upper bound is the unbounded shape")
}

const advisoryMixedVersionsAndRanges = `{
  "id": "MAL-2024-12",
  "summary": "explicit versions plus a range",
  "affected": [
    {
      "package": {"ecosystem": "npm", "name": "mixed"},
      "versions": ["0.0.1", "0.0.2"],
      "ranges": [
        {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}
      ]
    }
  ]
}`

func TestReportsMixedVersionsAndRanges(t *testing.T) {
	// Mixed advisories must emit BOTH per-version reports and per-range
	// reports — the pre-rewrite emitter would skip the range when an
	// explicit versions list was present, dropping coverage of versions
	// not in the explicit list.
	adv, err := osvschema.Parse([]byte(advisoryMixedVersionsAndRanges))
	require.NoError(t, err)
	reports := osvschema.Reports(adv, "osv")
	require.Len(t, reports, 3)
	require.Equal(t, "0.0.1", reports[0].Version)
	require.Nil(t, reports[0].Range)
	require.Equal(t, "0.0.2", reports[1].Version)
	require.Nil(t, reports[1].Range)
	require.Empty(t, reports[2].Version)
	require.NotNil(t, reports[2].Range)
	require.Equal(t, "1.0.0", reports[2].Range.Introduced)
	require.Equal(t, "2.0.0", reports[2].Range.Fixed)
}

const advisoryGitRange = `{
  "id": "MAL-2024-13",
  "summary": "GIT range — should be skipped",
  "affected": [
    {
      "package": {"ecosystem": "npm", "name": "git-only"},
      "ranges": [
        {"type": "GIT", "events": [{"introduced": "abc123"}, {"fixed": "def456"}]}
      ]
    }
  ]
}`

func TestReportsSkipsGitRanges(t *testing.T) {
	// GIT ranges are commit-SHA intervals — they don't map onto
	// (eco, name, version) lookups, so emitting them would either
	// create reports that never match (dead weight) or, worse, match
	// incorrectly. Skip the range entirely.
	adv, err := osvschema.Parse([]byte(advisoryGitRange))
	require.NoError(t, err)
	reports := osvschema.Reports(adv, "osv")
	require.Empty(t, reports, "GIT ranges produce no reports")
}
