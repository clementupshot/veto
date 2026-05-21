package osvschema_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/intel/osvschema"
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
	require.Empty(t, reports[0].Version, "all-versions advisory should produce empty Version")
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

func TestReportsSkipsUnknownEcosystem(t *testing.T) {
	adv, err := osvschema.Parse([]byte(advisoryUnknownEcosystem))
	require.NoError(t, err)
	reports := osvschema.Reports(adv, "osv")
	require.Empty(t, reports)
}

func TestReportsBoundedRangeNotAllVersions(t *testing.T) {
	// "introduced: 0, fixed: 2.0.0" means versions <2.0.0 are bad, NOT all versions.
	// We currently don't emit per-version reports for ranges (only for explicit
	// versions lists); a bounded range with no explicit versions should produce
	// no reports — refining range expansion is future work.
	adv, err := osvschema.Parse([]byte(advisoryRangeWithFix))
	require.NoError(t, err)
	reports := osvschema.Reports(adv, "osv")
	require.Empty(t, reports)
}
