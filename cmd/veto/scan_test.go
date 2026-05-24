package main

import (
	"testing"

	"github.com/brynbellomy/veto/internal/scan"

	"github.com/stretchr/testify/require"
)

func TestParseScanFlagsDefaultIsComprehensive(t *testing.T) {
	opts, err := parseScanFlags(nil, defaultScanOpts())
	require.NoError(t, err)
	require.True(t, opts.projects)
	require.True(t, opts.caches)
	require.True(t, opts.agentSurface)
	require.False(t, opts.json)
}

func TestParseScanFlagsCanNarrowSurfaces(t *testing.T) {
	opts, err := parseScanFlags([]string{"--root", "/tmp/projects", "--json", "--no-caches", "--no-agent-surface"}, defaultScanOpts())
	require.NoError(t, err)
	require.Equal(t, []string{"/tmp/projects"}, opts.roots)
	require.True(t, opts.projects)
	require.False(t, opts.caches)
	require.False(t, opts.agentSurface)
	require.True(t, opts.json)
}

func TestParseScanFlagsRejectsUnknown(t *testing.T) {
	_, err := parseScanFlags([]string{"--all"}, defaultScanOpts())
	require.Error(t, err)
}

func TestParseScanFlagsRejectsEmptySurfaceSet(t *testing.T) {
	_, err := parseScanFlags([]string{"--no-projects", "--no-caches", "--no-agent-surface"}, defaultScanOpts())
	require.Error(t, err)
}

func TestQuarantinePurgeExitCodeSucceedsWhenAllActionableFindingsDeleted(t *testing.T) {
	report := scan.Report{
		Summary:  scan.Summary{Actionable: 1},
		Findings: []scan.Finding{{ID: "finding", Severity: scan.SeverityHigh}},
	}
	actions := []scan.PurgeAction{{FindingID: "finding", Status: "deleted"}}

	require.Equal(t, exitOK, quarantinePurgeExitCode(report, actions))
}

func TestQuarantinePurgeExitCodeRefusesWhenActionableFindingRemains(t *testing.T) {
	report := scan.Report{
		Summary:  scan.Summary{Actionable: 1},
		Findings: []scan.Finding{{ID: "finding", Severity: scan.SeverityHigh}},
	}
	actions := []scan.PurgeAction{{FindingID: "finding", Status: "failed", Error: "permission denied"}}

	require.Equal(t, exitRefused, quarantinePurgeExitCode(report, actions))
}
