// Package scan defines the shared contracts and report model for veto's
// existing-exposure scanners.
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/brynbellomy/veto/internal/intel"
)

// Surface identifies the part of the host a finding came from.
type Surface string

const (
	SurfaceProject      Surface = "project"
	SurfaceCache        Surface = "cache"
	SurfaceAgentSurface Surface = "agent-surface"
)

// Severity is the operator-facing importance of a scan finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Evidence is one small, redacted piece of support for a Finding.
type Evidence struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Finding is a single scanner result. PackageRef and Verdict are populated
// when the finding is tied to package-intel lookup; agent and policy findings
// can use Evidence only.
type Finding struct {
	ID          string            `json:"id"`
	Surface     Surface           `json:"surface"`
	Severity    Severity          `json:"severity"`
	Path        string            `json:"path"`
	Title       string            `json:"title"`
	PackageRef  *intel.PackageRef `json:"package_ref,omitempty"`
	Verdict     *intel.Verdict    `json:"verdict,omitempty"`
	Evidence    []Evidence        `json:"evidence,omitempty"`
	Remediation string            `json:"remediation,omitempty"`

	// PurgePath is intentionally omitted from JSON/text reports. It is used by
	// cache quarantine planning after scanner code has verified the candidate.
	PurgePath string `json:"-"`
}

// Result is the output from one scanner.
type Result struct {
	Findings        []Finding
	Errors          []error
	FilesScanned    int
	PackagesChecked int
}

// Scanner scans one host surface and returns findings plus non-fatal errors.
// Implementations must respect ctx cancellation and avoid mutating the host.
type Scanner interface {
	Scan(ctx context.Context) Result
}

// PurgeAction describes a cache deletion candidate or result.
type PurgeAction struct {
	Path      string `json:"path"`
	Reason    string `json:"reason"`
	FindingID string `json:"finding_id"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

// Summary is the aggregate count block in a scan report.
type Summary struct {
	FilesScanned    int `json:"files_scanned"`
	PackagesChecked int `json:"packages_checked"`
	Findings        int `json:"findings"`
	Actionable      int `json:"actionable"`
	FlaggedPackages int `json:"flagged_packages"`
	ProjectFindings int `json:"project_findings"`
	CacheFindings   int `json:"cache_findings"`
	AgentFindings   int `json:"agent_findings"`
	Errors          int `json:"errors"`
}

// Report is the complete scan result rendered by the CLI.
type Report struct {
	SchemaVersion int           `json:"schema_version"`
	StartedAt     time.Time     `json:"started_at"`
	Roots         []string      `json:"roots"`
	Summary       Summary       `json:"summary"`
	Findings      []Finding     `json:"findings"`
	Errors        []string      `json:"errors,omitempty"`
	PurgeActions  []PurgeAction `json:"purge_actions,omitempty"`
}

// NewReport builds a report and computes summary fields from scanner results.
func NewReport(startedAt time.Time, roots []string, results ...Result) Report {
	report := Report{
		SchemaVersion: 1,
		StartedAt:     startedAt,
		Roots:         append([]string{}, roots...),
		Errors:        []string{},
	}
	for _, result := range results {
		report.Findings = append(report.Findings, result.Findings...)
		report.Summary.FilesScanned += result.FilesScanned
		report.Summary.PackagesChecked += result.PackagesChecked
		for _, err := range result.Errors {
			if err != nil {
				report.Errors = append(report.Errors, err.Error())
			}
		}
	}
	report.Summary.Errors = len(report.Errors)
	for _, f := range report.Findings {
		report.Summary.Findings++
		if IsActionable(f.Severity) {
			report.Summary.Actionable++
		}
		if f.Verdict != nil && f.Verdict.Flagged() {
			report.Summary.FlaggedPackages++
		}
		switch f.Surface {
		case SurfaceProject:
			report.Summary.ProjectFindings++
		case SurfaceCache:
			report.Summary.CacheFindings++
		case SurfaceAgentSurface:
			report.Summary.AgentFindings++
		}
	}
	return report
}

// IsActionable reports whether a severity should make scan exit non-zero.
func IsActionable(sev Severity) bool {
	switch sev {
	case SeverityCritical, SeverityHigh, SeverityMedium:
		return true
	default:
		return false
	}
}

// HasActionable reports whether any finding should make scan exit non-zero.
func HasActionable(findings []Finding) bool {
	for _, f := range findings {
		if IsActionable(f.Severity) {
			return true
		}
	}
	return false
}

// WriteJSON writes a stable JSON representation of the report.
func WriteJSON(w io.Writer, report Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// WriteText writes a concise human-readable scan report.
func WriteText(w io.Writer, report Report) {
	if len(report.Errors) > 0 {
		fmt.Fprintln(w, "veto: scan could not complete confidently")
	} else if report.Summary.Actionable > 0 {
		fmt.Fprintln(w, "veto: scan found exposure")
	} else {
		fmt.Fprintln(w, "veto: scan completed; no actionable exposure found")
	}

	fmt.Fprintf(w, "\nSummary: %d findings (%d actionable), %d flagged packages, %d errors\n",
		report.Summary.Findings, report.Summary.Actionable, report.Summary.FlaggedPackages, report.Summary.Errors)

	if len(report.Findings) > 0 {
		groups := groupBySurface(report.Findings)
		for _, surface := range []Surface{SurfaceProject, SurfaceCache, SurfaceAgentSurface} {
			findings := groups[surface]
			if len(findings) == 0 {
				continue
			}
			fmt.Fprintf(w, "\n%s:\n", surfaceHeading(surface))
			for _, f := range findings {
				fmt.Fprintf(w, "  - [%s] %s\n", f.Severity, f.Title)
				if f.Path != "" {
					fmt.Fprintf(w, "      path: %s\n", f.Path)
				}
				if f.PackageRef != nil {
					fmt.Fprintf(w, "      package: %s %s@%s\n", f.PackageRef.Ecosystem, f.PackageRef.Name, displayVersion(f.PackageRef.Version))
				}
				if f.Verdict != nil && len(f.Verdict.Reports) > 0 {
					for _, r := range f.Verdict.Reports {
						reason := r.Reason
						if reason == "" {
							reason = "flagged"
						}
						fmt.Fprintf(w, "      [%s] %s\n", r.SourceID, reason)
					}
				}
				for _, ev := range f.Evidence {
					fmt.Fprintf(w, "      %s: %s\n", ev.Label, ev.Value)
				}
				if f.Remediation != "" {
					fmt.Fprintf(w, "      fix: %s\n", f.Remediation)
				}
			}
		}
	}

	if len(report.Errors) > 0 {
		fmt.Fprintln(w, "\nErrors:")
		for _, e := range report.Errors {
			fmt.Fprintf(w, "  - %s\n", e)
		}
	}
}

func groupBySurface(findings []Finding) map[Surface][]Finding {
	out := map[Surface][]Finding{}
	for _, f := range findings {
		out[f.Surface] = append(out[f.Surface], f)
	}
	for surface := range out {
		sort.SliceStable(out[surface], func(i, j int) bool {
			if severityRank(out[surface][i].Severity) != severityRank(out[surface][j].Severity) {
				return severityRank(out[surface][i].Severity) > severityRank(out[surface][j].Severity)
			}
			return strings.Compare(out[surface][i].Path, out[surface][j].Path) < 0
		})
	}
	return out
}

func surfaceHeading(surface Surface) string {
	switch surface {
	case SurfaceProject:
		return "Projects"
	case SurfaceCache:
		return "Caches"
	case SurfaceAgentSurface:
		return "Agent surface"
	default:
		return string(surface)
	}
}

func severityRank(sev Severity) int {
	switch sev {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func displayVersion(v string) string {
	if v == "" {
		return "<any>"
	}
	return v
}
