// Package agentsurface audits agent hooks, MCP configs, and launchd surfaces.
package agentsurface

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/brynbellomy/go-utils/errors"

	"github.com/brynbellomy/veto/internal/scan"
)

// Options configures an agent-surface Scanner.
type Options struct {
	Home         string
	ProjectRoots []string
}

// Scanner audits agent configuration and persistence surfaces.
type Scanner struct {
	home         string
	projectRoots []string
}

var _ scan.Scanner = (*Scanner)(nil)

// New builds an agent-surface scanner.
func New(opts Options) *Scanner {
	return &Scanner{home: opts.Home, projectRoots: append([]string{}, opts.ProjectRoots...)}
}

// Scan implements scan.Scanner.
func (s *Scanner) Scan(ctx context.Context) scan.Result {
	result := scan.Result{}
	for _, target := range s.targets() {
		if err := ctx.Err(); err != nil {
			result.Errors = append(result.Errors, err)
			return result
		}
		info, err := os.Stat(target.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			result.Errors = append(result.Errors, errors.With(err, "stat agent surface path").Set("path", target.path))
			continue
		}
		if info.IsDir() {
			if err := filepath.WalkDir(target.path, func(path string, entry fs.DirEntry, walkErr error) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				if walkErr != nil {
					result.Errors = append(result.Errors, errors.With(walkErr, "walk agent surface path").Set("path", path))
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
				if !target.accept(path) {
					return nil
				}
				findings, err := scanFile(path, target.owner)
				result.FilesScanned++
				result.Findings = append(result.Findings, findings...)
				if err != nil {
					result.Errors = append(result.Errors, err)
				}
				return nil
			}); err != nil {
				result.Errors = append(result.Errors, errors.With(err, "walk agent surface root").Set("path", target.path))
			}
			continue
		}
		findings, err := scanFile(target.path, target.owner)
		result.FilesScanned++
		result.Findings = append(result.Findings, findings...)
		if err != nil {
			result.Errors = append(result.Errors, err)
		}
	}
	result.Findings = append(result.Findings, s.scanLaunchdDisabled(ctx)...)
	return result
}

type target struct {
	owner  string
	path   string
	accept func(string) bool
}

func (s *Scanner) targets() []target {
	acceptConfig := func(path string) bool {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json", ".toml", ".yaml", ".yml", ".js", ".ts", ".sh", ".mdc", ".txt", ".plist":
			return true
		default:
			return filepath.Base(path) == "command.txt"
		}
	}
	var out []target
	if s.home != "" {
		out = append(out,
			target{owner: "claude", path: filepath.Join(s.home, ".claude", "settings.json"), accept: acceptConfig},
			target{owner: "claude", path: filepath.Join(s.home, ".claude", "settings.local.json"), accept: acceptConfig},
			target{owner: "claude", path: filepath.Join(s.home, ".claude", "hooks"), accept: acceptConfig},
			target{owner: "codex", path: filepath.Join(s.home, ".codex", "config.toml"), accept: acceptConfig},
			target{owner: "cursor", path: filepath.Join(s.home, ".cursor", "mcp.json"), accept: acceptConfig},
			target{owner: "sirene", path: filepath.Join(s.home, ".sirene"), accept: acceptConfig},
			target{owner: "launchd", path: filepath.Join(s.home, "Library", "LaunchAgents"), accept: acceptConfig},
		)
		if runtime.GOOS == "darwin" && s.home == currentUserHome() {
			out = append(out, target{owner: "launchd", path: "/Library/LaunchAgents", accept: acceptConfig})
		}
	}
	for _, root := range s.projectRoots {
		if root == "" {
			continue
		}
		out = append(out,
			target{owner: "claude", path: filepath.Join(root, ".claude"), accept: acceptConfig},
			target{owner: "cursor", path: filepath.Join(root, ".cursor"), accept: acceptConfig},
			target{owner: "sirene", path: filepath.Join(root, ".sirene"), accept: acceptConfig},
		)
	}
	return out
}

func scanFile(path, owner string) ([]scan.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.With(err, "read agent surface file").Set("path", path)
	}
	text := string(data)
	redacted := redact(text)
	var findings []scan.Finding
	if strings.Contains(text, "SessionStart") {
		sev := scan.SeverityInfo
		title := "agent SessionStart hook configured"
		remediation := "Confirm this startup hook is expected."
		if suspiciousCommand(text) {
			sev = scan.SeverityMedium
			title = "agent SessionStart hook invokes suspicious command surface"
			remediation = "Remove the hook or rewrite it to use pinned, locally verified tooling."
		}
		findings = append(findings, finding(owner, path, "session-start", sev, title, remediation, evidenceSnippets(redacted)...))
	}
	if looksLikeMCPConfig(path, text) && fetchAndRunCommand(text) {
		findings = append(findings, finding(owner, path, "mcp-fetch-run", scan.SeverityMedium,
			"MCP server config uses fetch-and-run package command",
			"Pin and preinstall MCP server packages, or route the command through veto-controlled wrappers.",
			evidenceSnippets(redacted)...))
	}
	if owner == "launchd" && launchdSuspicious(text) {
		sev := scan.SeverityMedium
		if strings.Contains(text, "com.user.kitty-monitor") {
			sev = scan.SeverityLow
		}
		findings = append(findings, finding(owner, path, "launchd", sev,
			"launchd entry references suspicious command surface",
			"Inspect and unload the launch agent if it is not expected.",
			evidenceSnippets(redacted)...))
	}
	if owner == "sirene" && filepath.Base(path) == "command.txt" && suspiciousCommand(text) {
		findings = append(findings, finding(owner, path, "sirene-command", scan.SeverityLow,
			"Sirene CLI log contains package-manager command",
			"Review whether this command went through veto and whether it installed untrusted tooling.",
			evidenceSnippets(redacted)...))
	}
	return findings, nil
}

func (s *Scanner) scanLaunchdDisabled(ctx context.Context) []scan.Finding {
	if s.home == "" || runtime.GOOS != "darwin" {
		return nil
	}
	if s.home != currentUserHome() {
		return nil
	}
	uid := os.Getuid()
	cmd := exec.CommandContext(ctx, "launchctl", "print-disabled", "gui/"+strconv.Itoa(uid))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return []scan.Finding{{
			ID:       "agent-surface:launchd-disabled:unavailable",
			Surface:  scan.SurfaceAgentSurface,
			Severity: scan.SeverityInfo,
			Title:    "launchd disabled-label audit unavailable",
			Evidence: []scan.Evidence{
				{Label: "owner", Value: "launchd"},
				{Label: "error", Value: redact(strings.TrimSpace(string(out)) + " " + err.Error())},
			},
			Remediation: "Run `launchctl print-disabled gui/$UID` manually if launchd persistence is in scope.",
		}}
	}
	text := string(out)
	if !strings.Contains(text, "com.user.kitty-monitor") {
		return nil
	}
	return []scan.Finding{{
		ID:          "agent-surface:launchd-disabled:com.user.kitty-monitor",
		Surface:     scan.SurfaceAgentSurface,
		Severity:    scan.SeverityLow,
		Title:       "launchd disabled-label residue references com.user.kitty-monitor",
		Evidence:    []scan.Evidence{{Label: "owner", Value: "launchd"}, {Label: "label", Value: "com.user.kitty-monitor"}},
		Remediation: "Treat this as residual evidence unless a matching active plist or process is present.",
	}}
}

func finding(owner, path, kind string, severity scan.Severity, title, remediation string, evidence ...scan.Evidence) scan.Finding {
	return scan.Finding{
		ID:          fmt.Sprintf("agent-surface:%s:%s:%s", owner, kind, path),
		Surface:     scan.SurfaceAgentSurface,
		Severity:    severity,
		Path:        path,
		Title:       title,
		Evidence:    append([]scan.Evidence{{Label: "owner", Value: owner}}, evidence...),
		Remediation: remediation,
	}
}

func evidenceSnippets(text string) []scan.Evidence {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if suspiciousCommand(trimmed) || strings.Contains(trimmed, "SessionStart") || strings.Contains(trimmed, "com.user.kitty-monitor") {
			if len(trimmed) > 240 {
				trimmed = trimmed[:240] + "..."
			}
			return []scan.Evidence{{Label: "snippet", Value: trimmed}}
		}
	}
	return nil
}

func looksLikeMCPConfig(path, text string) bool {
	lowerPath := strings.ToLower(path)
	lowerText := strings.ToLower(text)
	return strings.Contains(lowerPath, "mcp") || strings.Contains(lowerText, "mcp") || strings.Contains(lowerText, "modelcontextprotocol")
}

func fetchAndRunCommand(text string) bool {
	lower := strings.ToLower(text)
	patterns := []string{"npx", "pnpx", "pnpm dlx", "bunx", "uvx", "pipx"}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func suspiciousCommand(text string) bool {
	lower := strings.ToLower(text)
	patterns := []string{"npx", "pnx", "pnpm dlx", "bunx", "uvx", "pipx", " npm ", " pnpm ", " yarn ", " bun ", " pip ", "curl", "wget", "bash -c", "sh -c", "http://", "https://"}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return packageCommandRE.MatchString(text)
}

func launchdSuspicious(text string) bool {
	if strings.Contains(text, "com.user.kitty-monitor") {
		return true
	}
	return suspiciousCommand(text) || strings.Contains(strings.ToLower(text), "/.cache/") || strings.Contains(strings.ToLower(text), "/_npx/")
}

var (
	packageCommandRE = regexp.MustCompile(`(?i)(^|[^a-z0-9_-])(npm|pnpm|yarn|bun|pip|pip3|uv)(\s|["',\]])`)
	secretLine       = regexp.MustCompile(`(?i)(token|secret|password|api[_-]?key)(["'\s:=]+)([^"'\s,}]+)`)
)

func redact(text string) string {
	return secretLine.ReplaceAllString(text, "$1$2<redacted>")
}

func currentUserHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

func shouldPruneDir(name string) bool {
	switch name {
	case ".git", "node_modules", ".venv", "venv", "env":
		return true
	default:
		return false
	}
}
