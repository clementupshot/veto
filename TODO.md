# TODO

Actionable follow-ups moved out of the README so the README stays focused on
current user-facing behavior.

- Verify Linux end-to-end: interposer build, shell integration, and Layer 4
  wrapper discovery for common Linux installs, including mise/asdf-managed
  package-manager binaries.
- Add an authenticated online lookup layer for vulnerability surfaces that do
  not fit the cached bulk-source model yet, especially Socket.dev vuln data and
  SafeDep PMG real-time package analysis.
- Track source report-count drops over time and alert on suspicious declines
  that remain above the current 1000-report sanity floor.
- Implement PEP 440 bounded-range matching for PyPI advisories instead of the
  current safe over-block behavior.
- Add remaining safe resolver pre-scans where practical: uv/poetry/pdm next for
  Python-family workflows, then Go/Cargo only if their tooling can resolve
  without executing project code.
- Improve Go/Cargo project-root discovery for project preflight: walk upward for
  `go.mod`, `Cargo.toml`, and Cargo workspace roots when commands run from
  nested directories without explicit path flags.
- Decide whether IOC-only cache residue can be promoted from report-only to
  purge-safe quarantine rules.
- Choose and add an explicit license before public distribution.
