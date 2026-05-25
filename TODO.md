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
- Add Go/Cargo cache scanning and quarantine coverage: discover `$GOMODCACHE`,
  `~/go/pkg/mod`, `~/.cargo/registry`, and `~/.cargo/git`; identify package and
  version metadata conservatively; purge only confirmed flagged artifacts inside
  known cache roots.
- Extend `install-all` and `doctor` to cover agent posture beyond Claude: Codex
  PATH inheritance policy, Cursor project/global rule posture where inspectable,
  and Sirene launch-environment coverage where inspectable.
- Expand Layer 4 wrapper discovery to pyenv- and nvm-managed package-manager
  binaries, with tests for versioned install dirs and upgrade drift.
- Add safe resolver pre-scans beyond npm where practical, starting with
  Python-family package managers and then Go/Cargo if their tooling can resolve
  without executing project code.
- Improve Go/Cargo project-root discovery for project preflight: walk upward for
  `go.mod`, `Cargo.toml`, and Cargo workspace roots when commands run from
  nested directories without explicit path flags.
- Decide whether IOC-only cache residue can be promoted from report-only to
  purge-safe quarantine rules.
- Choose and add an explicit license before public distribution.
