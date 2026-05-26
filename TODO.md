# TODO

Actionable follow-ups moved out of the README so the README stays focused on
current user-facing behavior.

- Verify Linux end-to-end: interposer build, shell integration, and Layer 4
  wrapper discovery for common Linux installs, including mise/asdf-managed
  package-manager binaries.
- Phase 1.4.2 deferred: add e2e coverage for `execvpe`, `fexecve`, and
  `execveat` (Linux-only) by extending `cmd/veto/testdata/interpose_spawner`
  with cgo helpers and a `--mode` flag. The Phase 1.4.1 fix (synthetic
  envp via `snapshot_environ` + `rewrite_envp`) closes the actual
  security finding; this task only adds regression coverage for the
  three Linux-only exec variants. Best done from a Linux box / CI.
- Phase 1.6.2 deferred: route `pnpm dlx` / `yarn dlx` / `bun x` /
  `bun create` through `internal/packagemanager/exec.Manager` so the
  `--package=<spec>` flag is honored and trailing positionals after
  the spec are not over-gated. Today these verbs go through
  `jsspec.ParseInstallArgs` which treats every positional as a spec.
- Phase 1.6.5 partial: jsmanifest does NOT yet walk `workspaces`
  glob patterns recursively. The lockfile expanders pick up
  workspace-member deps in practice (the resolver writes them
  through), but the manifest path on a fresh-checkout monorepo
  misses them.
- Phase 1.6 followup: gate `jsspec.tryParseAlias` on
  `isLegalNpmName(name)` so `user/repo@npm:evil@1` is treated as
  github-shorthand (OpaqueRemote) rather than alias-unwrapped to
  `evil`. Minor precedence quirk; no known exploit path in argv.
- Add an authenticated online lookup layer for vulnerability surfaces that do
  not fit the cached bulk-source model yet, especially Socket.dev vuln data and
  SafeDep PMG real-time package analysis.
- Add remaining safe resolver pre-scans where practical: project-level uv verbs,
  poetry, and pdm next for Python-family workflows, then Go/Cargo only if their
  tooling can resolve without executing project code.
- Decide whether IOC-only cache residue can be promoted from report-only to
  purge-safe quarantine rules.
- Choose and add an explicit license before public distribution.
