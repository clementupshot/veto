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
- Phase 1.7.3 (uv side done): the uv `pip compile` prescan now forwards the
  user's resolver-affecting flags (`--index`, `--default-index`, `--index-url`/
  `-i`, `--extra-index-url`, `--find-links`/`-f`, `--index-strategy`,
  `--keyring-provider`, `--prerelease`, `--resolution`, `--python`/`-p`) via
  `forwardResolverFlags`, so private-index installs prescan instead of aborting.
  pip's prescan already forwards these because it reuses the original argv. The
  original `--override` item is uv-only and not yet in the allowlist (add if a
  real use surfaces). NOTE: the earlier "strip `--no-deps` / `--no-build-isolation`"
  idea was dropped as a bug — with `--no-deps` the real install pulls NO
  transitives, so stripping it would over-block deps that never get fetched, and
  `--no-build-isolation` is inert under the forced `--only-binary=:all:`.
- Phase 1.7.4 (done for explicit specs): `uv add` / `uv install` now fall
  through to ResolverPreScan — `addPreScan` compiles the seeded `pyproject.toml`
  plus a synthetic input for the newly-named specs (`uv pip compile pyproject.toml
  veto-uv-requirements.in --format pylock.toml --only-binary :all:`), so the new
  package's transitive tree is gated before the install runs instead of relying
  on the now-stale (or absent) `uv.lock`. Remaining: `uv add -r requirements.txt`
  (no positional spec) still falls back to requirements-file expansion without a
  transitive probe; project-level `uv sync` continues to rely on the locked tree.
- Phase 1.7.5 (dev-deps + PEP 735 done): pymanifest now walks PEP 735
  `[dependency-groups]`, uv's legacy `[tool.uv] dev-dependencies`, and
  `[tool.pdm.dev-dependencies]`, closing the direct-dependency fail-open
  where a package declared only in those sections sailed through
  `uv sync` / `pdm install` on a fresh checkout (no lockfile). Remaining:
  `[tool.uv.workspace] members` (needs recursive per-member pyproject
  walking for monorepos) and `[tool.uv.sources]` (can redirect a named dep
  to a git/url; the name-keyed gate still fires, but the opaque-remote
  fetch isn't surfaced).
- Phase 1.8.2 deferred: cargo coverage still needs `publish` in
  ParseInstalls (it fetches + builds); `doc`, `package` added to
  ProjectPreflight (they run build.rs / proc-macros);
  `cargomanifest` registry classifier (non-crates-io `registry = ...`
  should be OpaqueRemote, mirroring cargolock); and `[workspace]`
  members expansion for monorepo Cargo.toml roots.
- Add an authenticated online lookup layer for vulnerability surfaces that do
  not fit the cached bulk-source model yet, especially Socket.dev vuln data and
  SafeDep PMG real-time package analysis.
- Add remaining safe resolver pre-scans where practical: project-level uv verbs,
  poetry, and pdm next for Python-family workflows, then Go/Cargo only if their
  tooling can resolve without executing project code.
- Decide whether IOC-only cache residue can be promoted from report-only to
  purge-safe quarantine rules.
- Choose and add an explicit license before public distribution.
