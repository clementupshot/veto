# Phase 0 — Dep pre-flight report

Date: 2026-05-25
Scanned-with veto SHA: 74c102d2b611e0296a40f04c3c2ce55acba9effe
Intel store snapshot: 637,343 reports across 4 sources (aikido, openssf, osv, pypa); refreshed 2026-05-25T15:38:56Z

## Method

For each candidate Go library:

1. `veto go get <pkg>@latest` against a throwaway scratch module — exercises the Go live-gating path (verifies the name and resolved version are not in any malware feed).
2. `veto scan --root <module-cache-path> --no-caches --no-agent-surface --json` — static scan of the candidate's source tree, including its `go.mod` and `go.sum`. `packages_checked` includes direct + transitive dependencies declared by the candidate.

Both checks run with the same intel-store snapshot. The Go module cache (`~/go/pkg/mod/<path>@<version>`) is the trusted source of the unpacked tree — scoped to the exact version resolved by step 1.

## Verdicts

| Library | Version | `veto go get` verdict | `veto scan` packages checked | findings | errors | Recommendation |
|---|---|---|---|---|---|---|
| `mvdan.cc/sh/v3` | v3.13.1 | allow | 29 | 0 | 0 | **adopt at v3.13.1** |
| `golang.org/x/mod` | v0.36.0 | allow | 2 | 0 | 0 | **adopt at v0.36.0** |
| `github.com/aquasecurity/go-pep440-version` | v0.0.1 | allow | 13 | 0 | 0 | **adopt at v0.0.1** |
| `github.com/pelletier/go-toml/v2` | v2.2.4 | n/a — already a direct dep | n/a | n/a | n/a | **already adopted (no action)** |

## Notes

- `mvdan.cc/sh/v3@v3.13.1` pulled one transitive (`mvdan.cc/sh v2.6.4+incompatible` for backwards-compat shims). The 29-package count includes its full module-graph transitives — none flagged.
- `golang.org/x/mod@v0.36.0` upgraded our existing pin from `v0.29.0`. The package count of 2 reflects that `golang.org/x/mod` has very few direct deps (it's near the bottom of the stdlib-adjacent stack). No flagged entries.
- `aquasecurity/go-pep440-version@v0.0.1` pulled `aquasecurity/go-version@v0.0.1` and `golang.org/x/xerrors`. 13 packages checked. None flagged.
- `pelletier/go-toml/v2` is already at `v2.2.4` in `go.mod`. Phase 3.4 uses it without a version bump; no separate scan needed.

## Phase 3 task gating

| Phase 3 task | Status |
|---|---|
| 3.1 L1 analyzer → `mvdan.cc/sh/v3` | **green light** at v3.13.1 |
| 3.2 gomod → `golang.org/x/mod` | **green light** at v0.36.0 |
| 3.3 PEP 440 → `aquasecurity/go-pep440-version` | **green light** at v0.0.1 |
| 3.4 Codex/Cargo TOML → `pelletier/go-toml/v2` | **green light** (already on v2.2.4) |

All four Phase 3 tasks proceed.

## Limitations

- `veto scan` walks the candidate's `go.mod`/`go.sum` for transitive coverage. Indirect-only transitives pulled by *Phase 3*'s integration (i.e., dependencies that veto itself doesn't already have) appear in the candidate's `go.mod` and so are covered.
- The scan does not execute the library's code. Build-time supply-chain attacks (compromised toolchain, post-install hooks) are outside veto's command-layer model, as documented in the README's "Known limitations" section.
- Re-scan before any minor version bump. The recommendations above pin to the exact versions tested.
