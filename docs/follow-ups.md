# Recommended follow-ups

Tracked here so the brynbellomy/veto issue tracker doesn't lose them.
Each entry has enough context to be opened as a GitHub issue without
digging through PR history.

## Open as GitHub issues against brynbellomy/veto

### 1. Feed signature / checksum verification (intel sources)

Every fetched feed (aikido, openssf, osv, pypa) should be verified
against a published manifest of known-good checksums or a publisher
signature before being trusted as input to the gate. Today the
sources rely on HTTPS + etag-based revalidation, which catches
in-transit tampering only if the TLS chain is intact. A compromised
feed at the upstream end — or a malicious mirror replacing the
upstream URL — is indistinguishable from a legitimate one until the
report counts start drifting (which the H3 partial-drop threshold
catches statistically, not cryptographically).

Concrete shape: per source, a manifest URL or a hard-coded public
key. Sources should refuse to populate the in-memory index if the
signature/checksum doesn't validate. Surfaced in PR #1 review by
author.

Probable effort: M. Depends on each upstream's publishing model;
aikido and openssf currently have no signed manifest at all.

### 2. Layer 4 auto-rewrap on toolchain upgrade

When a package manager updates (e.g. `brew upgrade node`, `mise
install node@<v>`, `asdf install nodejs <v>`), the upstream's
install script replaces the veto symlink at the wrapped path with
the new binary. This silently disables Layer 4 for that PM until
the operator re-runs `veto install-wrappers`.

Two plausible mitigations:

- **launchd watcher** on macOS / inotify on Linux: monitor every
  wrapped path; on replacement (Lstat says regular-file instead of
  symlink), automatically re-wrap. Survives toolchain upgrades
  invisibly to the operator.
- **doctor escalation**: today `veto doctor` already flags drift
  as FAIL with "wrapper replaced by real binary"; if we want to
  keep this manual, escalate it (loud terminal banner, system
  notification, exit-1 from a shell rc hook).

Probable effort: M. The watcher approach requires per-OS plumbing
but is mostly composable with existing wrapper-state plumbing.
Surfaced in PR #1 review by author.

### 3. mockery v3 migration of intel.Source hand-rolled fakes

The internal/intel/store_test.go `fakeSource` and `programmableSource`
are hand-rolled. brynsk-architecture defaults call for mockery-
generated mocks; the `programmableSource`'s "advance fixture after
every ecosystem has been served" bookkeeping is the part that would
benefit most — a mockery mock with a per-test `RunFn` would replace
the `served` map + `calls` counter.

Probable effort: S. Wire mockery for `intel.Source`, regenerate,
migrate the two consumers in store_test.go (and the cross-package
ones in cmd/veto/daemon_test.go, internal/gate/gate_test.go).
Surfaced in PR #1 review by author.

## Why this file exists

The PR author opened these in the PR review with "happy to ship as
follow-up" / "worth a ticket." This repo is small enough that
informal capture in a markdown file is the right granularity until
a GitHub issue is opened.
