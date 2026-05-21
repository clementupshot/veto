# package-bouncer — statement of intent

> **Status (2026-05-21, post-audit): superseded as the active architecture.**
>
> This doc was written when the planned Phase 2 direction was a
> `sandbox-exec`-based kernel-enforcement daemon. After a follow-up
> external review, the project pivoted back to a multi-layer
> user-space defense (now four layers: Claude hook, PATH shims, native
> execve interposer, and real-binary wrappers). The active design,
> install instructions, and threat model live in
> [`../README.md`](../README.md) and
> [`onboarding.md`](onboarding.md).
>
> This document is retained for reference — the audit history and
> primitives comparison are still useful context — but it does NOT
> describe what's installed by `make install` today. The
> `sandbox-exec` daemon code (`internal/daemon/`, `cmd/bouncer/{client,daemon}.go`)
> is still in the tree as a dormant experimental path; `bouncer daemon`
> exists as a subcommand but is not part of the recommended install
> flow.

**Author**: Bryn Bellomy
**Platform**: macOS 15 (Sequoia). Linux is a possible future target; not in current scope.
**License**: TBD (planning open-source release after security review).
**Last updated**: 2026-05-21.

---

## 1. Purpose

`package-bouncer` is a single-developer self-protection tool that interposes between an autonomous coding agent (Claude Code, Codex, etc.) and the package managers it invokes (`npm`, `pip`, `uv`, `bun`, …). Every install command is parsed, the named packages are looked up against aggregated malware intelligence (Aikido, OpenSSF malicious-packages, OSV), and the install is refused if any source flags any package.

It exists because:
- Coding agents in "auto mode" are unpredictable. They emit `bash -c '…'`, full-path invocations, `subprocess.run(shell=True)`, novel shell constructs. Any defense that relies on parsing the shell command is a treadmill of edge cases.
- Supply-chain worms — most recently the September 2025 "Shai-Hulud" attack against npm, and the early 2026 "mini-shai-hulud" variant — exfiltrate credentials during package install hooks and use those credentials to publish further infected packages. A single missed install during an agent run = full credential compromise and probable lateral propagation.
- Existing tools (Aikido's `safe-chain`, snyk, socket.dev's CLI) are shell-function wrappers or registry-level scanners. They fail open on: agents that exec the PM binary directly, agents inside non-interactive shells that didn't source the shim, package managers whose network behavior bypasses HTTPS proxies (e.g. `bun`).

The previous design used three composing software-layer defenses (Claude Code Bash hook, PATH shims, `DYLD_INSERT_LIBRARIES` interposer). That design was audited in May 2026; the audit found 1 ship-blocker (infinite exec recursion between layers), 4 critical hook-parser bypasses, multiple intel-store integrity gaps, and a long tail of correctness issues in parsers. Audit findings drove the conclusion that **software-layer parsing is the wrong primitive** — the kernel already has the right primitive (`sandbox-exec`'s `process-exec` policy), and the audit's worst bugs all clustered in the parsing layers.

This document describes the current design (kernel-enforcement via `sandbox-exec` + an out-of-sandbox daemon) and identifies what we need the security team to review.

---

## 2. Threat model

### 2.1 Attacker capabilities

- Operates a Large Language Model that controls a coding agent (Claude Code, Codex, etc.) in autonomous mode on the user's macOS workstation.
- Can emit arbitrary shell commands the agent will execute. This includes nested shells (`bash -c "bash -c '…'"`), wrapper composition (`sudo timeout env bash -c '…'`), command substitution (`bash -c "$(echo …)"`), `eval`, `setsid`, `numactl`, every uncommon wrapper that has ever existed on Unix, and constructs that don't yet exist in any LLM's training set.
- Can emit Python that does `subprocess.run([…], shell=False)` with full absolute paths.
- Can emit raw `os.execve` Go programs or any other libc-bypass exec path.
- Can be prompted-injected, jailbroken, or have its training data poisoned by an upstream attacker — we cannot model the *intent* of the agent; only assume it eventually emits the wrong command.

### 2.2 What we are defending

- The user's npm/PyPI credentials, GitHub tokens, AWS keys, browser cookies, SSH keys, and any other credential on the user's macOS workstation that an install hook (`preinstall`, `postinstall`, `prepare`, `setup.py`, etc.) could read.
- The user's published npm/PyPI packages — preventing Shai-Hulud-style propagation where the user's stolen credentials are used to publish infected versions of their own packages.
- The integrity of project source trees on the workstation (preventing in-tree modification of `node_modules`, `~/.npmrc`, shell rc files, etc.).

### 2.3 What we are NOT defending against

- A user typing `BOUNCER_BYPASS=1 npm install evil` themselves. The escape hatch exists; honoring it is a UX decision, not a security failure.
- An attacker with physical access or pre-existing root on the workstation. They can unload the daemon, edit the sandbox profile, replace the bouncer binary.
- A sandbox-escape vulnerability in macOS's sandbox kernel extension. That's Apple's threat surface, not ours.
- Network-layer attacks against the intel feeds beyond TLS (no signature/checksum verification on Aikido or OpenSSF or OSV today — see §6).
- Malware whose payload is not in any of the configured intel sources. We index three sources covering ~620k reports; this is wide but not exhaustive.
- Transitive dependencies whose names don't appear in the install command. A clean-named package whose `setup.py` fetches an unflagged-but-malicious second-level dep is out of scope; bouncer sees install requests, not resolved dependency graphs.

### 2.4 Threat model assertion

> If the user runs their coding agent via `bouncer run-agent <agent>`, no package manager — invoked by any code path, by any shell construct, by any wrapper, by any absolute or relative path — can execute without first having its arguments parsed and gated by the bouncer daemon.

This is the property the design is intended to enforce and the property we need the security team to attempt to break.

---

## 3. Architecture

### 3.1 Components

1. **The agent process tree** — Claude Code, Codex, or any other agent, plus every subprocess it spawns (bash, python, node, etc.). Launched via `bouncer run-agent <name>`, which wraps the launch in `sandbox-exec -f <profile>` so the entire process tree inherits the sandbox.

2. **The sandbox profile** — a generated TinyScheme file (Apple's sandbox profile language) that:
   - Allows `default` (every other syscall and resource).
   - Denies `process-exec` for every covered PM binary path enumerated under `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/share/mise/installs/.../bin`, every common Node version manager dir, etc.
   - Allows `process-exec` for the bouncer binary.
   - Allows `network-outbound` for AF_UNIX sockets to the bouncer daemon's path (so the bouncer CLI inside the sandbox can talk to the out-of-sandbox daemon).

3. **The bouncer CLI** — same binary as the daemon, different subcommand. When invoked inside the sandbox as `bouncer npm install foo` (either directly or via PATH shim), it:
   - Resolves the daemon socket path (`$BOUNCER_DAEMON_SOCKET` or `~/.local/state/bouncer/bouncer.sock`).
   - Connects via `net.Dial("unix", …)`.
   - Sends a `Request` (JSON length-prefixed) containing the PM name, args, cwd, env. Attaches the calling process's stdin/stdout/stderr fds via SCM_RIGHTS.
   - Waits for a `Response` and exits with the daemon's verdict (PM exit code, refusal, internal error).

4. **The bouncer daemon** — same binary, loaded by launchd as a per-user agent. Runs outside the sandbox. Owns:
   - The intel store (in-memory deduplicated index built from Aikido + OpenSSF + OSV, refreshed every 30 min in the background).
   - The Unix socket listener at `~/.local/state/bouncer/bouncer.sock`, parent dir 0700, socket 0600.
   - The gate logic (parse argv → look up each named package → allow/refuse).
   - The actual exec of the real PM, on behalf of the sandboxed client, using `os.StartProcess` with the client's dup'd fds.

5. **The intel sources** — three upstream HTTPS feeds (Aikido, OpenSSF malicious-packages, OSV MAL-* advisories), fetched via `etag`-cached HTTP. Roughly 620k reports indexed today.

### 3.2 Trust boundaries

```
┌──────────────────────────────────────────────────────────────────────┐
│  outside the sandbox (full user privilege)                           │
│  ┌────────────────────────────┐         ┌─────────────────────────┐  │
│  │ launchd (user agent)       │         │ Apple sandbox kernel    │  │
│  │  └─ bouncer daemon         │         │ (enforces process-exec  │  │
│  │      ├─ intel store        │         │  deny rules below)      │  │
│  │      ├─ socket listener    │         └─────────────────────────┘  │
│  │      └─ posix_spawn of PMs │                    │                 │
│  └────────────────────────────┘                    │                 │
│              ▲                                     │                 │
│              │ AF_UNIX socket                      │                 │
│              │ (only IPC across the boundary)      ▼                 │
├──────────────┼─────────────────────────────────────────────────────  │
│              │     inside the sandbox-exec'd subtree                 │
│              │     (denied: process-exec of any real PM)             │
│              │                                                       │
│   ┌──────────┴──────────┐    ┌─────────────────────┐                 │
│   │ agent (Claude/Codex)│    │ subprocess: python, │                 │
│   │  └─ bash shells     │◄──►│ node, ruby, …       │                 │
│   │     └─ bouncer CLI  │    │  └─ exec attempts:  │                 │
│   │        (allowed)    │    │     bash -c "..."   │                 │
│   └─────────────────────┘    │     /full/path/npm  │                 │
│                              │     subprocess.run  │                 │
│                              │      → EPERM        │                 │
│                              └─────────────────────┘                 │
└──────────────────────────────────────────────────────────────────────┘
```

**Trust boundary 1** (sandbox kernel ↔ agent process tree): enforced by macOS, kernel-level. The agent and everything it spawns inherits the deny rules. The only way out is to exec `bouncer` (which the profile allows).

**Trust boundary 2** (sandboxed CLI ↔ daemon, via AF_UNIX socket): the daemon parses the request, runs the gate, and either refuses or execs the real PM on the client's behalf. The daemon owns the only path from inside the sandbox to executing a real package manager.

**Trust boundary 3** (daemon ↔ upstream intel feeds, via HTTPS): TLS only. No signature or checksum verification (see §6).

### 3.3 Data flow

1. Agent emits `npm install foo` (in any form — bare, full path, via bash -c, etc.).
2. Sandbox kernel sees `execve(/opt/homebrew/bin/npm, …)`. Denied per profile. Returns EPERM.
3. Agent's only path forward is to invoke `bouncer npm install foo` (which the profile allows). Possibly via a PATH shim (`~/.local/bin/npm` → bouncer), so the literal `npm install foo` in the agent's shell still works if PATH is configured.
4. bouncer CLI connects to daemon socket, sends Request{pm:"npm", args:[…], cwd, env}, sends stdin/stdout/stderr fds via SCM_RIGHTS.
5. Daemon receives, runs the parser (existing battle-tested code: scoped packages, PEP 508, npm aliases, etc.), looks up each named package against the intel index, returns Allow / Refuse / Abort.
6. On Allow: daemon `os.StartProcess(/opt/homebrew/bin/npm, …)` with the client's stdio fds dup'd onto the child. The PM runs in the daemon's address space (not sandboxed); writes directly to the user's terminal via the passed fds.
7. Daemon `Wait`s for the child, sends exit code back to client.
8. Client exits with that code. Agent sees a normal exit.

On Refuse: daemon sends `StatusRefused` with the reports. Client prints the refusal banner and exits 1. Agent retries or escalates.

---

## 4. Design decisions

### 4.1 Why kernel enforcement (`sandbox-exec`)

The previous design relied on three software interception points (Claude Code hook, PATH shims, `DYLD_INSERT_LIBRARIES` interposer). The May 2026 audit found:

- The Claude Code hook's shell-command parser missed `sudo bash -c '…'`, `eval`, `setsid`, `numactl`, and several other wrapper compositions. Every miss = full Layer 1 bypass.
- The PATH shims could not catch full-path invocations (`/opt/homebrew/bin/npm install …`), which LLMs DO emit sometimes.
- The `DYLD_INSERT_LIBRARIES` interposer:
  - Had a ship-blocking infinite recursion when bouncer execs the real PM (the audit's SHIP-1 finding).
  - Used async-signal-unsafe `calloc` post-fork — deadlock risk under threaded Python.
  - Fails open on `system()`/`popen()` on macOS because `/bin/sh` is SIP-protected and strips `DYLD_INSERT_LIBRARIES`.
  - Cannot hook `execl`/`execlp`/`fexecve` on Linux without per-symbol coverage.
  - Propagates `DYLD_INSERT_LIBRARIES` to every unrelated process spawned by the user's shell, including processes that fail to load the dylib due to arch mismatch (silent fail-open).

These are not implementation bugs that can be fixed — they are fundamental properties of doing exec interception in userspace. Kernel-level `sandbox-exec` does not have any of these issues because the deny check happens at the syscall boundary, before any libc / shell / interposer involvement.

`sandbox-exec` is documented as deprecated since macOS 10.8 (2012) but still works in macOS 15 (2025) and is used by Chromium, Firefox, and Apple's own App Sandbox. The deprecation is a "we may break this" notice, not a removal countdown. If Apple does eventually remove it, the migration target is Endpoint Security framework (`ES_EVENT_TYPE_AUTH_EXEC`), which requires a paid Apple Developer ID and the `com.apple.developer.endpoint-security.client` entitlement — operationally heavier but architecturally identical.

### 4.2 Why a daemon + Unix socket

The sandboxed CLI cannot exec the real PM (the kernel denies it). Something outside the sandbox has to do that exec. Three options were considered:

- **Daemon process** (chosen): a long-running per-user agent loaded via launchd. The CLI talks to it over a Unix socket. Stdio passed via SCM_RIGHTS so no proxy overhead. Single attack surface: one socket, one request type.
- **setuid helper**: `bouncer` itself runs setuid and re-execs the real PM. Rejected because (a) we don't need root; (b) setuid expands the attack surface (PATH, env, arg parsing all need scrutiny); (c) doesn't solve the sandbox-side `execve` deny — the kernel denies based on path, not on UID.
- **`open`-based delegation**: have the sandboxed CLI use `open` (Apple's URL handler) to ask a registered .app to do the install. Rejected because `open`'s contract doesn't propagate exit codes or stdio.

The daemon design is the same pattern Docker, containerd, and gVisor use for the same reason: enforcement primitive is at a privilege the application can't reach.

### 4.3 Why fail-closed everywhere

The threat is supply-chain worms. The cost of a false-positive is "the user has to type `BOUNCER_BYPASS=1` once." The cost of a false-negative is credential compromise + lateral propagation. The asymmetry is enormous. Every doubt resolves toward refusing.

Concretely: the daemon refuses to start if the intel store is unreachable on initial refresh, refuses to gate if the report count is below 1000 (sanity floor for "every source returned empty"), refuses on manifest-parse errors, refuses on socket-protocol errors. The bouncer CLI inside the sandbox does not fall back to "let the install through" under any condition.

### 4.4 Why three aggregated intel sources

No single feed is comprehensive. Aikido reports ~120k npm names; OpenSSF malicious-packages adds ~454k cross-ecosystem; OSV's MAL-* namespace adds tens of thousands more. Reports overlap and disagree. The store dedupes by `(ecosystem, name, version)` and surfaces all matching sources in the refusal so the user can judge whether to bypass.

Source signature/checksum verification is NOT implemented — see §6.

### 4.5 Why same binary for CLI and daemon

Build simplicity (one Makefile target, one notarization target eventually), shared internal packages (parsers, gate, intel store) without import gymnastics, and one binary the launchd plist + sandbox profile both refer to. The subcommand selects mode: `bouncer daemon` for the launchd path, `bouncer run-agent` for the launcher, `bouncer <pm> …` for the CLI client.

---

## 5. Implementation status

### 5.1 Done (Phase 1)

- Daemon protocol package (`internal/daemon/`): Request/Response types, socket path resolution, two-step wire format (sendmsg for header+fds, write for payload — works around macOS's mbuf-cluster cap on sendmsg-with-ancillary).
- Daemon server: `bouncer daemon` subcommand, accept loop, gate integration, env sanitization, fd dup, spawn-and-wait, exit-code passthrough.
- Background intel refresh (30-minute cadence).
- `BOUNCER_BYPASS=1` honored loudly (INFO log).
- Client mode: `runGate` routes to daemon if socket reachable, falls back to in-process gate otherwise (daemon-less courtesy mode for users who haven't set up launchd).
- 9 new tests + 234 existing tests, all green.

### 5.2 Pending (Phase 2 — kernel enforcement; needs review before implementation)

- Sandbox profile generator (enumerate PM paths, emit `(deny process-exec (literal …))` for each, allow bouncer binary).
- `bouncer run-agent <name>` subcommand.
- `bouncer install-daemon` (launchd plist at `~/Library/LaunchAgents/com.bouncer.daemon.plist`).
- End-to-end test: sandbox-exec'd shell tries every bypass the audit found (sudo bash -c, eval, setsid, full-path, subprocess.run) → EPERM at kernel, daemon never sees it.

### 5.3 Pending (Phase 3 — cleanup)

- Delete the old Layer 1 (Claude Code hook) and Layer 3 (interposer) implementations.
- Keep Layer 2 (PATH shims) as a courtesy default outside the sandbox.
- Rewrite README and onboarding docs around the new architecture.

### 5.4 Pending (Phase 4 — audit findings carried forward)

Audit-identified issues that survive the refactor and still need fixing:
- PyPI PEP 503 name normalization at intel-store + lookup paths.
- Parser fixes: npm `lodash@npm:evil@1` alias, PEP 508 `name @ https://url` form, `uvx --with`/`--from` value flags.
- `requirements.txt` `-e` line handling.
- Cache freshness / max-age policy (currently a successful refresh today serves a six-month-old cache indefinitely if upstream becomes unreachable).
- Decision on `Local=true` (URL/git/tarball) installs: refuse, or document as explicit out-of-scope.

---

## 6. Known limitations and accepted risks

| # | Limitation | Severity | Mitigation / disposition |
|---|---|---|---|
| L1 | Intel feeds have no signature or checksum verification. A compromised upstream (account takeover, CA compromise, GitHub archive substitution) can inject false-negatives. | HIGH | Documented trust assumption. No upstream feed publishes a signed manifest today. Possible future work: pin known-good snapshots + canary list. |
| L2 | Stale-cache fail-open: after one successful sync, an upstream becoming unreachable doesn't degrade gate confidence. Cache could be months old. | HIGH | Phase 4 will add per-source `last_refresh_at` + max-age policy. |
| L3 | `sandbox-exec` is Apple-deprecated. Removal would require migration to Endpoint Security framework (paid Apple Dev ID + entitlement). | MEDIUM | 13-year history of "deprecated but functional"; Chromium/Firefox/Apple-App-Sandbox depend on the underlying kernel infra. Bet is 3+ years of warning before any real removal. |
| L4 | A sandbox-escape vulnerability in the macOS sandbox kernel extension defeats every defense at once. | LOW (Apple-managed) | Out of our threat surface. |
| L5 | Transitive dependencies: clean-named package whose `setup.py` fetches an unflagged-named malicious dep is not gated. | MEDIUM | Documented out-of-scope. Mitigation is in pinned-lockfile policy, not bouncer. |
| L6 | URL/path/git installs (`pip install https://…`, `npm install ./local`) bypass the intel lookup because the install target has no canonical package name to look up. | MEDIUM | Phase 4 decision: refuse, or document explicitly as bypass. |
| L7 | The bouncer binary itself is what the sandbox allows. If the bouncer binary is compromised (replaced, patched), the gate is bypassed. | MEDIUM | Mitigation: binary lives in a path the agent cannot write to (e.g. `/usr/local/bin/bouncer`, owned by root or by the user with no agent-writable path leading to it). Document this requirement explicitly. |
| L8 | The daemon's socket file permissions (0600) and parent dir (0700) are the only thing preventing other local users from connecting. On a single-user workstation this is sufficient; on shared hosts it requires additional thought. | LOW (single-user threat model) | Documented assumption. |

---

## 7. What we need from review

### 7.1 Adversarial review of the threat model assertion

From §2.4:

> If the user runs their coding agent via `bouncer run-agent <agent>`, no package manager — invoked by any code path, by any shell construct, by any wrapper, by any absolute or relative path — can execute without first having its arguments parsed and gated by the bouncer daemon.

We want the security team to attempt to falsify this by enumerating attacks of the form: "an agent in the sandboxed subtree runs X, and as a result the real PM executes without the daemon gating it." Specifically:

- Can a sandboxed process exec a binary at a path the sandbox profile didn't anticipate? (We enumerate `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`, mise/asdf/nvm/n shims, /opt/local/bin. Are there others? What about packages installed via the venv-bootstrap mechanism that creates a venv-local `pip`?)
- Are there ways to load a covered PM into the sandboxed process's own address space (e.g. via `dlopen` of a Python wheel that does the install logic in-process) such that no `execve` happens?
- The sandbox profile allows `default` for everything except `process-exec` deny rules. Are there other sandbox operations whose default-allow could be abused to install packages? (`file-write`, `process-fork`, etc.)
- Is the AF_UNIX socket connection from inside the sandbox to the daemon actually allowed by `(allow default)`, or does it need an explicit `(allow network-outbound …)`? (We need to confirm via test.)

### 7.2 Daemon attack surface

The daemon is the only thing standing between a hostile in-sandbox client and exec'ing a real PM. Specifically:

- The request parser (`internal/daemon/conn.go`): malformed JSON, oversized payloads, attached-fds-count mismatches, control message truncation. Are there shapes that crash the daemon vs. fail gracefully?
- The argv-passing path (`spawnAndWait` in `cmd/bouncer/daemon.go`): the client controls `Args`, `Cwd`, `Env`. We sanitize env to strip `BOUNCER_*` and replace `PATH`. Are there other env vars that, if controlled by the client, change the PM's behavior in dangerous ways? (`LD_PRELOAD`? `DYLD_*`? `NODE_OPTIONS`? `PIP_INDEX_URL`?)
- The PM resolution path (`findRealBinary`): walks `PATH` to find the first executable matching the PM name. Daemon's `PATH` is what the launchd plist sets. Is that path resistant to a hostile client manipulating it indirectly?

### 7.3 Daemon lifecycle

- Are the launchd plist's `KeepAlive` + `RunAtLoad` + crash-recovery semantics correct for "daemon-must-be-running-before-agent-installs-anything"?
- What happens if the daemon is crashed/killed and an agent is mid-install? The CLI fails-closed (cannot reach socket → exit non-zero). Confirm this is what reviewers expect.
- What happens if two agents are launched simultaneously, each via its own `sandbox-exec`? They share the daemon. The daemon serializes connection handling (one at a time). Is this acceptable?

### 7.4 Stuff out of scope of this review

- The intel-source HTTP clients themselves (audited previously; pending Phase 4 fixes are listed).
- The argv parsers (audited previously; pending Phase 4 fixes are listed). The daemon delegates to them but doesn't expand their attack surface.
- Linux. macOS only.

---

## 8. Open questions for the security team

1. **Sandbox profile completeness**: we enumerate PM paths under known prefixes. Is this enumeration future-proof? A user installing `npm` via a method we don't know about (a personal homebrew tap, a Nix profile, a Docker-shared bin dir) could land it at an unenumerated path. We're considering: (a) build the deny list dynamically per `bouncer doctor` run by walking PATH for known PM names; (b) deny by basename via `(regex …)` in the profile rather than literal paths; (c) accept the enumeration approach and document the limit. Preference?

2. **SIP-bypass concern**: `sandbox-exec` policies override SIP for the sandboxed subtree (the profile denies even SIP-protected binaries inside the sandbox). Reviewers please confirm this is the actual macOS behavior, not just our reading of the docs.

3. **Launchd plist trust**: the daemon is loaded as a per-user launchd agent. The plist lives at `~/Library/LaunchAgents/com.bouncer.daemon.plist`. If the agent can write to that path (which it can — `~/Library` is user-writable), can it replace the plist with one that points at a hostile binary, then trigger a reload? We believe not — launchd reloads happen on `launchctl bootstrap` or user login, neither of which the agent can trigger from inside the sandbox. Please confirm.

4. **Socket-path race**: between `os.Remove(stale_socket)` and `net.Listen("unix", path)` in daemon startup, can a local attacker race in to bind first? The parent dir is 0700 so only us-the-user can write — but our own (sandboxed) agent could. Is this a real concern given the threat model, or theoretical?

5. **`BOUNCER_BYPASS` UX**: the documented escape hatch. A user prepends `BOUNCER_BYPASS=1 npm install foo` and the gate is skipped. Is this UX appropriate? Alternatives: require explicit YAML approval in `~/.config/bouncer/allowlist`, require two-keystroke confirmation, etc. The current implementation logs every bypass at INFO level to the daemon's log file.

---

## 9. References

- README: `./README.md` (will be rewritten in Phase 3.4 to reflect new architecture).
- Audit findings: in conversation history; the user has the full audit transcript.
- `sandbox-exec(1)` man page (macOS). Profile language reference: Chromium's `content/common/sandbox/seatbelt/seatbelt_sandbox_design.md`.
- Apple Endpoint Security framework documentation (migration target if `sandbox-exec` is ever removed).
- Shai-Hulud npm worm reports (npm advisory database, GHSA-…, September 2025).
- OpenSSF malicious-packages: https://github.com/ossf/malicious-packages
- OSV MAL-* namespace: https://osv.dev/list?q=MAL-

---

## 10. Glossary

- **Agent**: an autonomous LLM-driven coding assistant (Claude Code, Codex, Cursor, etc.) that can emit shell commands and run them without per-command human confirmation.
- **Auto mode**: an agent operating mode in which commands run without confirmation; the threat model assumes this mode.
- **PM**: package manager (`npm`, `pnpm`, `yarn`, `bun`, `pip`, `pip3`, `uv`, `uvx`, `poetry`, `pipx`, `pdm`, `npx`, `pnpx`, `bunx`).
- **Intel source**: an upstream feed of known-malicious package names (Aikido, OpenSSF malicious-packages, OSV).
- **Gate**: the decision logic that takes parsed installs + intel and returns Allow / Refuse / Abort.
- **Sandbox** (lowercase): the `sandbox-exec`'d subtree containing the agent and everything it spawns.
- **Daemon**: the out-of-sandbox `bouncer daemon` process loaded by launchd.
- **Shim**: a symlink at `~/.local/bin/<pm>` pointing at the bouncer binary, so `npm install foo` typed in any shell with `~/.local/bin` on PATH transparently routes through bouncer.
- **SIP**: Apple's System Integrity Protection. Strips `DYLD_INSERT_LIBRARIES` from `/usr/bin/*`, `/bin/*`, `/sbin/*`, system frameworks. Not relevant in the new architecture except as a reason the old `DYLD_INSERT_LIBRARIES` approach was unfixable.
- **SCM_RIGHTS**: Unix socket control message for passing file descriptors between processes. Used to hand the client's stdio fds to the daemon so the spawned PM writes directly to the user's terminal.
