# Cursor IDE integration

Cursor does not expose a per-tool hook protocol analogous to Claude
Code's `PreToolUse`. veto's Cursor integration is therefore two
pieces:

1. **PATH shims (Layer 2)** — Cursor's agent mode runs shell commands
   in your integrated terminal, which inherits your shell's `PATH`.
   Once shims are installed, any `npm install foo` issued from Cursor's
   terminal resolves to the shim and routes through veto exactly as it
   does from any other shell.
2. **Project rules** — a `.cursor/rules/veto.mdc` file that tells
   Cursor's model to prefix install commands with `veto`. This is a
   behavioral nudge, not enforced. Strictly weaker than Claude Code's
   `PreToolUse` hook, but it's the best surface Cursor exposes.

## Setup

```sh
veto install-cursor                       # install-shims + write .cursor/rules/veto.mdc in CWD
veto install-cursor --project-dir DIR     # write the rule into a specific project
veto install-cursor --skip-shims          # rule only (shims already installed)
veto install-cursor --shim-dir DIR        # passes through to install-shims as --dir
veto install-cursor --force               # overwrite an existing rule / shim
```

For direct child-process invocations that bypass PATH entirely
(`subprocess.run(["/full/path/to/npm", ...])`, env-stripped spawns from
tooling Cursor invokes), also install Layers 3 and 4 — see
[`../../docs/onboarding.md`](../../docs/onboarding.md):

```sh
veto install-preload --lib /path/to/libveto_interpose.dylib
veto install-wrappers
```

## Global (cross-project) rule

The per-project rule lives in `.cursor/rules/veto.mdc` and only applies
when you have that project open. For **global** coverage that applies
to every project you open in Cursor, paste the rule body into Cursor
Settings → Rules → User Rules.

Cursor stores user rules in its app settings, not in a file veto can
safely write to — the schema is private to Cursor and changes between
releases. The copy-paste step has to be manual.

```sh
cat .cursor/rules/veto.mdc                # pipe into your clipboard tool
```

## Background Agents — out of scope

Cursor's Background Agents execute in Cursor's cloud, not on your
machine. **veto does not protect Background Agent execution.** Any
install issued by a Background Agent bypasses all four veto layers
because none of them are installed in Cursor's container.

Mitigations, in increasing order of effort:

1. **Don't use Background Agents for package-touching work.** Use the
   local agent mode for any task that may install dependencies.
2. **Audit the diff before merging.** Background Agents commit to a
   branch; review lockfile changes manually before merging to `main`.
3. **Custom Docker base image.** Cursor allows specifying a custom
   image for Background Agents. A future veto release may publish one
   with the gate preinstalled. Not available today.

## Bypass

Prepend `VETO_BYPASS=1 ` to a single command. Use sparingly — the rule
exists specifically because behavioral nudges are easy to bypass
silently, and a refusal usually means a real malware match.

## Removal

```sh
veto uninstall-shims              # remove the shim symlinks
rm .cursor/rules/veto.mdc         # remove the per-project rule
```

If you pasted the body into Cursor Settings → User Rules, remove it
there manually.

## Coverage

All sixteen package managers veto supports:

`npm`, `npx`, `yarn`, `pnpm`, `pnpx`, `rush`, `rushx`, `bun`, `bunx`,
`pip`, `pip3`, `uv`, `uvx`, `poetry`, `pipx`, `pdm`.

The rule and the shim set stay in sync — adding a new manager to veto
updates both surfaces automatically.
