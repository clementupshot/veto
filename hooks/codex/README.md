# Codex hook (planned)

Codex CLI doesn't ship a PreToolUse hook protocol of the same shape as Claude
Code's, so the integration here will likely take the form of a PATH shim:

- The bouncer install step writes shims to `~/.local/bin/{npm,pnpm,...}` that
  exec `bouncer <pm> "$@"`.
- The shim dir is prepended to `PATH` in the shell init Codex inherits.
- Codex sees `npm install foo` as usual; the shim routes through bouncer
  transparently.

This sidesteps the per-tool hook protocol entirely and works for any agent
that inherits the user's `PATH`, not just Codex.

@@TODO: implement once the shim subsystem lands.
