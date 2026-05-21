# Sirene integration

Sirene workflows execute steps as subprocess invocations via the
workflow runtime, inheriting the parent shell's `PATH`. Coverage is
Layers 2 + 3 + 4 — see [`../../docs/onboarding.md`](../../docs/onboarding.md)
for the full per-layer walkthrough.

```sh
bouncer install-shims                # Layer 2: ~/.local/bin/{npm,pip,...} → bouncer
make interposer                      # build native execve interposer
bouncer install-preload --lib $(pwd)/libbouncer_interpose.dylib --shell-rc auto
                                     # Layer 3: DYLD_INSERT_LIBRARIES / LD_PRELOAD
bouncer install-wrappers             # Layer 4: wrap real binaries at install paths
```

Why Layer 4 matters specifically for Sirene-style runners: when a
workflow step exec's a PM by its absolute path (which Sirene runtimes
commonly do, since they don't always inherit a normal interactive
shell's PATH), Layers 2–3 may not engage. Layer 4 replaces the actual
binary bytes at the install path, so PATH and env-var inheritance stop
mattering.

If Sirene grows a typed pre-step hook in the future, a workflow-aware
integration can live here.
