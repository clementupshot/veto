# Sirene hook (planned)

Sirene workflows execute steps as subprocess invocations via the workflow
runtime. The integration approach mirrors the Codex one: bouncer-managed
shims on `PATH`, prepended to whatever environment Sirene spawns its
steps under.

If Sirene grows a typed pre-step hook in the future, a workflow-aware
integration can live here.

@@TODO: implement once the shim subsystem lands.
