// veto_interpose: native execve/posix_spawn interposer.
//
// Closes the "direct child-process invocation" fail-OPEN that the Claude
// hook and PATH shims can't cover. When the calling process has this
// shared library loaded (via DYLD_INSERT_LIBRARIES on macOS or LD_PRELOAD
// on Linux), every execve/posix_spawn that names a known package manager
// — even by absolute path — is rewritten to invoke
//
//     <veto_path> <pm-name> <pm-args...>
//
// before reaching the kernel.
//
// Decision rules mirror the Claude hook so the three defense layers stay
// behaviorally consistent: veto/bypass prefix → no rewrite; non-PM
// basename → no rewrite; PM basename with non-dangerous verb → no
// rewrite. Anything else gets routed through veto for the actual
// malware lookup.
//
// Build:
//   macOS:  clang -O2 -dynamiclib -fno-common ... -o libveto_interpose.dylib
//   Linux:  gcc   -O2 -shared -fPIC ...        -o libveto_interpose.so
//
// Wire-up:
//   macOS:  export DYLD_INSERT_LIBRARIES=/path/to/libveto_interpose.dylib
//   Linux:  export LD_PRELOAD=/path/to/libveto_interpose.so
//   Both:   export VETO_PATH=/abs/path/to/veto   (resolved at install-preload time)
//
// Escape hatch: VETO_BYPASS=1 in the env of the *child* — checked at
// spawn time, so an agent can opt one process out without disabling the
// whole interposer.
//
// Fail-OPEN paths (documented, not bugs):
//   - SIP-protected binaries on macOS (system /usr/bin/*) ignore
//     DYLD_INSERT_LIBRARIES; if a malicious agent spawns those, we
//     never see the call.
//   - exec via raw syscall() bypassing libc — no libc interposer can
//     catch that.
//   - statically-linked binaries that don't go through libc's exec
//     wrappers.
// These mirror the README's "command-layer scanner, not kernel-level
// interposer" caveats — `veto install-preload` prints them.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <errno.h>

#ifdef __APPLE__
  // Tell the macOS dyld interposer machinery to swap our function for the
  // real one in every loaded image's call sites. No DYLD_FORCE_FLAT_NAMESPACE
  // required with this section-based mechanism.
  #define VETO_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { \
      const void *replacement; \
      const void *replacee; \
    } _veto_interpose_##_replacee \
      __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&_replacement, \
        (const void *)(unsigned long)&_replacee \
    }
#else
  #include <dlfcn.h>
#endif

// Mirrors internal/hook/claudecode/claudecode.go::shimmedPMs.
//
// "python" / "python3" are included so we can detect `python -m pip
// install …` — the canonical install form in virtualenvs, Dockerfiles,
// and most CI scripts. is_risky has a python-specific branch that only
// flags the `-m <pm>` form; bare python invocations (scripts, REPLs,
// -V, -m http.server, …) pass through untouched.
static const char *const PM_NAMES[] = {
  "npm", "npx", "yarn", "pnpm", "pnpx",
  "rush", "rushx", "bun", "bunx",
  "pip", "pip3", "uv", "uvx", "poetry", "pipx", "pdm",
  "python", "python3",
  NULL,
};

// Subset of PM_NAMES that, when invoked via `python -m <name>`, count
// as risky install-form calls we route through veto. Kept in sync with
// pythonDashMTargets in cmd/veto/main.go.
static const char *const PYTHON_DASH_M_TARGETS[] = {
  "pip", "pip3", "uv", "pipx", "poetry", "pdm", NULL,
};

// PMs whose every non-help invocation pulls remote code.
static const char *const EXEC_PMS[] = {
  "npx", "pnpx", "bunx", "rushx", "uvx", NULL,
};

// Verb tables. Kept compact at the cost of one strcmp loop per call;
// these only run on the rewrite hot path, which is rare relative to
// total execve traffic.
static const char *const NPM_VERBS[]    = {"install","i","add","ci","update","up","upgrade","exec",NULL};
static const char *const YARN_VERBS[]   = {"install","add","upgrade","up","dlx",NULL};
static const char *const PNPM_VERBS[]   = {"install","i","add","update","up","upgrade","dlx",NULL};
static const char *const BUN_VERBS[]    = {"install","i","add","update","upgrade","x","create",NULL};
static const char *const RUSH_VERBS[]   = {"install","add","update",NULL};
static const char *const PIP_VERBS[]    = {"install","download",NULL};
static const char *const PIPX_VERBS[]   = {"install","upgrade","inject","run",NULL};
static const char *const UV_VERBS[]     = {"add","sync","install","tool","run","pip",NULL};
static const char *const POETRY_VERBS[] = {"install","add","update","lock",NULL};
static const char *const PDM_VERBS[]    = {"install","add","update","sync",NULL};

static const char *const *verbs_for(const char *name) {
  if (!strcmp(name, "npm"))    return NPM_VERBS;
  if (!strcmp(name, "yarn"))   return YARN_VERBS;
  if (!strcmp(name, "pnpm"))   return PNPM_VERBS;
  if (!strcmp(name, "bun"))    return BUN_VERBS;
  if (!strcmp(name, "rush"))   return RUSH_VERBS;
  if (!strcmp(name, "pip") || !strcmp(name, "pip3")) return PIP_VERBS;
  if (!strcmp(name, "pipx"))   return PIPX_VERBS;
  if (!strcmp(name, "uv"))     return UV_VERBS;
  if (!strcmp(name, "poetry")) return POETRY_VERBS;
  if (!strcmp(name, "pdm"))    return PDM_VERBS;
  return NULL;
}

static int in_list(const char *s, const char *const *list) {
  for (; *list; list++) {
    if (!strcmp(s, *list)) return 1;
  }
  return 0;
}

static const char *basename_of(const char *path) {
  if (!path) return "";
  const char *slash = strrchr(path, '/');
  return slash ? slash + 1 : path;
}

// python_m_target inspects argv (without the basename check — callers
// have already determined bn is "python" / "python3") and returns the
// `-m <pm>` PM name if the invocation matches the gated install form.
// Returns NULL for every other python invocation: scripts, REPLs, -c
// snippets, -V, -m venv, -m http.server, etc. all pass through.
//
// We intentionally accept only the strict form `python -m <pm> …` —
// argv[1] must be exactly "-m" and argv[2] must be a recognized PM.
// Flags before `-m` (`python -I -m pip install …`) are real but rare;
// loosening the check would also expand the surface for crafted-input
// bypass attempts. Anything missed at this layer remains gated by the
// PATH shim (Layer 2), so the false-negative cost here is bounded.
static const char *python_m_target(char *const argv[]) {
  if (!argv || !argv[1] || !argv[2]) return NULL;
  if (strcmp(argv[1], "-m") != 0) return NULL;
  for (const char *const *p = PYTHON_DASH_M_TARGETS; *p; p++) {
    if (!strcmp(argv[2], *p)) return *p;
  }
  return NULL;
}

// is_risky returns the PM basename if (path, argv) describes a covered
// risky invocation, otherwise NULL. The returned pointer is owned by argv
// or by static storage — callers must not free it.
//
// For `python` / `python3`, the only gated form is `python -m <pm> …`;
// every other python invocation returns NULL so REPLs, scripts, `-V`,
// `-m http.server`, etc. dispatch fast and transparently. When the
// python-m form is detected, the returned PM name is the module
// ("pip"/"uv"/…), NOT "python" — so the rewritten argv routes through
// veto's per-PM gate logic. Callers MUST additionally detect the
// python-m form via python_m_target() so they can drop the "-m" and
// PM-name tokens from the rewritten argv and set
// VETO_PYTHON_M_ORIGINAL in the child env so veto re-execs the
// interpreter (not the bare PM) on the allow path.
static const char *is_risky(const char *path, char *const argv[]) {
  // VETO_BYPASS env var honored at child-spawn time. We can only see
  // the parent's env here, but a Claude-Code-like `VETO_BYPASS=1 npm
  // install foo` is implemented as a child-env var the parent sets — for
  // libc execve, that goes through the env argument we don't have on
  // this function signature, so we fall through to the rewrite logic and
  // let veto itself notice the bypass via its env at startup.
  if (getenv("VETO_BYPASS")) return NULL;

  if (!path || !argv || !argv[0]) return NULL;
  const char *bn = basename_of(path);
  if (!bn || !*bn) return NULL;

  // Already through veto? Don't recurse.
  if (!strcmp(bn, "veto")) return NULL;

  if (!in_list(bn, PM_NAMES)) return NULL;

  // python / python3: only the `python -m <pm>` form is gated. Every
  // other invocation (scripts, REPL, -c, -V, -m http.server, …) is
  // explicitly NOT risky and passes straight through.
  if (!strcmp(bn, "python") || !strcmp(bn, "python3")) {
    return python_m_target(argv); // PM name or NULL
  }

  // Fetch-and-run binaries: any non-flag arg that isn't help → risky.
  if (in_list(bn, EXEC_PMS)) {
    for (int i = 1; argv[i]; i++) {
      const char *a = argv[i];
      if (a[0] == '-') continue;
      if (!strcmp(a, "help") || !strcmp(a, "--help") || !strcmp(a, "-h") ||
          !strcmp(a, "--version") || !strcmp(a, "-v")) return NULL;
      return bn;
    }
    return NULL;
  }

  const char *const *verbs = verbs_for(bn);
  if (!verbs) return NULL;
  for (int i = 1; argv[i]; i++) {
    if (argv[i][0] == '-') continue;
    return in_list(argv[i], verbs) ? bn : NULL;
  }
  return NULL;
}

// rewrite_argv returns a newly-allocated argv array of the form
//    [veto_path, pm_name, original_args...]
// The caller is responsible for freeing the outer array; the inner string
// pointers are aliases of the originals or of veto_path / pm_name.
//
// `skip_after_zero` is the number of original argv slots to drop AFTER
// argv[0]. For a normal PM invocation it's 0 — we just replace argv[0]
// with the (veto_path, pm_name) pair and keep argv[1..]. For
// `python -m <pm> …` we pass 2 so argv[1]="-m" and argv[2]=<pm> are
// stripped, leaving the rewritten argv as [veto, pm, real-args…].
static char **rewrite_argv(const char *veto_path, const char *pm_name,
                           char *const argv[], int skip_after_zero) {
  int n = 0;
  while (argv[n]) n++;
  if (skip_after_zero < 0) skip_after_zero = 0;
  if (skip_after_zero > n - 1) skip_after_zero = n - 1; // clamp; defensive
  // +2 slots for veto_path and pm_name, +1 for NULL terminator.
  int extra = 2 + 1;
  char **out = (char **)calloc((n - skip_after_zero) + extra, sizeof(char *));
  if (!out) return NULL;
  out[0] = (char *)veto_path;
  out[1] = (char *)pm_name;
  // Skip the original argv[0] (the PM/interpreter) PLUS skip_after_zero
  // additional positions. Copy what remains.
  int dst = 2;
  for (int i = 1 + skip_after_zero; i < n; i++) {
    out[dst++] = argv[i];
  }
  out[dst] = NULL;
  return out;
}

// rewrite_envp returns a newly-allocated envp array equal to envp with
// one entry added/replaced. The added entry is of the form
// "NAME=VALUE" (the caller must pre-build this string; the lifetime is
// owned by the caller). Used to thread VETO_PYTHON_M_ORIGINAL through
// the python-m exec so the Go side can re-invoke the original
// interpreter on the allow path instead of exec'ing the bare PM (which
// would silently break venv-scoped resolution).
//
// On allocation failure, returns NULL — caller falls back to the
// original envp (the gate still runs, but the allow path may exec the
// PM directly; degraded behavior is acceptable for the rare case).
static char **rewrite_envp(char *const envp[], const char *kv) {
  if (!kv) return NULL;
  int n = 0;
  while (envp && envp[n]) n++;

  // If an existing entry matches NAME=, replace it. Otherwise append.
  const char *eq = strchr(kv, '=');
  size_t name_len = eq ? (size_t)(eq - kv) + 1 : 0; // include '='
  int existing_idx = -1;
  if (name_len > 0) {
    for (int i = 0; i < n; i++) {
      if (envp[i] && !strncmp(envp[i], kv, name_len)) {
        existing_idx = i;
        break;
      }
    }
  }

  int out_n = (existing_idx >= 0) ? n : n + 1;
  char **out = (char **)calloc(out_n + 1, sizeof(char *));
  if (!out) return NULL;
  for (int i = 0; i < n; i++) {
    out[i] = envp[i];
  }
  if (existing_idx >= 0) {
    out[existing_idx] = (char *)kv;
  } else {
    out[n] = (char *)kv;
  }
  out[out_n] = NULL;
  return out;
}

// build_python_m_env constructs the "VETO_PYTHON_M_ORIGINAL=<python>"
// string. Returns malloc'd memory the caller must free.
static char *build_python_m_env(const char *python_basename) {
  if (!python_basename || !*python_basename) return NULL;
  const char *prefix = "VETO_PYTHON_M_ORIGINAL=";
  size_t need = strlen(prefix) + strlen(python_basename) + 1;
  char *buf = (char *)malloc(need);
  if (!buf) return NULL;
  // Two-step to keep -Wstringop-truncation quiet across compilers.
  size_t pn = strlen(prefix);
  memcpy(buf, prefix, pn);
  size_t bn = strlen(python_basename);
  memcpy(buf + pn, python_basename, bn + 1); // include trailing NUL
  return buf;
}

// log_route prints a one-line marker so colleagues debugging "why did
// my command turn into `veto foo`?" have a trail. Off unless
// VETO_INTERPOSE_LOG=1; the hot path stays silent in production.
static void log_route(const char *pm, const char *path) {
  if (!getenv("VETO_INTERPOSE_LOG")) return;
  fprintf(stderr, "veto-interpose: routed %s (path=%s) through veto\n", pm, path);
}

// is_python_basename reports whether bn is "python" or "python3".
// Centralised so the python-m detection in the exec wrappers stays in
// sync with PM_NAMES / is_risky.
static int is_python_basename(const char *bn) {
  if (!bn) return 0;
  return !strcmp(bn, "python") || !strcmp(bn, "python3");
}

// classify_invocation packages the per-call decisions in one struct:
//   skip       — additional argv positions to drop after argv[0]
//                (2 for `python -m <pm> …`, 0 otherwise).
//   env_kv     — malloc'd "VETO_PYTHON_M_ORIGINAL=<python>" string when
//                python-m, NULL otherwise. Caller must free.
//
// The caller has already confirmed pm != NULL via is_risky and bp via
// getenv("VETO_PATH") — this helper only computes the python-m branch.
typedef struct {
  int skip;
  char *env_kv; // owned; caller frees
} invocation_t;

static invocation_t classify_invocation(const char *path, char *const argv[]) {
  invocation_t r = {0, NULL};
  const char *bn = basename_of(path);
  if (is_python_basename(bn) && python_m_target(argv)) {
    r.skip = 2;
    r.env_kv = build_python_m_env(bn);
  }
  return r;
}

#ifdef __APPLE__
// macOS interpose mechanism: define a same-signature function and a
// __DATA,__interpose entry that tells dyld to swap call sites.
extern int execve(const char *, char *const[], char *const[]);
extern int execvp(const char *, char *const[]);
extern int execv(const char *, char *const[]);
extern int posix_spawn(pid_t *, const char *, const posix_spawn_file_actions_t *,
                       const posix_spawnattr_t *, char *const[], char *const[]);
extern int posix_spawnp(pid_t *, const char *, const posix_spawn_file_actions_t *,
                        const posix_spawnattr_t *, char *const[], char *const[]);

static int veto_execve(const char *path, char *const argv[], char *const envp[]) {
  const char *pm = is_risky(path, argv);
  if (!pm) return execve(path, argv, envp);
  const char *bp = getenv("VETO_PATH");
  if (!bp || !*bp) return execve(path, argv, envp); // not installed — fail open at this layer (Claude hook / shims should catch)
  invocation_t inv = classify_invocation(path, argv);
  char **new_argv = rewrite_argv(bp, pm, argv, inv.skip);
  if (!new_argv) { free(inv.env_kv); return execve(path, argv, envp); }
  char **new_envp = (char **)envp;
  char **allocated_envp = NULL;
  if (inv.env_kv) {
    allocated_envp = rewrite_envp(envp, inv.env_kv);
    if (allocated_envp) new_envp = allocated_envp;
  }
  log_route(pm, path);
  int rc = execve(bp, new_argv, new_envp);
  free(new_argv);
  free(allocated_envp);
  free(inv.env_kv);
  return rc;
}

static int veto_execvp(const char *file, char *const argv[]) {
  const char *pm = is_risky(file, argv);
  if (!pm) return execvp(file, argv);
  const char *bp = getenv("VETO_PATH");
  if (!bp || !*bp) return execvp(file, argv);
  invocation_t inv = classify_invocation(file, argv);
  char **new_argv = rewrite_argv(bp, pm, argv, inv.skip);
  if (!new_argv) { free(inv.env_kv); return execvp(file, argv); }
  if (inv.env_kv) {
    // execvp uses the process environ; setenv() reflects into the
    // child. We accept the (rare) cost of leaking the entry into our
    // own process — exec replaces us anyway on success, and on failure
    // a stray VETO_PYTHON_M_ORIGINAL in our env is harmless.
    setenv("VETO_PYTHON_M_ORIGINAL", inv.env_kv + strlen("VETO_PYTHON_M_ORIGINAL="), 1);
  }
  log_route(pm, file);
  int rc = execvp(bp, new_argv);
  free(new_argv);
  free(inv.env_kv);
  return rc;
}

static int veto_execv(const char *path, char *const argv[]) {
  const char *pm = is_risky(path, argv);
  if (!pm) return execv(path, argv);
  const char *bp = getenv("VETO_PATH");
  if (!bp || !*bp) return execv(path, argv);
  invocation_t inv = classify_invocation(path, argv);
  char **new_argv = rewrite_argv(bp, pm, argv, inv.skip);
  if (!new_argv) { free(inv.env_kv); return execv(path, argv); }
  if (inv.env_kv) {
    setenv("VETO_PYTHON_M_ORIGINAL", inv.env_kv + strlen("VETO_PYTHON_M_ORIGINAL="), 1);
  }
  log_route(pm, path);
  int rc = execv(bp, new_argv);
  free(new_argv);
  free(inv.env_kv);
  return rc;
}

static int veto_posix_spawn(pid_t *pid, const char *path,
                               const posix_spawn_file_actions_t *fa,
                               const posix_spawnattr_t *attr,
                               char *const argv[], char *const envp[]) {
  const char *pm = is_risky(path, argv);
  if (!pm) return posix_spawn(pid, path, fa, attr, argv, envp);
  const char *bp = getenv("VETO_PATH");
  if (!bp || !*bp) return posix_spawn(pid, path, fa, attr, argv, envp);
  invocation_t inv = classify_invocation(path, argv);
  char **new_argv = rewrite_argv(bp, pm, argv, inv.skip);
  if (!new_argv) { free(inv.env_kv); return posix_spawn(pid, path, fa, attr, argv, envp); }
  char **new_envp = (char **)envp;
  char **allocated_envp = NULL;
  if (inv.env_kv) {
    allocated_envp = rewrite_envp(envp, inv.env_kv);
    if (allocated_envp) new_envp = allocated_envp;
  }
  log_route(pm, path);
  int rc = posix_spawn(pid, bp, fa, attr, new_argv, new_envp);
  free(new_argv);
  free(allocated_envp);
  free(inv.env_kv);
  return rc;
}

static int veto_posix_spawnp(pid_t *pid, const char *file,
                                const posix_spawn_file_actions_t *fa,
                                const posix_spawnattr_t *attr,
                                char *const argv[], char *const envp[]) {
  const char *pm = is_risky(file, argv);
  if (!pm) return posix_spawnp(pid, file, fa, attr, argv, envp);
  const char *bp = getenv("VETO_PATH");
  if (!bp || !*bp) return posix_spawnp(pid, file, fa, attr, argv, envp);
  invocation_t inv = classify_invocation(file, argv);
  char **new_argv = rewrite_argv(bp, pm, argv, inv.skip);
  if (!new_argv) { free(inv.env_kv); return posix_spawnp(pid, file, fa, attr, argv, envp); }
  char **new_envp = (char **)envp;
  char **allocated_envp = NULL;
  if (inv.env_kv) {
    allocated_envp = rewrite_envp(envp, inv.env_kv);
    if (allocated_envp) new_envp = allocated_envp;
  }
  log_route(pm, file);
  // Re-route to absolute veto path via posix_spawn (not posix_spawnp)
  // so we don't pay a PATH lookup we already resolved.
  int rc = posix_spawn(pid, bp, fa, attr, new_argv, new_envp);
  free(new_argv);
  free(allocated_envp);
  free(inv.env_kv);
  return rc;
}

VETO_INTERPOSE(veto_execve,        execve);
VETO_INTERPOSE(veto_execvp,        execvp);
VETO_INTERPOSE(veto_execv,         execv);
VETO_INTERPOSE(veto_posix_spawn,   posix_spawn);
VETO_INTERPOSE(veto_posix_spawnp,  posix_spawnp);

#else // Linux / glibc: LD_PRELOAD symbol-shadowing pattern.

#define _GNU_SOURCE
#include <dlfcn.h>

typedef int (*execve_fn)(const char *, char *const[], char *const[]);
typedef int (*execvp_fn)(const char *, char *const[]);
typedef int (*execv_fn)(const char *, char *const[]);
typedef int (*posix_spawn_fn)(pid_t *, const char *,
                              const posix_spawn_file_actions_t *,
                              const posix_spawnattr_t *,
                              char *const[], char *const[]);

static execve_fn      real_execve;
static execvp_fn      real_execvp;
static execv_fn       real_execv;
static posix_spawn_fn real_posix_spawn;
static posix_spawn_fn real_posix_spawnp;

static void __attribute__((constructor)) veto_init(void) {
  real_execve       = (execve_fn)      dlsym(RTLD_NEXT, "execve");
  real_execvp       = (execvp_fn)      dlsym(RTLD_NEXT, "execvp");
  real_execv        = (execv_fn)       dlsym(RTLD_NEXT, "execv");
  real_posix_spawn  = (posix_spawn_fn) dlsym(RTLD_NEXT, "posix_spawn");
  real_posix_spawnp = (posix_spawn_fn) dlsym(RTLD_NEXT, "posix_spawnp");
}

int execve(const char *path, char *const argv[], char *const envp[]) {
  const char *pm = is_risky(path, argv);
  if (!pm) return real_execve(path, argv, envp);
  const char *bp = getenv("VETO_PATH");
  if (!bp || !*bp) return real_execve(path, argv, envp);
  invocation_t inv = classify_invocation(path, argv);
  char **new_argv = rewrite_argv(bp, pm, argv, inv.skip);
  if (!new_argv) { free(inv.env_kv); return real_execve(path, argv, envp); }
  char **new_envp = (char **)envp;
  char **allocated_envp = NULL;
  if (inv.env_kv) {
    allocated_envp = rewrite_envp(envp, inv.env_kv);
    if (allocated_envp) new_envp = allocated_envp;
  }
  log_route(pm, path);
  int rc = real_execve(bp, new_argv, new_envp);
  free(new_argv);
  free(allocated_envp);
  free(inv.env_kv);
  return rc;
}

int execvp(const char *file, char *const argv[]) {
  const char *pm = is_risky(file, argv);
  if (!pm) return real_execvp(file, argv);
  const char *bp = getenv("VETO_PATH");
  if (!bp || !*bp) return real_execvp(file, argv);
  invocation_t inv = classify_invocation(file, argv);
  char **new_argv = rewrite_argv(bp, pm, argv, inv.skip);
  if (!new_argv) { free(inv.env_kv); return real_execvp(file, argv); }
  if (inv.env_kv) {
    setenv("VETO_PYTHON_M_ORIGINAL", inv.env_kv + strlen("VETO_PYTHON_M_ORIGINAL="), 1);
  }
  log_route(pm, file);
  int rc = real_execvp(bp, new_argv);
  free(new_argv);
  free(inv.env_kv);
  return rc;
}

int execv(const char *path, char *const argv[]) {
  const char *pm = is_risky(path, argv);
  if (!pm) return real_execv(path, argv);
  const char *bp = getenv("VETO_PATH");
  if (!bp || !*bp) return real_execv(path, argv);
  invocation_t inv = classify_invocation(path, argv);
  char **new_argv = rewrite_argv(bp, pm, argv, inv.skip);
  if (!new_argv) { free(inv.env_kv); return real_execv(path, argv); }
  if (inv.env_kv) {
    setenv("VETO_PYTHON_M_ORIGINAL", inv.env_kv + strlen("VETO_PYTHON_M_ORIGINAL="), 1);
  }
  log_route(pm, path);
  int rc = real_execv(bp, new_argv);
  free(new_argv);
  free(inv.env_kv);
  return rc;
}

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *fa,
                const posix_spawnattr_t *attr,
                char *const argv[], char *const envp[]) {
  const char *pm = is_risky(path, argv);
  if (!pm) return real_posix_spawn(pid, path, fa, attr, argv, envp);
  const char *bp = getenv("VETO_PATH");
  if (!bp || !*bp) return real_posix_spawn(pid, path, fa, attr, argv, envp);
  invocation_t inv = classify_invocation(path, argv);
  char **new_argv = rewrite_argv(bp, pm, argv, inv.skip);
  if (!new_argv) { free(inv.env_kv); return real_posix_spawn(pid, path, fa, attr, argv, envp); }
  char **new_envp = (char **)envp;
  char **allocated_envp = NULL;
  if (inv.env_kv) {
    allocated_envp = rewrite_envp(envp, inv.env_kv);
    if (allocated_envp) new_envp = allocated_envp;
  }
  log_route(pm, path);
  int rc = real_posix_spawn(pid, bp, fa, attr, new_argv, new_envp);
  free(new_argv);
  free(allocated_envp);
  free(inv.env_kv);
  return rc;
}

int posix_spawnp(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *fa,
                 const posix_spawnattr_t *attr,
                 char *const argv[], char *const envp[]) {
  const char *pm = is_risky(file, argv);
  if (!pm) return real_posix_spawnp(pid, file, fa, attr, argv, envp);
  const char *bp = getenv("VETO_PATH");
  if (!bp || !*bp) return real_posix_spawnp(pid, file, fa, attr, argv, envp);
  invocation_t inv = classify_invocation(file, argv);
  char **new_argv = rewrite_argv(bp, pm, argv, inv.skip);
  if (!new_argv) { free(inv.env_kv); return real_posix_spawnp(pid, file, fa, attr, argv, envp); }
  char **new_envp = (char **)envp;
  char **allocated_envp = NULL;
  if (inv.env_kv) {
    allocated_envp = rewrite_envp(envp, inv.env_kv);
    if (allocated_envp) new_envp = allocated_envp;
  }
  log_route(pm, file);
  int rc = real_posix_spawn(pid, bp, fa, attr, new_argv, new_envp);
  free(new_argv);
  free(allocated_envp);
  free(inv.env_kv);
  return rc;
}

#endif
