// bouncer_interpose: native execve/posix_spawn interposer.
//
// Closes the "direct child-process invocation" fail-OPEN that the Claude
// hook and PATH shims can't cover. When the calling process has this
// shared library loaded (via DYLD_INSERT_LIBRARIES on macOS or LD_PRELOAD
// on Linux), every execve/posix_spawn that names a known package manager
// — even by absolute path — is rewritten to invoke
//
//     <bouncer_path> <pm-name> <pm-args...>
//
// before reaching the kernel.
//
// Decision rules mirror the Claude hook so the three defense layers stay
// behaviorally consistent: bouncer/bypass prefix → no rewrite; non-PM
// basename → no rewrite; PM basename with non-dangerous verb → no
// rewrite. Anything else gets routed through bouncer for the actual
// malware lookup.
//
// Build:
//   macOS:  clang -O2 -dynamiclib -fno-common ... -o libbouncer_interpose.dylib
//   Linux:  gcc   -O2 -shared -fPIC ...        -o libbouncer_interpose.so
//
// Wire-up:
//   macOS:  export DYLD_INSERT_LIBRARIES=/path/to/libbouncer_interpose.dylib
//   Linux:  export LD_PRELOAD=/path/to/libbouncer_interpose.so
//   Both:   export BOUNCER_PATH=/abs/path/to/bouncer   (resolved at install-preload time)
//
// Escape hatch: BOUNCER_BYPASS=1 in the env of the *child* — checked at
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
// interposer" caveats — `bouncer install-preload` prints them.

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
  #define BOUNCER_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { \
      const void *replacement; \
      const void *replacee; \
    } _bouncer_interpose_##_replacee \
      __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&_replacement, \
        (const void *)(unsigned long)&_replacee \
    }
#else
  #include <dlfcn.h>
#endif

// Mirrors internal/hook/claudecode/claudecode.go::shimmedPMs.
static const char *const PM_NAMES[] = {
  "npm", "npx", "yarn", "pnpm", "pnpx",
  "rush", "rushx", "bun", "bunx",
  "pip", "pip3", "uv", "uvx", "poetry", "pipx", "pdm",
  NULL,
};

// PMs whose every non-help invocation pulls remote code.
static const char *const EXEC_PMS[] = {
  "npx", "pnpx", "bunx", "rushx", "uvx", NULL,
};

// Verb tables. Kept compact at the cost of one strcmp loop per call;
// these only run on the rewrite hot path, which is rare relative to
// total execve traffic.
static const char *const NPM_VERBS[]    = {"install","i","add","ci","update","up","upgrade",NULL};
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

// is_risky returns the PM basename if (path, argv) describes a covered
// risky invocation, otherwise NULL. The returned pointer is owned by argv
// or by static storage — callers must not free it.
static const char *is_risky(const char *path, char *const argv[]) {
  // BOUNCER_BYPASS env var honored at child-spawn time. We can only see
  // the parent's env here, but a Claude-Code-like `BOUNCER_BYPASS=1 npm
  // install foo` is implemented as a child-env var the parent sets — for
  // libc execve, that goes through the env argument we don't have on
  // this function signature, so we fall through to the rewrite logic and
  // let bouncer itself notice the bypass via its env at startup.
  if (getenv("BOUNCER_BYPASS")) return NULL;

  if (!path || !argv || !argv[0]) return NULL;
  const char *bn = basename_of(path);
  if (!bn || !*bn) return NULL;

  // Already through bouncer? Don't recurse.
  if (!strcmp(bn, "bouncer")) return NULL;

  if (!in_list(bn, PM_NAMES)) return NULL;

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
//    [bouncer_path, pm_name, original_args...]
// The caller is responsible for freeing the outer array; the inner string
// pointers are aliases of the originals or of bouncer_path / pm_name.
static char **rewrite_argv(const char *bouncer_path, const char *pm_name, char *const argv[]) {
  int n = 0;
  while (argv[n]) n++;
  // +2 slots for bouncer_path and pm_name, +1 for NULL terminator.
  char **out = (char **)calloc(n + 3, sizeof(char *));
  if (!out) return NULL;
  out[0] = (char *)bouncer_path;
  out[1] = (char *)pm_name;
  // Skip the original argv[0] — it was the PM. Copy argv[1..] across.
  for (int i = 1; i < n; i++) {
    out[i + 1] = argv[i];
  }
  out[n + 1] = NULL;
  return out;
}

// log_route prints a one-line marker so colleagues debugging "why did
// my command turn into `bouncer foo`?" have a trail. Off unless
// BOUNCER_INTERPOSE_LOG=1; the hot path stays silent in production.
static void log_route(const char *pm, const char *path) {
  if (!getenv("BOUNCER_INTERPOSE_LOG")) return;
  fprintf(stderr, "bouncer-interpose: routed %s (path=%s) through bouncer\n", pm, path);
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

static int bouncer_execve(const char *path, char *const argv[], char *const envp[]) {
  const char *pm = is_risky(path, argv);
  if (!pm) return execve(path, argv, envp);
  const char *bp = getenv("BOUNCER_PATH");
  if (!bp || !*bp) return execve(path, argv, envp); // not installed — fail open at this layer (Claude hook / shims should catch)
  char **new_argv = rewrite_argv(bp, pm, argv);
  if (!new_argv) return execve(path, argv, envp);
  log_route(pm, path);
  int rc = execve(bp, new_argv, envp);
  free(new_argv);
  return rc;
}

static int bouncer_execvp(const char *file, char *const argv[]) {
  const char *pm = is_risky(file, argv);
  if (!pm) return execvp(file, argv);
  const char *bp = getenv("BOUNCER_PATH");
  if (!bp || !*bp) return execvp(file, argv);
  char **new_argv = rewrite_argv(bp, pm, argv);
  if (!new_argv) return execvp(file, argv);
  log_route(pm, file);
  int rc = execvp(bp, new_argv);
  free(new_argv);
  return rc;
}

static int bouncer_execv(const char *path, char *const argv[]) {
  const char *pm = is_risky(path, argv);
  if (!pm) return execv(path, argv);
  const char *bp = getenv("BOUNCER_PATH");
  if (!bp || !*bp) return execv(path, argv);
  char **new_argv = rewrite_argv(bp, pm, argv);
  if (!new_argv) return execv(path, argv);
  log_route(pm, path);
  int rc = execv(bp, new_argv);
  free(new_argv);
  return rc;
}

static int bouncer_posix_spawn(pid_t *pid, const char *path,
                               const posix_spawn_file_actions_t *fa,
                               const posix_spawnattr_t *attr,
                               char *const argv[], char *const envp[]) {
  const char *pm = is_risky(path, argv);
  if (!pm) return posix_spawn(pid, path, fa, attr, argv, envp);
  const char *bp = getenv("BOUNCER_PATH");
  if (!bp || !*bp) return posix_spawn(pid, path, fa, attr, argv, envp);
  char **new_argv = rewrite_argv(bp, pm, argv);
  if (!new_argv) return posix_spawn(pid, path, fa, attr, argv, envp);
  log_route(pm, path);
  int rc = posix_spawn(pid, bp, fa, attr, new_argv, envp);
  free(new_argv);
  return rc;
}

static int bouncer_posix_spawnp(pid_t *pid, const char *file,
                                const posix_spawn_file_actions_t *fa,
                                const posix_spawnattr_t *attr,
                                char *const argv[], char *const envp[]) {
  const char *pm = is_risky(file, argv);
  if (!pm) return posix_spawnp(pid, file, fa, attr, argv, envp);
  const char *bp = getenv("BOUNCER_PATH");
  if (!bp || !*bp) return posix_spawnp(pid, file, fa, attr, argv, envp);
  char **new_argv = rewrite_argv(bp, pm, argv);
  if (!new_argv) return posix_spawnp(pid, file, fa, attr, argv, envp);
  log_route(pm, file);
  // Re-route to absolute bouncer path via posix_spawn (not posix_spawnp)
  // so we don't pay a PATH lookup we already resolved.
  int rc = posix_spawn(pid, bp, fa, attr, new_argv, envp);
  free(new_argv);
  return rc;
}

BOUNCER_INTERPOSE(bouncer_execve,        execve);
BOUNCER_INTERPOSE(bouncer_execvp,        execvp);
BOUNCER_INTERPOSE(bouncer_execv,         execv);
BOUNCER_INTERPOSE(bouncer_posix_spawn,   posix_spawn);
BOUNCER_INTERPOSE(bouncer_posix_spawnp,  posix_spawnp);

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

static void __attribute__((constructor)) bouncer_init(void) {
  real_execve       = (execve_fn)      dlsym(RTLD_NEXT, "execve");
  real_execvp       = (execvp_fn)      dlsym(RTLD_NEXT, "execvp");
  real_execv        = (execv_fn)       dlsym(RTLD_NEXT, "execv");
  real_posix_spawn  = (posix_spawn_fn) dlsym(RTLD_NEXT, "posix_spawn");
  real_posix_spawnp = (posix_spawn_fn) dlsym(RTLD_NEXT, "posix_spawnp");
}

int execve(const char *path, char *const argv[], char *const envp[]) {
  const char *pm = is_risky(path, argv);
  if (!pm) return real_execve(path, argv, envp);
  const char *bp = getenv("BOUNCER_PATH");
  if (!bp || !*bp) return real_execve(path, argv, envp);
  char **new_argv = rewrite_argv(bp, pm, argv);
  if (!new_argv) return real_execve(path, argv, envp);
  log_route(pm, path);
  int rc = real_execve(bp, new_argv, envp);
  free(new_argv);
  return rc;
}

int execvp(const char *file, char *const argv[]) {
  const char *pm = is_risky(file, argv);
  if (!pm) return real_execvp(file, argv);
  const char *bp = getenv("BOUNCER_PATH");
  if (!bp || !*bp) return real_execvp(file, argv);
  char **new_argv = rewrite_argv(bp, pm, argv);
  if (!new_argv) return real_execvp(file, argv);
  log_route(pm, file);
  int rc = real_execvp(bp, new_argv);
  free(new_argv);
  return rc;
}

int execv(const char *path, char *const argv[]) {
  const char *pm = is_risky(path, argv);
  if (!pm) return real_execv(path, argv);
  const char *bp = getenv("BOUNCER_PATH");
  if (!bp || !*bp) return real_execv(path, argv);
  char **new_argv = rewrite_argv(bp, pm, argv);
  if (!new_argv) return real_execv(path, argv);
  log_route(pm, path);
  int rc = real_execv(bp, new_argv);
  free(new_argv);
  return rc;
}

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *fa,
                const posix_spawnattr_t *attr,
                char *const argv[], char *const envp[]) {
  const char *pm = is_risky(path, argv);
  if (!pm) return real_posix_spawn(pid, path, fa, attr, argv, envp);
  const char *bp = getenv("BOUNCER_PATH");
  if (!bp || !*bp) return real_posix_spawn(pid, path, fa, attr, argv, envp);
  char **new_argv = rewrite_argv(bp, pm, argv);
  if (!new_argv) return real_posix_spawn(pid, path, fa, attr, argv, envp);
  log_route(pm, path);
  int rc = real_posix_spawn(pid, bp, fa, attr, new_argv, envp);
  free(new_argv);
  return rc;
}

int posix_spawnp(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *fa,
                 const posix_spawnattr_t *attr,
                 char *const argv[], char *const envp[]) {
  const char *pm = is_risky(file, argv);
  if (!pm) return real_posix_spawnp(pid, file, fa, attr, argv, envp);
  const char *bp = getenv("BOUNCER_PATH");
  if (!bp || !*bp) return real_posix_spawnp(pid, file, fa, attr, argv, envp);
  char **new_argv = rewrite_argv(bp, pm, argv);
  if (!new_argv) return real_posix_spawnp(pid, file, fa, attr, argv, envp);
  log_route(pm, file);
  int rc = real_posix_spawn(pid, bp, fa, attr, new_argv, envp);
  free(new_argv);
  return rc;
}

#endif
