// interpose_execl_spawner is the C-side analogue of interpose_spawner/main.go.
//
// It exercises the variadic execl() call path — the exact gap H7 closes.
// Without the execl shadow, libc routes through an internal __execve that
// no LD_PRELOAD / DYLD_INSERT_LIBRARIES interposer catches; the call
// would reach the kernel unmodified and our veto/Layer-3 gate would
// never fire.
//
// Usage:
//   interpose_execl_spawner <target> [args...]
//
// The spawner builds an execl call with argv = [basename(target), args...]
// and exec's <target>. Under DYLD_INSERT_LIBRARIES (macOS) or LD_PRELOAD
// (Linux), the veto interposer must rewrite the call to invoke
// $VETO_PATH with the original basename promoted to argv[1].
//
// We cap the variadic argv at 8 entries — plenty for the e2e tests
// (`execl npm install foo NULL`) and keeps the source dependency-free.

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <target> [args...]\n", argv[0]);
    return 2;
  }
  const char *target = argv[1];
  // basename for argv[0] (libc convention).
  const char *slash = strrchr(target, '/');
  const char *base = slash ? slash + 1 : target;

  // Hand-rolled execl: we can't pass a runtime-sized va_list to execl,
  // so we enumerate up to a small fixed cap. The e2e tests pass at
  // most three trailing args, so 8 is overkill.
  switch (argc) {
    case 2:
      execl(target, base, (char *)0);
      break;
    case 3:
      execl(target, base, argv[2], (char *)0);
      break;
    case 4:
      execl(target, base, argv[2], argv[3], (char *)0);
      break;
    case 5:
      execl(target, base, argv[2], argv[3], argv[4], (char *)0);
      break;
    case 6:
      execl(target, base, argv[2], argv[3], argv[4], argv[5], (char *)0);
      break;
    case 7:
      execl(target, base, argv[2], argv[3], argv[4], argv[5], argv[6], (char *)0);
      break;
    default:
      fprintf(stderr, "too many args (max 5 trailing args supported)\n");
      return 2;
  }
  // If we get here, execl failed.
  fprintf(stderr, "execl(%s) failed: %s\n", target, strerror(errno));
  return 1;
}
