// interpose_spawner is a tiny helper used by the interposer e2e test.
//
// It exec's the program named by os.Args[1] with the remaining args.
// When run with DYLD_INSERT_LIBRARIES (or LD_PRELOAD on Linux) pointing at
// the bouncer interposer dylib, the exec call should be intercepted and
// rewritten to invoke BOUNCER_PATH with the original target as argv[1].
//
// Kept dependency-free so `go run` works without a module context.
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: interpose_spawner <target> [args...]")
		os.Exit(2)
	}
	target := os.Args[1]
	argv := os.Args[1:]
	// syscall.Exec on darwin/linux goes through libc's execve / posix_spawn,
	// which is exactly the call site the interposer hooks.
	if err := syscall.Exec(target, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "exec %s: %v\n", target, err)
		os.Exit(1)
	}
}
