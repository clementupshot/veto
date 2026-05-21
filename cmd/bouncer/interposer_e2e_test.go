// End-to-end test for the native interposer.
//
// The flow:
//
//  1. Build the interposer .dylib/.so (skip the test if `make interposer`
//     hasn't been run AND we can't run it from here).
//  2. Build a tiny "spawner" helper that calls syscall.Exec(target, args)
//     — the spawner's posix_spawn / execve calls are what the interposer
//     hooks.
//  3. Drop a fake bouncer into a temp dir. It just dumps argv to a log
//     file and exits.
//  4. Drop a fake `npm` next to it. The interposer should see "the
//     program being exec'd is named npm with verb=install" and route the
//     call through fake-bouncer instead of executing fake-npm.
//  5. Run the spawner with DYLD_INSERT_LIBRARIES (macOS) / LD_PRELOAD
//     (Linux) pointing at the interposer, BOUNCER_PATH pointing at the
//     fake bouncer.
//  6. Assert the fake bouncer received argv == [bouncer, npm, install, foo].
//
// This catches the failure modes that unit tests cannot: argv-allocation
// bugs, NULL termination off-by-ones, dyld linkage issues, and the
// "interposer loaded but doesn't actually intercept" class of bugs.

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInterposerEndToEnd_RewritesNpmInstall(t *testing.T) {
	libPath := interposerLibPath(t)
	if libPath == "" {
		t.Skip("interposer artifact not built; run `make interposer` to enable this test")
	}

	dir := t.TempDir()
	argLog := filepath.Join(dir, "argv.log")

	// Fake bouncer: writes argv (one arg per line) to argLog.
	fakeBouncer := filepath.Join(dir, "bouncer")
	bouncerScript := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + argLog + "\n" +
		"exit 0\n"
	require.NoError(t, os.WriteFile(fakeBouncer, []byte(bouncerScript), 0o755))

	// Fake npm: should NEVER run; sentinel exit code so a false-negative
	// (interposer fails to intercept) produces a clearly distinct failure.
	fakeNpm := filepath.Join(dir, "npm")
	require.NoError(t, os.WriteFile(fakeNpm, []byte("#!/bin/sh\nexit 77\n"), 0o755))

	// Build the spawner helper inside the temp dir so we don't pollute
	// the repo. Go run would work too but `go build` keeps the binary
	// around for debugging if the test fails.
	spawnerSrc := filepath.Join("testdata", "interpose_spawner", "main.go")
	spawnerBin := filepath.Join(dir, "spawner")
	build := exec.Command("go", "build", "-o", spawnerBin, spawnerSrc)
	build.Stderr = os.Stderr
	require.NoError(t, build.Run(), "build interpose_spawner helper")

	// Spawn the helper, asking it to exec fakeNpm with install+foo.
	cmd := exec.Command(spawnerBin, fakeNpm, "install", "foo")
	cmd.Env = withPreloadEnv(libPath, fakeBouncer)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	require.NoError(t, err, "spawner exit error; stderr=%s", stderr.String())

	// If the interposer didn't fire, fakeNpm would have run and exited 77.
	// We're here, so something exec'd successfully (we expect fakeBouncer).
	data, err := os.ReadFile(argLog)
	require.NoError(t, err, "fakeBouncer did not write argv.log — interposer may not have rewritten")
	lines := splitLines(string(data))
	// fakeBouncer's "$@" excludes argv[0] ("bouncer"). The interposer
	// rewrites to [bouncer, npm, install, foo]; the script sees npm,
	// install, foo.
	require.Equal(t, []string{"npm", "install", "foo"}, lines)
}

func TestInterposerEndToEnd_PassesThroughNonPM(t *testing.T) {
	libPath := interposerLibPath(t)
	if libPath == "" {
		t.Skip("interposer artifact not built; run `make interposer`")
	}

	dir := t.TempDir()
	// Marker file the target writes to confirm it actually ran.
	marker := filepath.Join(dir, "ran")
	target := filepath.Join(dir, "myprog")
	script := "#!/bin/sh\ntouch " + marker + "\nexit 0\n"
	require.NoError(t, os.WriteFile(target, []byte(script), 0o755))

	// fake bouncer that would log if mistakenly invoked.
	fakeBouncer := filepath.Join(dir, "bouncer")
	require.NoError(t, os.WriteFile(fakeBouncer, []byte("#!/bin/sh\nexit 99\n"), 0o755))

	spawnerSrc := filepath.Join("testdata", "interpose_spawner", "main.go")
	spawnerBin := filepath.Join(dir, "spawner")
	require.NoError(t, exec.Command("go", "build", "-o", spawnerBin, spawnerSrc).Run())

	cmd := exec.Command(spawnerBin, target)
	cmd.Env = withPreloadEnv(libPath, fakeBouncer)
	require.NoError(t, cmd.Run())
	_, err := os.Stat(marker)
	require.NoError(t, err, "target program did not run — interposer rewrote a non-PM call (false positive)")
}

func TestInterposerEndToEnd_AllowsNpmRunDev(t *testing.T) {
	// `npm run dev` is a PM invocation with a NON-dangerous verb; the
	// interposer must let it through unchanged.
	libPath := interposerLibPath(t)
	if libPath == "" {
		t.Skip("interposer artifact not built; run `make interposer`")
	}

	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	fakeNpm := filepath.Join(dir, "npm")
	script := "#!/bin/sh\ntouch " + marker + "\nexit 0\n"
	require.NoError(t, os.WriteFile(fakeNpm, []byte(script), 0o755))

	fakeBouncer := filepath.Join(dir, "bouncer")
	require.NoError(t, os.WriteFile(fakeBouncer, []byte("#!/bin/sh\nexit 99\n"), 0o755))

	spawnerSrc := filepath.Join("testdata", "interpose_spawner", "main.go")
	spawnerBin := filepath.Join(dir, "spawner")
	require.NoError(t, exec.Command("go", "build", "-o", spawnerBin, spawnerSrc).Run())

	cmd := exec.Command(spawnerBin, fakeNpm, "run", "dev")
	cmd.Env = withPreloadEnv(libPath, fakeBouncer)
	require.NoError(t, cmd.Run())
	_, err := os.Stat(marker)
	require.NoError(t, err, "fake npm did not run — `npm run dev` was incorrectly rewritten")
}

// interposerLibPath returns the absolute path to the built interposer
// artifact, or "" if it doesn't exist. We look both in the repo root
// (where `make interposer` puts it) and in the testdata dir, so the test
// can be wired up either way.
func interposerLibPath(t *testing.T) string {
	t.Helper()
	name := "libbouncer_interpose.dylib"
	if runtime.GOOS != "darwin" {
		name = "libbouncer_interpose.so"
	}
	// Tests run with cwd = the package dir (cmd/bouncer). The library
	// lives in the repo root, two levels up.
	candidates := []string{
		filepath.Join("..", "..", name),
		filepath.Join(name),
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	return ""
}

// withPreloadEnv returns os.Environ() augmented with the preload env
// vars. Preserves the current PATH so the Go toolchain (for the build
// step above) still resolves correctly.
func withPreloadEnv(libPath, bouncerPath string) []string {
	env := os.Environ()
	envVar := "DYLD_INSERT_LIBRARIES"
	if runtime.GOOS != "darwin" {
		envVar = "LD_PRELOAD"
	}
	env = append(env, envVar+"="+libPath)
	env = append(env, "BOUNCER_PATH="+bouncerPath)
	// Optional: BOUNCER_INTERPOSE_LOG=1 emits a stderr marker each time the
	// interposer rewrites. Useful when debugging a failing test locally.
	return env
}

func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
