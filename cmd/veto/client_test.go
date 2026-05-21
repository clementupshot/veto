package main

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
)

// shortSockPath returns a Unix socket path under /tmp short enough to fit
// macOS's 104-char sun_path limit. Go's t.TempDir() produces paths under
// /var/folders/... (~50 chars) which busts the budget for any test name
// over 30 chars or so. Using /tmp directly leaves comfortable headroom.
func shortSockPath(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "veto-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return filepath.Join(d, "s")
}

// TestClientToDaemonViaSocket: full client→daemon round trip over a real
// Unix listener. Validates net.Dial("unix"), socket path resolution via
// VETO_DAEMON_SOCKET, request encode/decode in production code paths
// (not the test helper's socketpair), and exit-code passthrough.
func TestClientToDaemonViaSocket(t *testing.T) {
	tmp := t.TempDir()
	sockPath := shortSockPath(t)

	// Fake npm: writes argv to marker, exits 42 — so we can prove the
	// daemon exec'd it AND that the client's exit-code mirrors the PM's.
	marker := filepath.Join(tmp, "ran")
	fakeNpm := filepath.Join(tmp, "npm")
	require.NoError(t, os.WriteFile(fakeNpm,
		[]byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+marker+"\nexit 42\n"),
		0o755))

	origPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", origPath) })
	require.NoError(t, os.Setenv("PATH", tmp+":"+origPath))

	store := buildTestStore(t)

	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	// One-shot accept goroutine — the test does exactly one request.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		uconn, _ := conn.(*net.UnixConn)
		handleDaemonConn(zerolog.Nop(), store, uconn)
	}()

	// Working dir for the spawned PM must exist; the daemon stat-checks
	// it. We're already in a Go test working dir, but assert tmp is the
	// requested cwd to keep the test self-contained.
	prevCwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() { _ = os.Chdir(prevCwd) })

	exitCode := daemonClient(zerolog.Nop(), sockPath, "npm", []string{"install", "lodash"})
	require.Equal(t, 42, exitCode, "exit code from fake PM should pass through unchanged")

	wg.Wait()

	data, err := os.ReadFile(marker)
	require.NoError(t, err, "daemon did not spawn fake npm")
	require.Equal(t, "install\nlodash\n", string(data))
}

// TestClientRefusalRendersReports: when the daemon returns StatusRefused
// with reports, the client's exit code is exitRefused and stderr contains
// a recognizable refusal banner. We capture stderr via os.Pipe.
func TestClientRefusalRendersReports(t *testing.T) {
	tmp := t.TempDir()
	sockPath := shortSockPath(t)

	fakeNpm := filepath.Join(tmp, "npm")
	require.NoError(t, os.WriteFile(fakeNpm,
		[]byte("#!/bin/sh\nexit 77\n"),
		0o755))

	origPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", origPath) })
	require.NoError(t, os.Setenv("PATH", tmp+":"+origPath))

	store := buildTestStore(t, intel.MalwareReport{
		PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil-pkg"},
		SourceID:   "fake",
		Reason:     "MALWARE",
	})

	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		uconn, _ := conn.(*net.UnixConn)
		handleDaemonConn(zerolog.Nop(), store, uconn)
	}()

	// Redirect os.Stderr to a pipe so we can inspect the refusal banner.
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	t.Cleanup(func() {
		os.Stderr = origStderr
		_ = r.Close()
	})

	prevCwd, _ := os.Getwd()
	require.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() { _ = os.Chdir(prevCwd) })

	exitCode := daemonClient(zerolog.Nop(), sockPath, "npm", []string{"install", "evil-pkg"})
	w.Close()

	require.Equal(t, exitRefused, exitCode)

	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	stderr := string(buf[:n])
	require.Contains(t, stderr, "install refused — malware intelligence flagged the following:")
	require.Contains(t, stderr, "evil-pkg")
	require.Contains(t, stderr, "[fake]")

	wg.Wait()
}

// TestDaemonSocketExistsDiscriminatesType: regular file at the socket
// path should NOT be mistaken for a usable socket — that would route
// daemon-client traffic to a stale file and produce a confusing
// connection-refused error.
func TestDaemonSocketExistsDiscriminatesType(t *testing.T) {
	sockPath := shortSockPath(t)

	require.False(t, daemonSocketExists(sockPath), "nonexistent path should be false")

	// Regular file at the socket path.
	require.NoError(t, os.WriteFile(sockPath, []byte("not a socket"), 0o600))
	require.False(t, daemonSocketExists(sockPath), "regular file should not be a socket")
	require.NoError(t, os.Remove(sockPath))

	// Actual socket — listen briefly.
	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	defer listener.Close()
	require.True(t, daemonSocketExists(sockPath), "unix listener should register as socket")
}
