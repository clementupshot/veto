package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/package-bouncer/internal/daemon"
	"github.com/brynbellomy/package-bouncer/internal/intel"
)

// daemonFakeSource is an in-process intel.Source that returns a fixed list
// of MalwareReports. Mirrors the helper in internal/gate/gate_test.go; we
// can't import that one because it's in package gate_test.
type daemonFakeSource struct {
	reports []intel.MalwareReport
}

func (daemonFakeSource) ID() string { return "fake" }
func (f daemonFakeSource) Fetch(_ context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	var out []intel.MalwareReport
	for _, r := range f.reports {
		if r.Ecosystem == eco {
			out = append(out, r)
		}
	}
	return out, nil
}

func buildTestStore(t *testing.T, reports ...intel.MalwareReport) intel.Store {
	t.Helper()
	store := intel.NewStore(zerolog.Nop(), daemonFakeSource{reports: reports})
	require.NoError(t, store.Refresh(context.Background()))
	return store
}

// TestDaemonHandlesCleanInstall: a clean install routes through the gate
// (allow) and the daemon spawns the (fake) real PM with the request's
// args/cwd/fds. We verify the spawn by having fake-npm touch a marker
// file in cwd containing its argv.
func TestDaemonHandlesCleanInstall(t *testing.T) {
	tmp := t.TempDir()
	marker := filepath.Join(tmp, "ran")
	fakeNpm := filepath.Join(tmp, "npm")
	require.NoError(t, os.WriteFile(fakeNpm,
		[]byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+marker+"\nexit 0\n"),
		0o755))

	// Put fakeNpm on PATH so findRealBinary picks it up. Restore on
	// cleanup so other tests aren't affected.
	origPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", origPath) })
	require.NoError(t, os.Setenv("PATH", tmp+":"+origPath))

	store := buildTestStore(t) // no flagged reports
	client, server := unixPair(t)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		handleDaemonConn(zerolog.Nop(), store, server)
	}()

	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	require.NoError(t, err)
	defer devnull.Close()
	fds := [daemon.FDCount]int{int(devnull.Fd()), int(devnull.Fd()), int(devnull.Fd())}

	require.NoError(t, daemon.SendRequest(client, daemon.Request{
		PM:   "npm",
		Args: []string{"install", "lodash"},
		Cwd:  tmp,
		Env:  []string{"PATH=" + tmp + ":" + origPath},
	}, fds))

	resp, err := daemon.RecvResponse(client)
	require.NoError(t, err)
	require.Equal(t, daemon.StatusOK, resp.Status, "msg=%s", resp.Message)
	require.Equal(t, 0, resp.ExitCode)

	wg.Wait()

	// Marker confirms fakeNpm actually ran in tmp with the right argv.
	data, err := os.ReadFile(marker)
	require.NoError(t, err, "fake npm did not run — daemon didn't spawn the PM")
	require.Equal(t, "install\nlodash\n", string(data))
}

// TestDaemonRefusesFlaggedInstall: a flagged install must NOT spawn the
// real PM and must return StatusRefused with the report attached.
func TestDaemonRefusesFlaggedInstall(t *testing.T) {
	tmp := t.TempDir()
	marker := filepath.Join(tmp, "ran")
	fakeNpm := filepath.Join(tmp, "npm")
	// Sentinel exit code so a false-negative (daemon spawns the PM
	// instead of refusing) produces a distinct failure shape.
	require.NoError(t, os.WriteFile(fakeNpm,
		[]byte("#!/bin/sh\ntouch "+marker+"\nexit 77\n"),
		0o755))

	origPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", origPath) })
	require.NoError(t, os.Setenv("PATH", tmp+":"+origPath))

	store := buildTestStore(t, intel.MalwareReport{
		PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil-pkg"},
		SourceID:   "fake",
		Reason:     "MALWARE",
	})
	client, server := unixPair(t)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		handleDaemonConn(zerolog.Nop(), store, server)
	}()

	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	require.NoError(t, err)
	defer devnull.Close()
	fds := [daemon.FDCount]int{int(devnull.Fd()), int(devnull.Fd()), int(devnull.Fd())}

	require.NoError(t, daemon.SendRequest(client, daemon.Request{
		PM:   "npm",
		Args: []string{"install", "evil-pkg"},
		Cwd:  tmp,
		Env:  []string{"PATH=" + tmp + ":" + origPath},
	}, fds))

	resp, err := daemon.RecvResponse(client)
	require.NoError(t, err)
	require.Equal(t, daemon.StatusRefused, resp.Status, "msg=%s", resp.Message)
	require.NotEmpty(t, resp.Reports, "refused response must carry reports")
	require.Equal(t, "evil-pkg", resp.Reports[0].Name)
	require.Equal(t, "fake", resp.Reports[0].SourceID)

	wg.Wait()

	// Marker absence confirms fakeNpm was NOT spawned.
	_, err = os.Stat(marker)
	require.True(t, os.IsNotExist(err), "fake npm ran despite refusal")
}

// TestDaemonHonorsBouncerBypass: BOUNCER_BYPASS=1 in the request env
// skips the gate and execs the PM regardless of intel verdict. This is
// the documented per-call escape hatch.
func TestDaemonHonorsBouncerBypass(t *testing.T) {
	tmp := t.TempDir()
	marker := filepath.Join(tmp, "ran")
	fakeNpm := filepath.Join(tmp, "npm")
	require.NoError(t, os.WriteFile(fakeNpm,
		[]byte("#!/bin/sh\ntouch "+marker+"\nexit 0\n"),
		0o755))

	origPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", origPath) })
	require.NoError(t, os.Setenv("PATH", tmp+":"+origPath))

	store := buildTestStore(t, intel.MalwareReport{
		PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil-pkg"},
		SourceID:   "fake",
		Reason:     "MALWARE",
	})
	client, server := unixPair(t)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		handleDaemonConn(zerolog.Nop(), store, server)
	}()

	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	require.NoError(t, err)
	defer devnull.Close()
	fds := [daemon.FDCount]int{int(devnull.Fd()), int(devnull.Fd()), int(devnull.Fd())}

	require.NoError(t, daemon.SendRequest(client, daemon.Request{
		PM:   "npm",
		Args: []string{"install", "evil-pkg"},
		Cwd:  tmp,
		Env:  []string{"BOUNCER_BYPASS=1", "PATH=" + tmp + ":" + origPath},
	}, fds))

	resp, err := daemon.RecvResponse(client)
	require.NoError(t, err)
	require.Equal(t, daemon.StatusOK, resp.Status, "msg=%s", resp.Message)
	require.Equal(t, 0, resp.ExitCode)

	wg.Wait()

	_, err = os.Stat(marker)
	require.NoError(t, err, "BOUNCER_BYPASS=1 should have let fakeNpm run")
}

func unixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	require.NoError(t, err)
	c1 := fdToConn(t, fds[0])
	c2 := fdToConn(t, fds[1])
	return c1, c2
}

func fdToConn(t *testing.T, fd int) *net.UnixConn {
	t.Helper()
	f := os.NewFile(uintptr(fd), "sock")
	require.NotNil(t, f)
	c, err := net.FileConn(f)
	require.NoError(t, err)
	_ = f.Close()
	uc, ok := c.(*net.UnixConn)
	require.True(t, ok)
	return uc
}
