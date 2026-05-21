package daemon_test

import (
	"net"
	"os"
	"reflect"
	"sync"
	"syscall"
	"testing"

	"github.com/brynbellomy/veto/internal/daemon"
)

// TestSendReceiveRoundTrip pumps a Request with three pipe-fds through a
// socketpair and asserts the daemon side reads the JSON and recovers the
// fds correctly. The fds are pipe write-ends; we verify they're usable by
// writing into them and reading from the held read-ends in the test.
func TestSendReceiveRoundTrip(t *testing.T) {
	clientConn, daemonConn := unixSocketPair(t)
	defer clientConn.Close()
	defer daemonConn.Close()

	// Three pipes; pass the WRITE ends through the protocol, keep the
	// READ ends in the test so we can prove the daemon-side dup'd fds
	// are connected to the same kernel buffers.
	stdinR, stdinW := pipe(t)
	stdoutR, stdoutW := pipe(t)
	stderrR, stderrW := pipe(t)
	defer stdinR.Close()
	defer stdoutR.Close()
	defer stderrR.Close()

	wantReq := daemon.Request{
		PM:   "npm",
		Args: []string{"install", "lodash"},
		Cwd:  "/tmp/proj",
		Env:  []string{"FOO=bar", "PATH=/usr/bin"},
	}

	var (
		gotReq  daemon.Request
		gotFDs  [daemon.FDCount]int
		recvErr error
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		gotReq, gotFDs, recvErr = daemon.RecvRequest(daemonConn)
	}()

	fds := [daemon.FDCount]int{
		daemon.FDStdin:  int(stdinW.Fd()),
		daemon.FDStdout: int(stdoutW.Fd()),
		daemon.FDStderr: int(stderrW.Fd()),
	}
	if err := daemon.SendRequest(clientConn, wantReq, fds); err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	// Close the client-side writer ends immediately — the daemon has
	// kernel-level dup'd them; closing here doesn't disturb the daemon's
	// view, and it proves the fds the daemon got are independent.
	stdinW.Close()
	stdoutW.Close()
	stderrW.Close()

	wg.Wait()
	if recvErr != nil {
		t.Fatalf("RecvRequest: %v", recvErr)
	}
	if !reflect.DeepEqual(gotReq, wantReq) {
		t.Fatalf("request mismatch\ngot:  %+v\nwant: %+v", gotReq, wantReq)
	}

	// Daemon-side fds must be live: writing to them should reach the
	// reader ends we held back in the test.
	probeFD(t, gotFDs[daemon.FDStdin], "stdin-payload\n", stdinR)
	probeFD(t, gotFDs[daemon.FDStdout], "stdout-payload\n", stdoutR)
	probeFD(t, gotFDs[daemon.FDStderr], "stderr-payload\n", stderrR)

	// Daemon must close them when done — simulate.
	for _, fd := range gotFDs {
		_ = syscall.Close(fd)
	}
}

func TestSendResponseRoundTrip(t *testing.T) {
	clientConn, daemonConn := unixSocketPair(t)
	defer clientConn.Close()
	defer daemonConn.Close()

	want := daemon.Response{
		Status:   daemon.StatusRefused,
		ExitCode: 0,
		Message:  "install refused — malware intelligence flagged the following",
		Reports: []daemon.Report{
			{Name: "evil-pkg", Ecosystem: "npm", SourceID: "aikido", Reason: "MALWARE"},
		},
	}

	var (
		got     daemon.Response
		recvErr error
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, recvErr = daemon.RecvResponse(clientConn)
	}()

	if err := daemon.SendResponse(daemonConn, want); err != nil {
		t.Fatalf("SendResponse: %v", err)
	}
	wg.Wait()
	if recvErr != nil {
		t.Fatalf("RecvResponse: %v", recvErr)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("response mismatch\ngot:  %+v\nwant: %+v", got, want)
	}
}

// TestRecvRejectsOversizedHeader confirms a hostile client claiming a
// gigantic payload is rejected before we allocate or read it. The wire
// limit is the only thing standing between us and trivial DoS via
// "promise me 4 GiB then disconnect".
func TestRecvRejectsOversizedHeader(t *testing.T) {
	clientConn, daemonConn := unixSocketPair(t)
	defer clientConn.Close()
	defer daemonConn.Close()

	// Build a header announcing a payload larger than MaxRequestBytes.
	hdr := []byte{0x10, 0x00, 0x00, 0x00} // 256 MiB declared
	// Open three /dev/null fds so the kernel doesn't reject the sendmsg
	// for missing SCM_RIGHTS payload.
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	defer devnull.Close()
	fd := int(devnull.Fd())
	oob := syscall.UnixRights(fd, fd, fd)

	if _, _, err := clientConn.WriteMsgUnix(hdr, oob, nil); err != nil {
		t.Fatalf("sendmsg evil header: %v", err)
	}

	_, _, err = daemon.RecvRequest(daemonConn)
	if err == nil {
		t.Fatalf("expected RecvRequest to reject oversized header")
	}
}

// --- helpers ------------------------------------------------------------

func unixSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	c1 := fdToUnixConn(t, fds[0], "c1")
	c2 := fdToUnixConn(t, fds[1], "c2")
	return c1, c2
}

func fdToUnixConn(t *testing.T, fd int, name string) *net.UnixConn {
	t.Helper()
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		t.Fatalf("os.NewFile(%d) returned nil", fd)
	}
	c, err := net.FileConn(f)
	if err != nil {
		t.Fatalf("net.FileConn: %v", err)
	}
	// net.FileConn dup's the fd; we can close our copy.
	_ = f.Close()
	uc, ok := c.(*net.UnixConn)
	if !ok {
		t.Fatalf("expected *net.UnixConn, got %T", c)
	}
	return uc
}

func pipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	return r, w
}

func probeFD(t *testing.T, fd int, payload string, reader *os.File) {
	t.Helper()
	// Wrap the daemon-side fd in an os.File so we can use Write. The
	// daemon will normally hand the fd to dup2 inside posix_spawn — the
	// fd's identity doesn't depend on Go-level wrapping, just on its
	// position in the daemon's table.
	f := os.NewFile(uintptr(fd), "daemon-side")
	if _, err := f.WriteString(payload); err != nil {
		t.Fatalf("write daemon-side fd %d: %v", fd, err)
	}
	// Read it back through the held reader end.
	buf := make([]byte, len(payload))
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(buf[:n]) != payload {
		t.Fatalf("payload mismatch: got %q want %q", string(buf[:n]), payload)
	}
	// Don't Close f — that would close the underlying fd that the
	// caller may also try to close.
}
