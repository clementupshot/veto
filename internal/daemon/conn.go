package daemon

import (
	"encoding/json"
	"io"
	"net"
	"strconv"
	"syscall"

	"github.com/brynbellomy/go-utils/errors"
)

func itoa(n int) string { return strconv.Itoa(n) }

// MaxRequestBytes bounds the size of a Request payload to defend against a
// hostile (or buggy) client streaming unbounded JSON at the daemon. A real
// install request — even with hundreds of args and a large env — fits in
// well under 64 KiB.
const MaxRequestBytes = 256 * 1024

// FDCount is the number of file descriptors a Request carries: stdin,
// stdout, stderr.
const FDCount = 3

// FD indices into the fds slice returned by RecvRequest.
const (
	FDStdin  = 0
	FDStdout = 1
	FDStderr = 2
)

// SendRequest writes req as length-prefixed JSON to conn, with stdin,
// stdout, stderr fds attached out-of-band via SCM_RIGHTS. The daemon
// receives the fds and dup2's them onto the spawned PM's stdio so the
// PM writes directly to the original terminal (or pipe), no proxy in the
// data path.
//
// We send in two steps:
//
//  1. sendmsg(header_bytes, oob=SCM_RIGHTS) — carries the 4-byte length
//     prefix with the fds attached. The kernel atomically delivers the
//     fds with these few bytes in the daemon's first recvmsg.
//  2. write(payload_bytes) — the JSON request itself.
//
// macOS's sendmsg() on SOCK_STREAM caps the data portion when ancillary
// data is attached at one mbuf cluster (typically ~8KB), so we keep the
// sendmsg payload tiny and stream the rest with a regular Write. The
// daemon mirrors this split: recvmsg for header+fds, ReadFull for body.
//
// Returns once both writes complete. fds passed in are NOT closed here;
// the caller decides their lifetime (typically the client closes them
// right after Send, since the kernel has duplicated them into the
// daemon).
func SendRequest(conn *net.UnixConn, req Request, fds [FDCount]int) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return errors.With(err, "marshal request")
	}
	if len(payload) > MaxRequestBytes {
		return errors.WithNew("request too large").Set("bytes", len(payload))
	}
	header := lenPrefix(len(payload))
	oob := syscall.UnixRights(fds[:]...)

	// Step 1: header + fds via sendmsg.
	n, oobn, err := conn.WriteMsgUnix(header[:], oob, nil)
	if err != nil {
		return errors.With(err, "sendmsg header+fds")
	}
	if n != len(header) || oobn != len(oob) {
		return errors.WithNew(
			"short write on header+fds: header_written=" + itoa(n) +
				" header_expected=" + itoa(len(header)) +
				" oob_written=" + itoa(oobn) +
				" oob_expected=" + itoa(len(oob)),
		)
	}

	// Step 2: payload via regular write. SOCK_STREAM may split into
	// multiple kernel deliveries — that's fine, the receiver uses
	// io.ReadFull to drain exactly len(payload) bytes.
	if _, err := conn.Write(payload); err != nil {
		return errors.With(err, "write payload")
	}
	return nil
}

// RecvRequest reads a Request from conn. The sender uses a two-step
// pattern (recvmsg for header+fds, write for payload) so the daemon does
// the same: one recvmsg to capture the header bytes AND the SCM_RIGHTS
// fds atomically, then a regular ReadFull to consume the JSON payload.
//
// The returned fds are owned by the caller (the daemon) and must be
// closed after use — typically after handing them to os.StartProcess
// which dup2's them into the child.
//
// Fails closed: any error (short read, malformed JSON, wrong fd count,
// oversized payload) returns an error with zero-valued Request/fds. The
// daemon should send a StatusError response and close the connection.
func RecvRequest(conn *net.UnixConn) (Request, [FDCount]int, error) {
	var zeroFDs [FDCount]int

	// Step 1: recvmsg for header (4 bytes) + SCM_RIGHTS fds. We
	// allocate a slightly larger data buffer in case the kernel
	// coalesces some payload bytes alongside the header; any extra
	// bytes are stashed and consumed before the ReadFull.
	const headerLen = 4
	const recvBuf = 4096
	data := make([]byte, recvBuf)
	oob := make([]byte, syscall.CmsgSpace(FDCount*4))
	n, oobn, flags, _, err := conn.ReadMsgUnix(data, oob)
	if err != nil {
		return Request{}, zeroFDs, errors.With(err, "recvmsg header+fds")
	}
	if flags&syscall.MSG_CTRUNC != 0 {
		closeFDsFromOOB(oob[:oobn])
		return Request{}, zeroFDs, errors.WithNew("control message truncated; sender attached more fds than expected")
	}
	if n < headerLen {
		closeFDsFromOOB(oob[:oobn])
		return Request{}, zeroFDs, errors.WithNew("short read: header").Set("bytes", n)
	}

	fds, err := parseFDsFromOOB(oob[:oobn])
	if err != nil {
		return Request{}, zeroFDs, err
	}

	var headerArr [4]byte
	copy(headerArr[:], data[:headerLen])
	payloadLen := decodeLenPrefix(headerArr)
	if payloadLen > MaxRequestBytes {
		closeFDs(fds[:])
		return Request{}, zeroFDs, errors.WithNew("payload length exceeds limit").
			Set("declared", payloadLen).
			Set("limit", MaxRequestBytes)
	}

	// Some payload bytes may have come with the header recvmsg if the
	// sender wrote in one syscall (we don't, but defend against future
	// sender refactors that do).
	payload := make([]byte, payloadLen)
	alreadyRead := n - headerLen
	if alreadyRead > payloadLen {
		alreadyRead = payloadLen
	}
	copy(payload, data[headerLen:headerLen+alreadyRead])
	if alreadyRead < payloadLen {
		if _, err := io.ReadFull(conn, payload[alreadyRead:]); err != nil {
			closeFDs(fds[:])
			return Request{}, zeroFDs, errors.With(err, "read payload")
		}
	}

	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		closeFDs(fds[:])
		return Request{}, zeroFDs, errors.With(err, "unmarshal request")
	}
	return req, fds, nil
}

// SendResponse writes resp as JSON to conn, no fds attached. The client
// reads and exits.
func SendResponse(conn *net.UnixConn, resp Response) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		return errors.With(err, "marshal response")
	}
	header := lenPrefix(len(payload))
	if _, err := conn.Write(header[:]); err != nil {
		return errors.With(err, "write response header")
	}
	if _, err := conn.Write(payload); err != nil {
		return errors.With(err, "write response payload")
	}
	return nil
}

// RecvResponse reads a length-prefixed JSON Response from conn.
func RecvResponse(conn *net.UnixConn) (Response, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return Response{}, errors.With(err, "read response header")
	}
	payloadLen := decodeLenPrefix(header)
	if payloadLen > MaxRequestBytes {
		return Response{}, errors.WithNew("response too large").Set("bytes", payloadLen)
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return Response{}, errors.With(err, "read response payload")
	}
	var resp Response
	if err := json.Unmarshal(payload, &resp); err != nil {
		return Response{}, errors.With(err, "unmarshal response")
	}
	return resp, nil
}

func lenPrefix(n int) [4]byte {
	return [4]byte{
		byte(n >> 24),
		byte(n >> 16),
		byte(n >> 8),
		byte(n),
	}
}

func decodeLenPrefix(b [4]byte) int {
	return int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
}

// parseFDsFromOOB walks the SCM_RIGHTS control messages and returns the
// three fds. Errors if the count doesn't match exactly — receiving more
// or fewer fds than expected is a protocol violation, not a thing to
// guess at.
func parseFDsFromOOB(oob []byte) ([FDCount]int, error) {
	var fds [FDCount]int
	scms, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return fds, errors.With(err, "parse socket control message")
	}
	var collected []int
	for _, scm := range scms {
		if scm.Header.Level != syscall.SOL_SOCKET || scm.Header.Type != syscall.SCM_RIGHTS {
			continue
		}
		got, err := syscall.ParseUnixRights(&scm)
		if err != nil {
			return fds, errors.With(err, "parse unix rights")
		}
		collected = append(collected, got...)
	}
	if len(collected) != FDCount {
		// Close any fds we did receive so we don't leak them.
		closeFDs(collected)
		return fds, errors.WithNew("wrong fd count").
			Set("expected", FDCount).
			Set("received", len(collected))
	}
	copy(fds[:], collected)
	return fds, nil
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		if fd > 0 {
			_ = syscall.Close(fd)
		}
	}
}

// closeFDsFromOOB is the best-effort cleanup path when we have to bail
// before fully validating the request — we still need to close the fds
// the kernel handed us or they leak in the daemon process.
func closeFDsFromOOB(oob []byte) {
	scms, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	for _, scm := range scms {
		if scm.Header.Level != syscall.SOL_SOCKET || scm.Header.Type != syscall.SCM_RIGHTS {
			continue
		}
		got, err := syscall.ParseUnixRights(&scm)
		if err != nil {
			continue
		}
		closeFDs(got)
	}
}
