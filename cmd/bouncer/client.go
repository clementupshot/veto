package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"

	"github.com/rs/zerolog"

	"github.com/brynbellomy/package-bouncer/internal/daemon"
)

// daemonClient is the client-mode entry point: contact the bouncer daemon
// over its Unix socket, send a Request that names the PM and its args,
// pass our own stdio fds via SCM_RIGHTS, and exit with whatever code the
// daemon reports.
//
// Called from runGate when the daemon socket is reachable. When the
// socket is missing or unreachable, the caller falls back to the
// in-process gate (runGateInProcess). The in-process path is the
// "daemon-less courtesy mode" — useful for a user's own interactive
// shell without launchd setup; the kernel-enforcement story is in the
// daemon path.
func daemonClient(logger zerolog.Logger, socketPath string, pmName string, pmArgs []string) int {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		// Surface this as a hard error rather than silently falling
		// back. If the daemon WAS supposed to be reachable (i.e. we're
		// inside a sandboxed agent that has no other way to install),
		// silent fallback is exactly the wrong move — the in-process
		// path would try to exec the real PM, which the sandbox would
		// reject with EPERM, and the user would get a confusing "exec
		// failed" error. Better to refuse loudly.
		logger.Error().Err(err).Str("socket", socketPath).Msg("connect to daemon")
		fmt.Fprintf(os.Stderr, "bouncer: cannot reach daemon at %s: %v\n", socketPath, err)
		fmt.Fprintln(os.Stderr, "If you have not installed the daemon yet, run `bouncer install-daemon`.")
		return exitInternal
	}
	defer conn.Close()
	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		// net.Dial("unix", ...) always returns *net.UnixConn; the
		// type-assert is a guard against a future refactor reaching
		// here with the wrong network type.
		fmt.Fprintf(os.Stderr, "bouncer: internal: expected *net.UnixConn from net.Dial(unix), got %T\n", conn)
		return exitInternal
	}

	cwd, err := os.Getwd()
	if err != nil {
		logger.Error().Err(err).Msg("getwd")
		return exitInternal
	}

	fds := [daemon.FDCount]int{
		daemon.FDStdin:  int(os.Stdin.Fd()),
		daemon.FDStdout: int(os.Stdout.Fd()),
		daemon.FDStderr: int(os.Stderr.Fd()),
	}
	req := daemon.Request{
		PM:   pmName,
		Args: pmArgs,
		Cwd:  cwd,
		Env:  os.Environ(),
	}
	if err := daemon.SendRequest(uconn, req, fds); err != nil {
		logger.Error().Err(err).Msg("send request")
		fmt.Fprintf(os.Stderr, "bouncer: send request to daemon: %v\n", err)
		return exitInternal
	}

	resp, err := daemon.RecvResponse(uconn)
	if err != nil {
		logger.Error().Err(err).Msg("recv response")
		fmt.Fprintf(os.Stderr, "bouncer: recv response from daemon: %v\n", err)
		return exitInternal
	}

	switch resp.Status {
	case daemon.StatusOK:
		return resp.ExitCode
	case daemon.StatusRefused:
		printRefusalFromResponse(os.Stderr, resp)
		return exitRefused
	case daemon.StatusAborted:
		fmt.Fprintln(os.Stderr, "bouncer: INTERNAL ERROR — install aborted fail-closed.")
		if resp.Message != "" {
			fmt.Fprintln(os.Stderr, "  "+resp.Message)
		}
		fmt.Fprintln(os.Stderr, "\nThis is not a malware block — it's a bouncer-side failure. Investigate before retrying.")
		return exitInternal
	case daemon.StatusError:
		fmt.Fprintf(os.Stderr, "bouncer: daemon error: %s\n", resp.Message)
		return exitInternal
	default:
		fmt.Fprintf(os.Stderr, "bouncer: unknown daemon status: %s\n", resp.Status)
		return exitInternal
	}
}

// printRefusalFromResponse renders the daemon's refusal payload in the
// same shape the old in-process refusal used, so the user-visible UX is
// identical regardless of which path produced the verdict.
func printRefusalFromResponse(w *os.File, resp daemon.Response) {
	fmt.Fprintln(w, "bouncer: install refused — malware intelligence flagged the following:")
	// Group by (name, version) so multiple sources on the same package
	// render as nested lines under one heading, matching the in-process
	// formatter's behavior.
	type key struct{ name, version, ecosystem string }
	groups := make(map[key][]daemon.Report)
	var order []key
	for _, r := range resp.Reports {
		k := key{r.Name, r.Version, r.Ecosystem}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}
	for _, k := range order {
		ver := k.version
		if ver == "" {
			ver = "<any>"
		}
		fmt.Fprintf(w, "  - %s@%s (ecosystem: %s)\n", k.name, ver, k.ecosystem)
		for _, r := range groups[k] {
			reason := r.Reason
			if reason == "" {
				reason = "flagged"
			}
			fmt.Fprintf(w, "      [%s] %s\n", r.SourceID, reason)
		}
	}
	fmt.Fprintln(w, "\nTo override (you really shouldn't), prepend BOUNCER_BYPASS=1 to the command.")
}

// daemonSocketExists reports whether a Unix socket exists at path AND is
// actually a socket. A regular file (e.g. left over from a non-daemon
// install) does not count.
func daemonSocketExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		// Other errors (permission denied, etc.) — treat as "not
		// reachable" and let the in-process fallback decide.
		return false
	}
	return info.Mode()&os.ModeSocket != 0
}
