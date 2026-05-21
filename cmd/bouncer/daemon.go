package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/brynbellomy/package-bouncer/internal/daemon"
	"github.com/brynbellomy/package-bouncer/internal/gate"
	"github.com/brynbellomy/package-bouncer/internal/intel"
)

// daemonRefreshInterval is how often the daemon refreshes the intel store
// in the background. Aikido and OpenSSF only update on the order of hours;
// a 30-minute cadence catches new flags within the day they're published
// without hammering upstream.
const daemonRefreshInterval = 30 * time.Minute

// runDaemon implements the `bouncer daemon` subcommand. It is the
// out-of-sandbox process loaded by launchd that owns the intel store and
// performs the actual exec of real package managers on behalf of
// sandbox-confined bouncer-client invocations.
func runDaemon(logger zerolog.Logger, cfg config, args []string) int {
	socketPath, err := daemon.SocketPath()
	if err != nil {
		logger.Error().Err(err).Msg("resolve socket path")
		return exitInternal
	}
	if err := daemon.EnsureSocketDir(socketPath); err != nil {
		logger.Error().Err(err).Msg("ensure socket dir")
		return exitInternal
	}
	// Clean up a stale socket from a previous run; bind would fail with
	// EADDRINUSE otherwise. Safe because the socket is owned by us (0700
	// parent dir) and we hold the launchd singleton lock.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		logger.Warn().Err(err).Str("path", socketPath).Msg("remove stale socket")
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		logger.Error().Err(err).Str("path", socketPath).Msg("listen")
		return exitInternal
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	if err := os.Chmod(socketPath, 0o600); err != nil {
		logger.Error().Err(err).Msg("chmod socket")
		return exitInternal
	}

	store, err := buildStore(logger, cfg)
	if err != nil {
		logger.Error().Err(err).Msg("build intel store")
		return exitInternal
	}

	// Initial refresh — the daemon won't accept connections until the
	// store is healthy. Sandboxed clients connecting before this point
	// would otherwise hit a cold store and the gate would abort
	// fail-closed, which is annoying on a fresh boot.
	refreshCtx, refreshCancel := context.WithTimeout(context.Background(), syncTimeout)
	if err := store.Refresh(refreshCtx); err != nil {
		refreshCancel()
		logger.Error().Err(err).Msg("initial intel refresh — refusing to start")
		return exitInternal
	}
	refreshCancel()
	if reportCount := store.ReportCount(); reportCount < minHealthyReportCount {
		logger.Error().Int("reports", reportCount).Int("floor", minHealthyReportCount).
			Msg("intel store below sanity floor — refusing to start")
		return exitInternal
	}
	logger.Info().
		Int("reports", store.ReportCount()).
		Str("socket", socketPath).
		Msg("daemon ready")

	// Background refresher.
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()
	go runRefreshLoop(ctx, logger, store)

	// Signal handler: SIGINT/SIGTERM unblock the accept loop via listener
	// close. launchd uses SIGTERM for orderly shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info().Msg("shutdown requested")
		listener.Close()
	}()

	// Accept loop. Connections are handled serially: in a single-user
	// agent loop you don't have concurrent installs, and serializing
	// keeps the gate logic simple (no per-request store snapshot, no
	// concurrent exec-spawn surprises).
	_ = args // reserved for future flags (--socket, --foreground, etc.)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return exitOK
			}
			logger.Warn().Err(err).Msg("accept")
			continue
		}
		unix, ok := conn.(*net.UnixConn)
		if !ok {
			logger.Error().Type("conn", conn).Msg("non-unix connection on unix listener")
			conn.Close()
			continue
		}
		handleDaemonConn(logger, store, unix)
	}
}

// handleDaemonConn services a single client connection: one Request, one
// Response, then close. Errors are sent back as StatusError responses
// when possible so the client can render a useful message; connections
// are always closed on return.
func handleDaemonConn(logger zerolog.Logger, store intel.Store, conn *net.UnixConn) {
	defer conn.Close()
	// Per-connection deadlines defend against a sandboxed client that
	// connects then hangs forever holding the daemon's accept loop. We
	// re-set the deadline once the request is read and we know we're
	// about to fork+exec a real PM, since that can legitimately take a
	// long time.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	req, fds, err := daemon.RecvRequest(conn)
	if err != nil {
		logger.Warn().Err(err).Msg("recv request")
		_ = daemon.SendResponse(conn, daemon.Response{
			Status:  daemon.StatusError,
			Message: fmt.Sprintf("recv request: %v", err),
		})
		return
	}
	// Once the request is in hand we own the fds — be diligent about
	// closing them on every exit path.
	defer closeFDsBest([]int{fds[daemon.FDStdin], fds[daemon.FDStdout], fds[daemon.FDStderr]})

	// Clear the read deadline now that the request is in. The PM may
	// run for minutes (npm install is slow). Write deadline for the
	// final response is set just before sending.
	_ = conn.SetReadDeadline(time.Time{})

	logger.Info().Str("pm", req.PM).Strs("args", req.Args).Str("cwd", req.Cwd).Msg("request")

	// BOUNCER_BYPASS=1 in the request env is the documented per-call
	// escape hatch. Honored loudly: logged at INFO so it shows up in
	// the daemon's launchd log alongside the install it skipped.
	if envHas(req.Env, "BOUNCER_BYPASS", "1") {
		logger.Info().Str("pm", req.PM).Msg("BOUNCER_BYPASS=1 — skipping gate")
		execPMAndReply(logger, conn, req, fds)
		return
	}

	pms := buildPackageManagers()
	pm, known := pms[req.PM]
	if !known {
		// Unknown PM — pass through. The daemon is the only thing that
		// can reach the real binary, so we have to exec something. Log
		// for forensics.
		logger.Warn().Str("pm", req.PM).Msg("unknown package manager; passing through")
		execPMAndReply(logger, conn, req, fds)
		return
	}

	installs := pm.ParseInstalls(req.Args)
	manifestRefs := pm.ManifestRefs(req.Args)
	if installs == nil && len(manifestRefs) == 0 {
		// Not an install verb — pass through, no gate needed.
		execPMAndReply(logger, conn, req, fds)
		return
	}

	policy := gate.DefaultPolicy()
	policy.ManifestExpander = newCompoundExpander()
	g := gate.New(store, policy).WithLogger(logger)
	decision := g.Evaluate(installs, manifestRefs...)

	switch decision.Outcome {
	case gate.OutcomePassThrough, gate.OutcomeAllow:
		execPMAndReply(logger, conn, req, fds)
	case gate.OutcomeRefuse:
		sendRefused(conn, decision)
	case gate.OutcomeAbort:
		sendAborted(conn, decision)
	default:
		_ = daemon.SendResponse(conn, daemon.Response{
			Status:  daemon.StatusError,
			Message: fmt.Sprintf("unknown gate outcome: %s", decision.Outcome),
		})
	}
}

// execPMAndReply resolves the real PM binary, spawns it with the request's
// fds dup'd onto stdin/stdout/stderr, waits for completion, and sends the
// exit code back to the client.
func execPMAndReply(logger zerolog.Logger, conn *net.UnixConn, req daemon.Request, fds [daemon.FDCount]int) {
	realPath, err := findRealBinary(req.PM)
	if err != nil {
		logger.Error().Err(err).Str("pm", req.PM).Msg("find real binary")
		_ = daemon.SendResponse(conn, daemon.Response{
			Status:  daemon.StatusError,
			Message: fmt.Sprintf("cannot find real %s: %v", req.PM, err),
		})
		return
	}

	exitCode, err := spawnAndWait(realPath, req, fds)
	if err != nil {
		logger.Error().Err(err).Str("path", realPath).Msg("spawn")
		_ = daemon.SendResponse(conn, daemon.Response{
			Status:  daemon.StatusError,
			Message: fmt.Sprintf("spawn %s: %v", realPath, err),
		})
		return
	}
	_ = daemon.SendResponse(conn, daemon.Response{
		Status:   daemon.StatusOK,
		ExitCode: exitCode,
	})
}

// spawnAndWait forks a child process running the real PM with the
// client's stdio fds dup'd onto 0/1/2, in the client's cwd, with the
// client's env (minus BOUNCER_* control vars that would confuse the PM
// or trigger surprise re-invocations of bouncer). Returns the child's
// exit code, or -1 + error on spawn failure.
func spawnAndWait(realPath string, req daemon.Request, fds [daemon.FDCount]int) (int, error) {
	// Wrap the raw int fds in *os.File so os.StartProcess can dup2 them
	// onto 0/1/2 in the child. We hand ownership to os.StartProcess —
	// the kernel duplicates the fds during fork, and our copies are
	// closed in the deferred closeFDsBest of the caller.
	stdin := os.NewFile(uintptr(fds[daemon.FDStdin]), "child-stdin")
	stdout := os.NewFile(uintptr(fds[daemon.FDStdout]), "child-stdout")
	stderr := os.NewFile(uintptr(fds[daemon.FDStderr]), "child-stderr")
	if stdin == nil || stdout == nil || stderr == nil {
		return -1, errors.New("os.NewFile returned nil — fd dup table exhausted?")
	}

	cwd := req.Cwd
	if cwd == "" {
		// Spawning with an empty Dir would inherit the daemon's cwd
		// (typically /). That's surprising for installs. If the client
		// didn't send one, refuse.
		return -1, errors.New("request missing cwd")
	}
	if _, err := os.Stat(cwd); err != nil {
		return -1, fmt.Errorf("cwd unreachable: %w", err)
	}

	proc, err := os.StartProcess(realPath, append([]string{req.PM}, req.Args...), &os.ProcAttr{
		Dir:   cwd,
		Env:   sanitizeEnv(req.Env),
		Files: []*os.File{stdin, stdout, stderr},
	})
	if err != nil {
		return -1, err
	}
	state, err := proc.Wait()
	if err != nil {
		return -1, err
	}
	if state.Exited() {
		return state.ExitCode(), nil
	}
	// Signaled or stopped — map to 128+signal in shell convention.
	if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), nil
	}
	return state.ExitCode(), nil
}

// sanitizeEnv removes BOUNCER_* control vars and PATH manipulations that
// would let the spawned PM accidentally re-invoke bouncer (the SHIP-1
// recursion the audit caught). The client's PATH is replaced with the
// daemon's PATH, which is what the daemon used to resolve `realPath`
// anyway — keeping them consistent avoids surprises in the PM's own
// subprocess lookups.
func sanitizeEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case strings.HasPrefix(name, "BOUNCER_"):
			// Drop all BOUNCER_* — the PM has no business seeing them,
			// and BOUNCER_BYPASS in particular has already been honored
			// by the daemon before this point.
			continue
		case name == "PATH":
			// Replace with the daemon's PATH so the PM's own subprocess
			// lookups go through the same toolchain the daemon does.
			continue
		default:
			out = append(out, kv)
		}
	}
	if daemonPath := os.Getenv("PATH"); daemonPath != "" {
		out = append(out, "PATH="+daemonPath)
	}
	return out
}

func sendRefused(conn *net.UnixConn, decision gate.Decision) {
	var reports []daemon.Report
	for _, v := range decision.Flagged() {
		for _, r := range v.Reports {
			reports = append(reports, daemon.Report{
				Name:      v.Ref.Name,
				Version:   v.Ref.Version,
				Ecosystem: string(v.Ref.Ecosystem),
				SourceID:  r.SourceID,
				Reason:    r.Reason,
			})
		}
	}
	_ = daemon.SendResponse(conn, daemon.Response{
		Status:  daemon.StatusRefused,
		Message: "install refused — malware intelligence flagged the following",
		Reports: reports,
	})
}

func sendAborted(conn *net.UnixConn, decision gate.Decision) {
	var msg strings.Builder
	msg.WriteString("install aborted fail-closed: the gate could not make a confident safety decision.")
	for _, e := range decision.Errors {
		fmt.Fprintf(&msg, "\n  - %v", e)
	}
	_ = daemon.SendResponse(conn, daemon.Response{
		Status:  daemon.StatusAborted,
		Message: msg.String(),
	})
}

// runRefreshLoop periodically refreshes the intel store. Failures during
// refresh log a warning but keep the previous index live (Store.Refresh
// handles this internally by only swapping on success). This is the
// daemon's only background work.
func runRefreshLoop(ctx context.Context, logger zerolog.Logger, store intel.Store) {
	ticker := time.NewTicker(daemonRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, syncTimeout)
			if err := store.Refresh(refreshCtx); err != nil {
				logger.Warn().Err(err).Msg("background refresh failed; keeping previous index")
			} else {
				logger.Debug().Int("reports", store.ReportCount()).Msg("background refresh complete")
			}
			cancel()
		}
	}
}

func envHas(env []string, name, value string) bool {
	prefix := name + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) && kv[len(prefix):] == value {
			return true
		}
	}
	return false
}

func closeFDsBest(fds []int) {
	for _, fd := range fds {
		if fd > 0 {
			_ = syscall.Close(fd)
		}
	}
}

