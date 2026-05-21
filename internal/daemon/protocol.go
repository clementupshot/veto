// Package daemon defines the wire protocol and socket plumbing between the
// veto CLI (running inside a sandbox-exec'd agent) and the veto daemon
// (running outside the sandbox via launchd).
//
// Threat model: the agent process is sandbox-confined and cannot exec any
// real package manager directly — the kernel returns EPERM. The only
// PM-adjacent thing the agent can reach is `veto`. When `veto` needs
// to actually run the real PM after a clean gate decision, it asks the
// daemon to do the exec on its behalf, passing its own stdin/stdout/stderr
// fds over the Unix socket via SCM_RIGHTS so the user sees the PM's output
// directly with no proxying overhead.
//
// One request, one response, then hang up. No streaming, no multiplexing.
// Installs aren't concurrent in any agent loop worth supporting.
package daemon

// Request is what the client sends to the daemon. The fds for stdin,
// stdout, stderr are passed out-of-band via SCM_RIGHTS on the same
// sendmsg; they are not part of this struct.
type Request struct {
	// PM is the package-manager binary name (e.g. "npm", "pip"). The daemon
	// resolves this to an absolute path via its own PATH, not the client's,
	// because the client is sandboxed and can't reach the real binaries.
	PM string `json:"pm"`

	// Args are the arguments to pass to the PM (NOT including argv[0]).
	Args []string `json:"args"`

	// Cwd is the working directory the PM should run in. The daemon
	// chdirs (or uses posix_spawn file_actions) into this before exec.
	// Required: an install in the wrong directory is a different install.
	Cwd string `json:"cwd"`

	// Env is the environment to give the PM. Sent verbatim; the daemon
	// does not filter, except to strip VETO_* control vars that would
	// confuse the PM or trigger recursion if veto is re-invoked.
	Env []string `json:"env"`
}

// Status enumerates the daemon's possible verdicts on a Request.
type Status string

const (
	// StatusOK means the gate allowed the install and the PM ran to
	// completion. ExitCode is the PM's exit code.
	StatusOK Status = "ok"

	// StatusRefused means the gate refused: at least one intel source
	// flagged a named package. Reports lists the matches. The client
	// prints them and exits non-zero.
	StatusRefused Status = "refused"

	// StatusAborted means the gate could not make a confident decision
	// (manifest parse failure, intel store unreachable, etc.). Per
	// fail-closed posture the PM did NOT run. Distinguished from Refused
	// so users know it's a veto-side failure, not a malware block.
	StatusAborted Status = "aborted"

	// StatusError means the daemon itself failed: socket error, exec
	// failure, internal panic. Message carries the detail.
	StatusError Status = "error"
)

// Report mirrors the per-package match info the gate produces. Duplicated
// here (rather than re-using intel.MalwareReport directly) so the wire
// protocol can evolve without ABI-coupling to the intel package.
type Report struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Ecosystem string `json:"ecosystem"`
	SourceID  string `json:"source_id"`
	Reason    string `json:"reason,omitempty"`
}

// Response is what the daemon sends back. Single message, then close.
type Response struct {
	Status Status `json:"status"`

	// ExitCode is populated only when Status == StatusOK; it is the PM's
	// own exit code, which the client mirrors via os.Exit.
	ExitCode int `json:"exit_code"`

	// Message is human-readable detail for Refused/Aborted/Error. The
	// client prints it to stderr verbatim.
	Message string `json:"message,omitempty"`

	// Reports is populated only when Status == StatusRefused. The client
	// renders these in its refusal banner.
	Reports []Report `json:"reports,omitempty"`
}
