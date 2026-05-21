package daemon

import (
	"os"
	"path/filepath"

	"github.com/brynbellomy/go-utils/errors"
)

// SocketEnvVar lets a user (or test) override the default socket location.
// Useful for running multiple daemons during development, or for placing
// the socket in a sandbox-readable path when the default location isn't
// reachable from inside the agent sandbox.
const SocketEnvVar = "BOUNCER_DAEMON_SOCKET"

// SocketPath returns the absolute path of the daemon's Unix socket.
//
// Resolution order:
//  1. $BOUNCER_DAEMON_SOCKET if set (testing / custom layouts).
//  2. $XDG_RUNTIME_DIR/bouncer/bouncer.sock if set (Linux convention).
//  3. ~/.local/state/bouncer/bouncer.sock (macOS — XDG_STATE_HOME).
//
// macOS imposes a 104-char limit on Unix socket paths in struct sockaddr_un;
// $HOME on macOS is typically short enough that ~/.local/state/... fits with
// generous headroom. We do not attempt to fall back to /tmp — putting the
// socket in a world-writable directory invites local-attacker shenanigans
// (someone races us to bind first, our daemon fails, our client connects to
// their socket).
func SocketPath() (string, error) {
	if p := os.Getenv(SocketEnvVar); p != "" {
		return p, nil
	}
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		return filepath.Join(x, "bouncer", "bouncer.sock"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.With(err, "resolve home dir")
	}
	return filepath.Join(home, ".local", "state", "bouncer", "bouncer.sock"), nil
}

// EnsureSocketDir creates the parent directory of the socket with
// 0700 permissions. Called by the daemon at startup before binding;
// idempotent.
func EnsureSocketDir(socketPath string) error {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.With(err, "mkdir socket dir").Set("dir", dir)
	}
	// Tighten perms even if the dir already existed with looser perms —
	// the socket is the only thing controlling daemon access, so its
	// parent dir's permissions are a load-bearing piece of the security
	// boundary.
	if err := os.Chmod(dir, 0o700); err != nil {
		return errors.With(err, "chmod socket dir").Set("dir", dir)
	}
	return nil
}
