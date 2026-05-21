// Package vetopath provides the strict physical-path identity check
// used to decide whether a symlink "is veto." Centralized here so
// every layer (Layer 2 shims, Layer 4 wrappers, doctor diagnostics,
// claude-code hook recognition) makes the SAME decision against the
// SAME helper — earlier versions of the codebase had near-duplicates
// of this logic in install_wrappers.go and a substring check in
// doctor.go / install_claude_hook.go that an attacker-planted symlink
// `/opt/homebrew/bin/npm -> /tmp/veto-malware` could quietly pass.
package vetopath

import "path/filepath"

// PointsAt reports whether linkPath resolves to the same physical
// file as vetoPath. Both sides are fully evaluated via
// filepath.EvalSymlinks so a symlink chain that ends at the canonical
// veto binary is recognised regardless of how many hops it takes.
//
// Why a strict identity check matters: prior implementations used
// strings.Contains(target, "veto"), which would accept ANY symlink
// whose target string contained the substring "veto" — including an
// attacker-planted /opt/homebrew/bin/npm → /tmp/veto-malware that
// merely uses our name. Once accepted as "already ours," install /
// uninstall steps skip and the attacker's shadow stays in place.
// Resolving and comparing physical paths closes that hole.
//
// Fail-closed: returns false (not error) on any I/O failure — a
// symlink we cannot resolve (dangling target, permission denied) is,
// by definition, not provably ours. The two empty-string cases
// (linkPath or vetoPath blank) are likewise treated as "not ours" so
// a caller that failed to resolve the running veto binary still gets
// a safe default.
func PointsAt(linkPath, vetoPath string) bool {
	if linkPath == "" || vetoPath == "" {
		return false
	}
	resolved, err := filepath.EvalSymlinks(linkPath)
	if err != nil {
		return false
	}
	canonicalVeto, err := filepath.EvalSymlinks(vetoPath)
	if err != nil {
		return false
	}
	return resolved == canonicalVeto
}
