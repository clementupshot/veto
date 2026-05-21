// Package argv contains ecosystem-agnostic command-line argument helpers
// shared across package-manager implementations.
package argv

import "strings"

// IsFlag reports whether a token is a CLI flag (starts with '-').
func IsFlag(tok string) bool { return strings.HasPrefix(tok, "-") }

// FirstNonFlag returns the first token in args that does not start with '-',
// the tail after it, and whether one was found.
func FirstNonFlag(args []string) (string, []string, bool) {
	for i, a := range args {
		if IsFlag(a) {
			continue
		}
		return a, args[i+1:], true
	}
	return "", nil, false
}
