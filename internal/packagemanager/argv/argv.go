// Package argv contains ecosystem-agnostic command-line argument helpers
// shared across package-manager implementations.
package argv

import "strings"

// IsFlag reports whether a token is a CLI flag (starts with '-').
func IsFlag(tok string) bool { return strings.HasPrefix(tok, "-") }

// FlagsWithValues is the set of flag names (long or short form, e.g.
// "--prefix", "-p") that consume the next argv token as their value.
//
// Each PM subpackage owns its own table; this type is the shared shape so
// the generic helpers below can be reused across ecosystems.
type FlagsWithValues map[string]struct{}

// FirstNonFlag returns the first token in args that does not start with '-',
// the tail after it, and whether one was found.
//
// This is the conservative variant: it does not consult any flag table, so
// the value of a flag-with-value (e.g. "/tmp" in "--prefix /tmp install")
// will be misread as the verb. Callers that know the PM's flag set should
// prefer FirstNonFlagWithTable.
func FirstNonFlag(args []string) (string, []string, bool) {
	for i, a := range args {
		if IsFlag(a) {
			continue
		}
		return a, args[i+1:], true
	}
	return "", nil, false
}

// FirstNonFlagWithTable behaves like FirstNonFlag but also skips the value
// of every flag named in flagsTakingValues. Use this when callers know the
// PM's flag set; FirstNonFlag remains the conservative default.
//
// A token of the form "--flag=value" is a single argv entry and does NOT
// consume the next token, regardless of whether "--flag" is in the table.
//
// The POSIX "--" separator is honored: once seen, no further tokens are
// treated as flags (so "--" itself is consumed and the next non-flag token
// is returned as the verb).
func FirstNonFlagWithTable(args []string, flagsTakingValues FlagsWithValues) (string, []string, bool) {
	i := 0
	for i < len(args) {
		tok := args[i]
		if tok == "--" {
			// Everything after `--` is positional; first one is the verb.
			if i+1 < len(args) {
				return args[i+1], args[i+2:], true
			}
			return "", nil, false
		}
		if !IsFlag(tok) {
			return tok, args[i+1:], true
		}
		// It's a flag. Decide whether it eats the next token.
		if strings.Contains(tok, "=") {
			// "--flag=value" — single token, no skip.
			i++
			continue
		}
		if _, takesValue := flagsTakingValues[tok]; takesValue && i+1 < len(args) {
			i += 2 // skip flag and its value
			continue
		}
		i++
	}
	return "", nil, false
}

// CollectPositionals returns every non-flag token in args, honoring the POSIX
// `--` separator: tokens after `--` are positional even when they begin with
// '-'. Without this, package names like `-chalk` (a real typosquat shape)
// would be silently filtered out.
func CollectPositionals(args []string) []string {
	out := make([]string, 0, len(args))
	positional := false
	for _, tok := range args {
		if !positional && tok == "--" {
			positional = true
			continue
		}
		if !positional && IsFlag(tok) {
			continue
		}
		out = append(out, tok)
	}
	return out
}

// CollectFlagValues returns the value attached to every occurrence of any
// flag in targets, honoring both "--flag value" and "--flag=value" forms.
// flagsTakingValues is the broader set of value-taking flags the caller knows
// about (so the iterator advances past unrelated flag-value pairs correctly).
//
// Order follows argv. POSIX "--" terminates flag parsing as usual; tokens
// after "--" are positional and never produce values.
//
// Use this when a PM has a flag whose value is itself a path the gate needs
// to follow (pip's "-r requirements.txt") rather than a tunable to ignore.
func CollectFlagValues(args []string, targets FlagsWithValues, flagsTakingValues FlagsWithValues) []string {
	out := make([]string, 0, 4)
	i := 0
	for i < len(args) {
		tok := args[i]
		if tok == "--" {
			return out
		}
		if !IsFlag(tok) {
			i++
			continue
		}
		// "--flag=value" form.
		if eq := strings.IndexByte(tok, '='); eq > 0 {
			name := tok[:eq]
			if _, hit := targets[name]; hit {
				out = append(out, tok[eq+1:])
			}
			i++
			continue
		}
		// "--flag value" form: peek if this flag takes a value.
		if _, takesValue := flagsTakingValues[tok]; takesValue && i+1 < len(args) {
			if _, hit := targets[tok]; hit {
				out = append(out, args[i+1])
			}
			i += 2
			continue
		}
		i++
	}
	return out
}

// CollectPositionalsWithTable is the table-aware sibling of
// CollectPositionals: it additionally skips the value of every flag named in
// flagsTakingValues. POSIX "--" still flips into positional-only mode, and
// "--flag=value" remains a single token (no extra skip).
func CollectPositionalsWithTable(args []string, flagsTakingValues FlagsWithValues) []string {
	out := make([]string, 0, len(args))
	positional := false
	i := 0
	for i < len(args) {
		tok := args[i]
		if !positional && tok == "--" {
			positional = true
			i++
			continue
		}
		if positional {
			out = append(out, tok)
			i++
			continue
		}
		if !IsFlag(tok) {
			out = append(out, tok)
			i++
			continue
		}
		// Pre-separator flag handling.
		if strings.Contains(tok, "=") {
			i++
			continue
		}
		if _, takesValue := flagsTakingValues[tok]; takesValue && i+1 < len(args) {
			i += 2
			continue
		}
		i++
	}
	return out
}
