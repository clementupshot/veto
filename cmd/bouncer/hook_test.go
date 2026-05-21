package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestRunClaudeCodeHook_RiskyEmitsDenyWithCorrectedPrefix is the most
// important behavior to nail down: a bash command that reaches a covered
// package manager produces a deny envelope whose message contains the
// `bouncer <pm> <args>` correction so the agent can re-issue cleanly.
func TestRunClaudeCodeHook_RiskyEmitsDenyWithCorrectedPrefix(t *testing.T) {
	withBouncerOnPath(t)

	in := encodePayload(t, "Bash", "npm install lodash")
	var out bytes.Buffer
	rc := runClaudeCodeHook(zerolog.Nop(), in, &out)
	require.Equal(t, exitOK, rc)

	decision := decodeDecision(t, &out)
	require.Equal(t, "deny", decision.PermissionDecision)
	require.Contains(t, decision.PermissionDecisionReason, "bouncer npm install lodash")
	require.Contains(t, decision.PermissionDecisionReason, "blocked unguarded `npm`")
}

// TestRunClaudeCodeHook_AllowsBouncerPrefixed: agent already added the
// prefix; we must not deny a second time, or we'd loop forever.
func TestRunClaudeCodeHook_AllowsBouncerPrefixed(t *testing.T) {
	withBouncerOnPath(t)

	in := encodePayload(t, "Bash", "bouncer npm install lodash")
	var out bytes.Buffer
	rc := runClaudeCodeHook(zerolog.Nop(), in, &out)
	require.Equal(t, exitOK, rc)
	require.Empty(t, strings.TrimSpace(out.String()), "no envelope should be emitted for already-guarded commands")
}

// TestRunClaudeCodeHook_NonBashIgnored: the hook only cares about Bash
// tool calls. Other tool types pass through with no envelope.
func TestRunClaudeCodeHook_NonBashIgnored(t *testing.T) {
	in := encodePayload(t, "Edit", "npm install lodash") // command field present but tool is Edit
	var out bytes.Buffer
	rc := runClaudeCodeHook(zerolog.Nop(), in, &out)
	require.Equal(t, exitOK, rc)
	require.Empty(t, strings.TrimSpace(out.String()))
}

// TestRunClaudeCodeHook_MalformedInput: invalid JSON => let the tool
// proceed (we can't tell what it is; same behavior as the Python original).
func TestRunClaudeCodeHook_MalformedInput(t *testing.T) {
	in := strings.NewReader("not json at all")
	var out bytes.Buffer
	rc := runClaudeCodeHook(zerolog.Nop(), in, &out)
	require.Equal(t, exitOK, rc)
	require.Empty(t, strings.TrimSpace(out.String()))
}

// TestRunClaudeCodeHook_BouncerNotOnPath: when bouncer can't be found by
// the agent's re-invocation, telling them to add a prefix is useless. We
// must still deny but with a "do not retry" message.
func TestRunClaudeCodeHook_BouncerNotOnPath(t *testing.T) {
	// Empty PATH guarantees lookup fails.
	t.Setenv("PATH", "")

	in := encodePayload(t, "Bash", "npm install lodash")
	var out bytes.Buffer
	rc := runClaudeCodeHook(zerolog.Nop(), in, &out)
	require.Equal(t, exitOK, rc)

	decision := decodeDecision(t, &out)
	require.Equal(t, "deny", decision.PermissionDecision)
	require.Contains(t, decision.PermissionDecisionReason, "bouncer binary itself was not found on PATH")
	require.Contains(t, decision.PermissionDecisionReason, "Do NOT retry")
}

// withBouncerOnPath drops a fake `bouncer` executable into a temp dir and
// puts it on PATH for the test. Lets the reachable-check pass without
// requiring bouncer to be installed system-wide.
func withBouncerOnPath(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	bouncerPath := filepath.Join(dir, "bouncer")
	require.NoError(t, os.WriteFile(bouncerPath, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func encodePayload(t *testing.T, tool, cmd string) *bytes.Reader {
	t.Helper()
	buf, err := json.Marshal(map[string]any{
		"tool_name":  tool,
		"tool_input": map[string]any{"command": cmd},
	})
	require.NoError(t, err)
	return bytes.NewReader(buf)
}

type decision struct {
	PermissionDecision       string
	PermissionDecisionReason string
}

func decodeDecision(t *testing.T, buf *bytes.Buffer) decision {
	t.Helper()
	var env claudeHookOutput
	require.NoError(t, json.Unmarshal(buf.Bytes(), &env))
	require.Equal(t, "PreToolUse", env.HookSpecificOutput.HookEventName)
	return decision{
		PermissionDecision:       env.HookSpecificOutput.PermissionDecision,
		PermissionDecisionReason: env.HookSpecificOutput.PermissionDecisionReason,
	}
}
