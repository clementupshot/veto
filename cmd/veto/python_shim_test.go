package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPythonDashMTarget covers the classifier that decides whether a
// python invocation should be gated. The rule is narrow on purpose: only
// `-m {pip,pip3,uv,pipx,poetry,pdm}` as the very first python-arg
// counts. Every other invocation (scripts, REPL, -c, -V, -m
// http.server, etc.) MUST be reported as not gated so main()'s
// fast-path dispatch sends it straight to the real interpreter.
func TestPythonDashMTarget(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantPM  string
		wantHit bool
	}{
		{"pip install", []string{"-m", "pip", "install", "foo"}, "pip", true},
		{"pip3 install", []string{"-m", "pip3", "install", "foo"}, "pip3", true},
		{"uv add", []string{"-m", "uv", "add", "pandas"}, "uv", true},
		{"pipx install", []string{"-m", "pipx", "install", "black"}, "pipx", true},
		{"poetry install", []string{"-m", "poetry", "install"}, "poetry", true},
		{"pdm add", []string{"-m", "pdm", "add", "foo"}, "pdm", true},

		{"bare pip module without verb still flagged", []string{"-m", "pip"}, "pip", true},

		{"http.server is benign", []string{"-m", "http.server", "8000"}, "", false},
		{"venv is benign", []string{"-m", "venv", ".venv"}, "", false},
		{"unittest is benign", []string{"-m", "unittest", "discover"}, "", false},
		{"script is benign", []string{"script.py"}, "", false},
		{"-V is benign", []string{"-V"}, "", false},
		{"-c snippet is benign", []string{"-c", "print('hi')"}, "", false},
		{"REPL is benign", nil, "", false},
		{"pre-m flag is intentionally not unwrapped", []string{"-I", "-m", "pip", "install", "foo"}, "", false},
		{"-m without arg is benign", []string{"-m"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotPM, gotHit := pythonDashMTarget(tc.args)
			require.Equal(t, tc.wantHit, gotHit, "hit mismatch for %v", tc.args)
			require.Equal(t, tc.wantPM, gotPM, "pm mismatch for %v", tc.args)
		})
	}
}

// TestPythonShimIsRecognized confirms the install/uninstall side and the
// dispatch side agree that "python"/"python3" are managed shim names.
// If these drift apart, install-shims creates a symlink the runtime
// dispatcher wouldn't recognize.
func TestPythonShimIsRecognized(t *testing.T) {
	require.True(t, isShimName("python"))
	require.True(t, isShimName("python3"))

	have := map[string]bool{}
	for _, n := range shimmedManagers {
		have[n] = true
	}
	require.True(t, have["python"], "shimmedManagers must include python")
	require.True(t, have["python3"], "shimmedManagers must include python3")
}
