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
		{"-m without arg is benign", []string{"-m"}, "", false},

		// Phase 1.3 — pre-`-m` flag bundles and `-m<pm>` (no space).
		// CPython accepts `python -mpip install foo` as a single-token
		// equivalent of `python -m pip install foo`; the old parser
		// missed it and let pip slip past Layer 2. Same with `-I -m pip`
		// (isolated mode) which agents use commonly. See the L2 reviewer's
		// "trivially bypassable" finding for the rationale.
		{"no_space_mpip", []string{"-mpip", "install", "foo"}, "pip", true},
		{"no_space_muv", []string{"-muv", "pip", "install", "x"}, "uv", true},
		{"no_space_mpipx", []string{"-mpipx", "install", "black"}, "pipx", true},
		{"flag_I_then_m", []string{"-I", "-m", "pip", "install", "foo"}, "pip", true},
		{"flag_E_then_m", []string{"-E", "-m", "pip", "install", "foo"}, "pip", true},
		{"flag_S_then_m", []string{"-S", "-m", "pip", "install", "foo"}, "pip", true},
		{"flag_B_then_m", []string{"-B", "-m", "pip", "install", "foo"}, "pip", true},
		{"flag_bundle_IES_then_m", []string{"-IES", "-m", "pip", "install", "foo"}, "pip", true},
		{"flag_I_then_no_space_m", []string{"-I", "-mpip", "install", "foo"}, "pip", true},
		// Non-PM `-m` modules MUST still pass through, even with leading flags.
		{"flag_I_then_m_venv_benign", []string{"-I", "-m", "venv", ".venv"}, "", false},
		{"no_space_m_http_server_benign", []string{"-mhttp.server", "8000"}, "", false},
		// Long options (`--check-hash-based-pycs`) and value-taking short
		// options (`-c CMD`, `-W ARG`, `-X ARG`) must NOT be conflated
		// with the no-argument bundle — bail conservatively so they can't
		// conceal a `-m pip` further in.
		{"long_option_then_m_bails", []string{"--check-hash-based-pycs", "default", "-m", "pip"}, "", false},
		{"dash_c_then_m_bails", []string{"-c", "import sys", "-m", "pip"}, "", false},
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
