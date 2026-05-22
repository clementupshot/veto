package claudecode

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAnalyze covers the cases the Python original was built to catch:
// bare PM verbs, exec-style PMs, wrapped invocations, bash -c "..." nesting,
// env-assignment prefixes, redirects, and explicit bypass.
func TestAnalyze(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want string // PM name expected, "" for "not risky"
	}{
		{"plain npm install", "npm install foo", "npm"},
		{"npm with version", "npm install lodash@4.17.21", "npm"},
		{"npm run is not risky", "npm run dev", ""},
		{"npm ci risky", "npm ci", "npm"},
		{"yarn add", "yarn add react", "yarn"},
		{"yarn dlx", "yarn dlx some-tool", "yarn"},
		{"yarn build is not risky", "yarn build", ""},
		{"pnpm add", "pnpm add chalk", "pnpm"},
		{"pip install", "pip install requests", "pip"},
		{"pip3 install", "pip3 install requests", "pip3"},
		{"pip download", "pip download numpy", "pip"},
		{"uv add", "uv add pandas", "uv"},
		{"poetry install", "poetry install", "poetry"},

		// `npm exec` is the npx-equivalent built into npm 7+. The hook
		// only checks the verb (real spec-resolution happens at the
		// veto-Go-parser layer), so any `npm exec` invocation must
		// route through veto — even `npm exec --help`. The Go parser
		// then sees the help flag and emits no installs.
		{"npm exec is risky", "npm exec evil-pkg", "npm"},
		{"npm exec with -- separator", "npm exec -- evil-pkg", "npm"},
		{"npx with any arg is risky", "npx create-react-app foo", "npx"},
		{"npx help is fine", "npx --help", ""},
		{"npx -h is fine", "npx -h", ""},
		{"bunx is risky", "bunx some-cli", "bunx"},
		{"uvx is risky", "uvx ruff check .", "uvx"},
		{"pipx run is risky", "pipx run black .", "pipx"},

		{"veto prefix already guarded", "veto npm install foo", ""},
		{"absolute path PM", "/opt/homebrew/bin/npm install foo", "npm"},

		{"timeout wrapper", "timeout 30 npm install foo", "npm"},
		{"timeout with flags", "timeout --signal=KILL -k 5 30 npm install foo", "npm"},
		{"env wrapper", "env FOO=bar npm install foo", "npm"},
		{"env with -i flag", "env -i PATH=/usr/bin npm install foo", "npm"},
		{"sudo wrapper", "sudo npm install -g foo", "npm"},
		{"sudo with user", "sudo -u root npm install -g foo", "npm"},
		{"xargs wrapper", "xargs -n1 npm install foo", "npm"},
		{"nice wrapper", "nice -n 10 npm install foo", "npm"},
		{"nohup wrapper", "nohup npm install foo", "npm"},
		{"time wrapper", "time npm install foo", "npm"},
		{"watch wrapper", "watch -n 5 npm install foo", "npm"},

		{"bash -c inline", `bash -c "npm install foo"`, "npm"},
		{"bash -c with wrapper inside", `bash -c "timeout 30 pip install foo"`, "pip"},
		{"sh -c inline", `sh -c "yarn add react"`, "yarn"},
		{"zsh -c inline", `zsh -c "uv add pandas"`, "uv"},
		{"bash -c with separator", `bash -c "cd /tmp && npm install foo"`, "npm"},

		{"chained &&", "cd /tmp && npm install foo", "npm"},
		{"chained ;", "cd /tmp; npm install foo", "npm"},
		{"chained |", "echo y | npm install foo", "npm"},
		{"chained ||", "false || npm install foo", "npm"},

		{"env var assignment", "FOO=bar npm install foo", "npm"},
		{"two env var assignments", "FOO=bar BAZ=qux pip install requests", "pip"},
		{"explicit bypass", "VETO_BYPASS=1 npm install foo", ""},
		// Only the literal value "1" disables the gate. Any other value
		// (including the foot-gun "0", which a user might assume means
		// "off") MUST still be flagged. The C interposer and runGate
		// honor the same rule — see veto_interpose.c::is_risky and
		// cmd/veto/main.go::vetoBypassEnabled.
		{"bypass with value 0 is not a bypass", "VETO_BYPASS=0 npm install foo", "npm"},
		{"bypass with empty value is not a bypass", "VETO_BYPASS= npm install foo", "npm"},
		{"bypass with arbitrary value is not a bypass", "VETO_BYPASS=true npm install foo", "npm"},

		{"redirect operator", "npm install foo > /tmp/log 2>&1", "npm"},
		{"redirect operator with append", "pip install foo >> /tmp/log", "pip"},

		{"empty string", "", ""},
		{"just whitespace", "   ", ""},
		{"non-PM command", "ls -la /tmp", ""},
		{"not an install verb", "npm test", ""},
		{"git is not a PM", "git clone https://example.com/foo", ""},
		{"unparseable quotes", `npm install "unterminated`, ""},

		// `python -m <pm> …` is the canonical install form inside
		// virtualenvs, Dockerfiles, and most CI scripts. It MUST gate.
		// Other `python -m` modules (venv, http.server, unittest, …)
		// and bare python invocations MUST pass through.
		{"python -m pip install", "python -m pip install foo", "pip"},
		{"python3 -m pip install", "python3 -m pip install foo", "pip"},
		{"python -m pip3 install", "python -m pip3 install foo", "pip3"},
		{"python -m uv add", "python -m uv add pandas", "uv"},
		{"python -m pipx install", "python -m pipx install black", "pipx"},
		{"python -m poetry install", "python -m poetry install", "poetry"},
		{"python -m pdm add", "python -m pdm add foo", "pdm"},
		{"python -m pip via absolute path", "/usr/bin/python3 -m pip install foo", "pip"},
		{"python -m pip with verb-less argv", "python -m pip", ""},
		{"python -m pip with non-dangerous verb", "python -m pip list", ""},
		{"python -m http.server is benign", "python -m http.server 8000", ""},
		{"python -m venv is benign", "python -m venv .venv", ""},
		{"python -m unittest is benign", "python -m unittest discover", ""},
		{"plain python script is benign", "python script.py", ""},
		{"python -c snippet is benign", `python -c "print('hi')"`, ""},
		{"python -V is benign", "python -V", ""},
		{"python REPL is benign", "python", ""},
		{"python -m pip inside bash -c", `bash -c "python -m pip install foo"`, "pip"},
		{"python -m pip with wrapper", "timeout 30 python -m pip install foo", "pip"},
		{"python -m pip with env assignment", "FOO=bar python -m pip install foo", "pip"},
		{"python -m pip chained", "cd /tmp && python -m pip install foo", "pip"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			finding, risky := Analyze(tc.cmd)
			if tc.want == "" {
				require.False(t, risky, "expected not-risky for %q; got pm=%s tokens=%v", tc.cmd, finding.PM, finding.Tokens)
				return
			}
			require.True(t, risky, "expected risky for %q", tc.cmd)
			require.Equal(t, tc.want, finding.PM)
		})
	}
}

// TestStripWrappers exercises wrapper-stripping behavior end-to-end through
// Analyze for the more complex flag combinations. Wrappers that swallow
// the wrong number of arguments would either let a risky command through
// (false-negative) or block an innocent one (false-positive).
func TestStripWrappersComplex(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want string
	}{
		{"timeout with kill-after and signal", "timeout --kill-after=5s --signal=TERM 30 npm install foo", "npm"},
		{"sudo with multiple short flags", "sudo -E -H npm install -g foo", "npm"},
		{"sudo -u user with --", "sudo -u me -- pnpm add chalk", "pnpm"},
		{"nested wrappers", "timeout 30 nice -n 10 sudo npm install foo", "npm"},
		{"env with multiple assignments", "env A=1 B=2 C=3 pip install requests", "pip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			finding, risky := Analyze(tc.cmd)
			require.True(t, risky, "expected risky for %q", tc.cmd)
			require.Equal(t, tc.want, finding.PM)
		})
	}
}

// TestTokensSurfacedForRefusalMessage confirms the Tokens field carries
// the leaf-command (post-wrapper-stripping) so the refusal message tells
// the agent precisely what to re-issue with a `veto` prefix.
func TestTokensSurfacedForRefusalMessage(t *testing.T) {
	finding, ok := Analyze("timeout 30 npm install --save-dev lodash")
	require.True(t, ok)
	require.Equal(t, []string{"npm", "install", "--save-dev", "lodash"}, finding.Tokens)
}

// TestPythonDashMTokensPreserveOriginalInvocation confirms the
// corrected command the agent gets back is `veto python -m pip install
// foo`, not `veto pip install foo`. The interpreter prefix is
// load-bearing: `python -m pip` resolves pip against the running
// interpreter (venv scope), so dropping it would silently break the
// install.
func TestPythonDashMTokensPreserveOriginalInvocation(t *testing.T) {
	finding, ok := Analyze("python -m pip install foo")
	require.True(t, ok)
	require.Equal(t, "pip", finding.PM)
	require.Equal(t, []string{"python", "-m", "pip", "install", "foo"}, finding.Tokens)
}
