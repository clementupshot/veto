package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/gate"
	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
	"github.com/brynbellomy/veto/internal/packagemanager/jslock"
)

// TestSanitizedEnv covers the env-scrub helper that execReal applies
// before syscall.Exec. The contract:
//
//   - VETO_PATH must be removed (otherwise the interposer's is_risky()
//     fires again in the child and re-rewrites the call to veto,
//     producing the B6 infinite loop).
//   - VETO_PYTHON_M_ORIGINAL must be removed (belt-and-suspenders for
//     the B2 python-m re-entry concern; execPMOrPythonM already
//     Unsetenv's it, but a future refactor could regress that).
//   - DYLD_INSERT_LIBRARIES and LD_PRELOAD must NOT be touched — we
//     deliberately keep Layer 3 loaded in the child so sibling
//     processes spawned by other parents in the same shell still get
//     the interposer (we only defang the recursion via VETO_PATH).
//   - Unrelated vars (PATH, HOME, FOO=bar, even an empty-valued one)
//     pass through unchanged.
//
// If a future contributor decides to also strip the OS preload vars,
// they should change the "preserved" cases here too — that's an
// intentional tripwire.
func TestSanitizedEnv(t *testing.T) {
	in := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/Users/test",
		"VETO_PATH=/opt/veto/bin/veto",
		"DYLD_INSERT_LIBRARIES=/opt/veto/lib/libveto_interpose.dylib",
		"LD_PRELOAD=/opt/veto/lib/libveto_interpose.so",
		"VETO_PYTHON_M_ORIGINAL=python3",
		"VETO_LOG=debug",
		"VETO_CACHE_DIR=/tmp/veto",
		"FOO=bar",
		"EMPTY=",
	}

	out := sanitizedEnv(in)

	got := map[string]bool{}
	for _, kv := range out {
		got[kv] = true
	}

	// Stripped:
	require.False(t, got["VETO_PATH=/opt/veto/bin/veto"],
		"VETO_PATH must be stripped to break the interposer-recursion loop")
	require.False(t, got["VETO_PYTHON_M_ORIGINAL=python3"],
		"VETO_PYTHON_M_ORIGINAL must be stripped to prevent B2 double-rewrite")

	// Preserved (deliberate — keep Layer 3 loaded in siblings):
	require.True(t, got["DYLD_INSERT_LIBRARIES=/opt/veto/lib/libveto_interpose.dylib"],
		"DYLD_INSERT_LIBRARIES must be preserved; we rely on it for sibling-process Layer 3 coverage")
	require.True(t, got["LD_PRELOAD=/opt/veto/lib/libveto_interpose.so"],
		"LD_PRELOAD must be preserved; same rationale as DYLD_INSERT_LIBRARIES")

	// Unrelated vars passed through verbatim:
	require.True(t, got["PATH=/usr/bin:/bin"])
	require.True(t, got["HOME=/Users/test"])
	require.True(t, got["VETO_LOG=debug"], "non-control VETO_* vars must pass through")
	require.True(t, got["VETO_CACHE_DIR=/tmp/veto"], "non-control VETO_* vars must pass through")
	require.True(t, got["FOO=bar"])
	require.True(t, got["EMPTY="])
}

// TestSanitizedEnvOnlyExactPrefix guards against an over-eager
// prefix match. A var like VETO_PATHWAY=foo or
// VETO_PYTHON_M_ORIGINALITY=bar (contrived, but plausible if a future
// env var picks a similar name) must NOT be stripped — the helper
// uses "VETO_PATH=" (with the equals) so only the exact name matches.
func TestSanitizedEnvOnlyExactPrefix(t *testing.T) {
	in := []string{
		"VETO_PATHWAY=should-pass",
		"VETO_PATH_EXTRA=should-pass",
		"VETO_PYTHON_M_ORIGINALITY=should-pass",
	}
	out := sanitizedEnv(in)
	require.ElementsMatch(t, in, out,
		"sanitizedEnv must only match VETO_PATH= and VETO_PYTHON_M_ORIGINAL= exactly, not as substrings")
}

// TestSanitizedEnvEmpty is a tiny smoke test that the helper doesn't
// blow up on an empty input env (some test harnesses produce one).
func TestSanitizedEnvEmpty(t *testing.T) {
	require.Empty(t, sanitizedEnv(nil))
	require.Empty(t, sanitizedEnv([]string{}))
}

// TestVetoBypassEnabled pins the contract shared by all three veto
// layers: the literal value "1" — and ONLY "1" — disables the gate.
// Any other value (0, true, false, off, empty) leaves the gate in
// force. The Claude Code hook (Analyze in
// internal/hook/claudecode/claudecode.go) and the C interposer
// (is_risky in internal/interposer/veto_interpose.c) honor the same
// rule; if a future change relaxes this helper, the other layers will
// drift from it silently. Keep the three checks in sync.
func TestVetoBypassEnabled(t *testing.T) {
	cases := []struct {
		name  string
		value string
		set   bool
		want  bool
	}{
		{"unset", "", false, false},
		{"empty", "", true, false},
		{"literal 1", "1", true, true},
		{"literal 0", "0", true, false},
		{"literal true", "true", true, false},
		{"literal false", "false", true, false},
		{"leading space (not normalized)", " 1", true, false},
		{"trailing space (not normalized)", "1 ", true, false},
		{"yes", "yes", true, false},
		{"on", "on", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("VETO_BYPASS", tc.value)
			} else {
				// t.Setenv to "" still SETS the var; we want it unset.
				// Save+restore around a manual Unsetenv.
				orig, had := os.LookupEnv("VETO_BYPASS")
				require.NoError(t, os.Unsetenv("VETO_BYPASS"))
				t.Cleanup(func() {
					if had {
						_ = os.Setenv("VETO_BYPASS", orig)
					} else {
						_ = os.Unsetenv("VETO_BYPASS")
					}
				})
			}
			require.Equal(t, tc.want, vetoBypassEnabled())
		})
	}
}

func TestSeedResolverWorkdir(t *testing.T) {
	projectDir := t.TempDir()
	workdir := t.TempDir()
	oldwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldwd)) })

	require.NoError(t, os.WriteFile("package.json", []byte(`{"name":"app"}`), 0o644))
	require.NoError(t, os.Mkdir("nested", 0o755))
	require.NoError(t, os.WriteFile(filepath.Join("nested", "package-lock.json"), []byte(`{"lockfileVersion":3}`), 0o600))
	require.NoError(t, os.Mkdir("ignored-dir", 0o755))
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Symlink("package.json", "link.json"))
	}

	err = seedResolverWorkdir(workdir, []string{
		"package.json",
		"missing.json",
		"nested/package-lock.json",
		"ignored-dir",
		"/abs/path",
		"../escape.json",
		"link.json",
		"package.json",
	})
	require.NoError(t, err)

	gotPkg, err := os.ReadFile(filepath.Join(workdir, "package.json"))
	require.NoError(t, err)
	require.JSONEq(t, `{"name":"app"}`, string(gotPkg))

	gotLock, err := os.ReadFile(filepath.Join(workdir, "nested", "package-lock.json"))
	require.NoError(t, err)
	require.JSONEq(t, `{"lockfileVersion":3}`, string(gotLock))
	info, err := os.Stat(filepath.Join(workdir, "nested", "package-lock.json"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	_, err = os.Stat(filepath.Join(workdir, "ignored-dir"))
	require.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(workdir, "link.json"))
	require.True(t, os.IsNotExist(err))
}

func TestRunResolverPreScanExtractsGeneratedTransitives(t *testing.T) {
	projectDir := t.TempDir()
	oldwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldwd)) })
	require.NoError(t, os.WriteFile("package.json", []byte(`{"name":"app","version":"1.0.0"}`), 0o644))

	fakeBin := t.TempDir()
	npmPath := filepath.Join(fakeBin, "npm")
	fakeNPM := `#!/bin/sh
set -eu
	case " $* " in
  *" --package-lock=true "*) ;;
  *) echo "missing --package-lock=true" >&2; exit 40 ;;
esac
case " $* " in
  *" --package-lock-only "*) ;;
  *) echo "missing --package-lock-only" >&2; exit 41 ;;
esac
case " $* " in
  *" --ignore-scripts "*) ;;
  *) echo "missing --ignore-scripts" >&2; exit 42 ;;
esac
if [ -n "${VETO_PATH:-}" ]; then
  echo "VETO_PATH leaked into resolver" >&2
  exit 43
fi
cat > package-lock.json <<'JSON'
{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/clean-direct": {"version": "1.0.0"},
    "node_modules/clean-direct/node_modules/evil-transitive": {"version": "9.9.9"}
  }
}
JSON
`
	require.NoError(t, os.WriteFile(npmPath, []byte(fakeNPM), 0o755))
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("VETO_PATH", "/tmp/veto")

	got, err := runResolverPreScan(zerolog.Nop(), config{CacheDir: t.TempDir()}, "npm", packagemanager.ResolverPreScanPlan{
		Args: []string{"install", "clean-direct", "--package-lock=true", "--package-lock-only", "--ignore-scripts"},
		ManifestRefs: []packagemanager.ManifestRef{
			{Path: "package-lock.json", Kind: packagemanager.ManifestKindPackageLockJSON},
		},
		SeedFiles: []string{"package.json"},
		DirectInstalls: []packagemanager.Install{
			{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "clean-direct"}, RawSpec: "clean-direct"},
		},
	}, jslock.New())
	require.NoError(t, err)
	require.Contains(t, got, packagemanager.Install{
		Ref: intel.PackageRef{
			Ecosystem: intel.EcosystemNPM,
			Name:      "evil-transitive",
			Version:   "9.9.9",
		},
		RawSpec: "evil-transitive@9.9.9",
	})
}

func TestRunResolverPreScanRequiresDirectInstallInOutput(t *testing.T) {
	projectDir := t.TempDir()
	oldwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	t.Cleanup(func() { require.NoError(t, os.Chdir(oldwd)) })

	fakeBin := t.TempDir()
	npmPath := filepath.Join(fakeBin, "npm")
	fakeNPM := `#!/bin/sh
set -eu
cat > package-lock.json <<'JSON'
{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/stale-existing": {"version": "1.0.0"}
  }
}
JSON
`
	require.NoError(t, os.WriteFile(npmPath, []byte(fakeNPM), 0o755))
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err = runResolverPreScan(zerolog.Nop(), config{CacheDir: t.TempDir()}, "npm", packagemanager.ResolverPreScanPlan{
		Args: []string{"install", "clean-direct", "--package-lock-only", "--ignore-scripts"},
		ManifestRefs: []packagemanager.ManifestRef{
			{Path: "package-lock.json", Kind: packagemanager.ManifestKindPackageLockJSON},
		},
		DirectInstalls: []packagemanager.Install{
			{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "clean-direct"}, RawSpec: "clean-direct"},
		},
	}, jslock.New())
	require.Error(t, err)
	require.Contains(t, err.Error(), "resolver pre-scan output did not include every requested package")
}

func TestRunResolverPreScanRequiresOutputLockfile(t *testing.T) {
	fakeBin := t.TempDir()
	npmPath := filepath.Join(fakeBin, "npm")
	require.NoError(t, os.WriteFile(npmPath, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err := runResolverPreScan(zerolog.Nop(), config{CacheDir: t.TempDir()}, "npm", packagemanager.ResolverPreScanPlan{
		Args: []string{"install", "clean-direct", "--package-lock-only", "--ignore-scripts"},
		ManifestRefs: []packagemanager.ManifestRef{
			{Path: "package-lock.json", Kind: packagemanager.ManifestKindPackageLockJSON},
		},
	}, jslock.New())
	require.Error(t, err)
	require.Contains(t, err.Error(), "resolver pre-scan did not produce an expected lockfile")
}

func TestResolverPreScanDecisionRefusesGeneratedTransitive(t *testing.T) {
	g := gateWithFakeStore(t, []intel.MalwareReport{
		{
			PackageRef: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil-transitive", Version: "9.9.9"},
			SourceID:   "test-feed",
			Reason:     "known malicious transitive",
		},
	})

	decision := g.Evaluate([]packagemanager.Install{
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "clean-direct", Version: "1.0.0"}, RawSpec: "clean-direct@1.0.0"},
		{Ref: intel.PackageRef{Ecosystem: intel.EcosystemNPM, Name: "evil-transitive", Version: "9.9.9"}, RawSpec: "evil-transitive@9.9.9"},
	})

	require.Equal(t, gate.OutcomeRefuse, decision.Outcome)
	require.Len(t, decision.Flagged(), 1)
	require.Equal(t, "evil-transitive", decision.Flagged()[0].Ref.Name)
}

func gateWithFakeStore(t *testing.T, reports []intel.MalwareReport) *gate.Gate {
	t.Helper()
	store := intel.NewStore(zerolog.Nop(), fakeSource{reports: reports})
	require.NoError(t, store.Refresh(context.Background()))
	return gate.New(store, gate.DefaultPolicy(), zerolog.Nop())
}

type fakeSource struct {
	reports []intel.MalwareReport
}

func (s fakeSource) ID() string { return "test-feed" }

func (s fakeSource) Fetch(_ context.Context, eco intel.Ecosystem) ([]intel.MalwareReport, error) {
	out := make([]intel.MalwareReport, 0, len(s.reports))
	for _, r := range s.reports {
		if r.Ecosystem == eco {
			out = append(out, r)
		}
	}
	return out, nil
}
