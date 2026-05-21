package pyreq_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/pyreq"
)

func TestExpandRequirementsFile(t *testing.T) {
	dir := t.TempDir()

	mainPath := filepath.Join(dir, "req.txt")
	extraPath := filepath.Join(dir, "req-extra.txt")

	mainContents := `# top-level requirements
requests==2.31.0
# a comment line
flask >= 2.0,<3.0    # inline comment
django[bcrypt,argon2]==4.2.0

# include the extras file
-r req-extra.txt

# hash flag should be ignored (it's a flag, not a spec)
--hash=sha256:deadbeef

pywin32; sys_platform == 'win32'
`

	// Note: pyspec doesn't validate PyPI name syntax, so a "garbage" non-flag,
	// non-comment line still produces an Install with the garbage name.
	// That's intentional: a name-keyed lookup against the intel store will
	// simply miss, the cost is one extra map probe, and we'd rather over-check
	// than miss a typosquat that looks malformed at a glance.
	extraContents := `# extra deps
numpy==1.26.0
junk-but-still-parses

# nested constraint
-c req-constraints.txt
`

	constraintsPath := filepath.Join(dir, "req-constraints.txt")
	constraintsContents := `# constraints
urllib3<2.0
`

	require.NoError(t, os.WriteFile(mainPath, []byte(mainContents), 0o644))
	require.NoError(t, os.WriteFile(extraPath, []byte(extraContents), 0o644))
	require.NoError(t, os.WriteFile(constraintsPath, []byte(constraintsContents), 0o644))

	exp := pyreq.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: mainPath,
		Kind: packagemanager.ManifestKindRequirements,
	})
	require.NoError(t, err)

	// Expected names in order of discovery; malformed line is dropped silently,
	// "--hash=..." flag line is dropped, comment-only lines are dropped, and
	// the nested -r / -c references are followed relative to the file that
	// contains them.
	wantNames := []string{
		"requests",
		"flask",
		"django",
		// from req-extra.txt:
		"numpy",
		"junk-but-still-parses",
		// nested -c req-constraints.txt:
		"urllib3",
		// back in main file after the include:
		"pywin32",
	}
	require.Len(t, installs, len(wantNames))
	for i, want := range wantNames {
		require.Equal(t, want, installs[i].Ref.Name, "install at index %d", i)
		require.Equal(t, intel.EcosystemPyPI, installs[i].Ref.Ecosystem)
	}

	// Specific assertions on a few we care about.
	require.Equal(t, "2.31.0", installs[0].Ref.Version, "exact == version preserved")
	require.Equal(t, "", installs[1].Ref.Version, "range collapses to empty version")
	require.Equal(t, "4.2.0", installs[2].Ref.Version, "extras stripped, version kept")
}

func TestExpandUnknownKindReturnsNil(t *testing.T) {
	exp := pyreq.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: "doesnt-matter",
		Kind: packagemanager.ManifestKind("unknown"),
	})
	require.NoError(t, err)
	require.Empty(t, installs)
}

func TestExpandMissingFileReturnsError(t *testing.T) {
	exp := pyreq.New()
	_, err := exp.Expand(packagemanager.ManifestRef{
		Path: filepath.Join(t.TempDir(), "no-such-file.txt"),
		Kind: packagemanager.ManifestKindRequirements,
	})
	require.Error(t, err)
}

func TestExpandConstraintKindAlsoReadsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.txt")
	require.NoError(t, os.WriteFile(path, []byte("urllib3==1.26.18\n"), 0o644))

	exp := pyreq.New()
	installs, err := exp.Expand(packagemanager.ManifestRef{
		Path: path,
		Kind: packagemanager.ManifestKindConstraint,
	})
	require.NoError(t, err)
	require.Len(t, installs, 1)
	require.Equal(t, "urllib3", installs[0].Ref.Name)
	require.Equal(t, "1.26.18", installs[0].Ref.Version)
}
