package jsspec_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/jsspec"
)

func TestParse(t *testing.T) {
	cases := []struct {
		spec          string
		wantName      string
		wantVersion   string
		wantLocalPath bool
		wantOpaque    bool
	}{
		{"lodash", "lodash", "", false, false},
		{"lodash@4.17.21", "lodash", "4.17.21", false, false},
		{"lodash@^4.17", "lodash", "^4.17", false, false},
		{"@types/node", "@types/node", "", false, false},
		{"@types/node@20.0.0", "@types/node", "20.0.0", false, false},
		{"@scope/pkg@~1.2", "@scope/pkg", "~1.2", false, false},

		// Filesystem-path specs → LocalPath.
		{"./local", "./local", "", true, false},
		{"../sibling", "../sibling", "", true, false},
		{"/abs/path", "/abs/path", "", true, false},
		{"file:./local", "file:./local", "", true, false},

		// Remote / git / shorthand → OpaqueRemote (refused by default).
		{"git+https://github.com/user/repo.git", "git+https://github.com/user/repo.git", "", false, true},
		{"github:user/repo", "github:user/repo", "", false, true},
		{"user/repo", "user/repo", "", false, true}, // npm shorthand
		{"https://example.com/x.tgz", "https://example.com/x.tgz", "", false, true},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			got := jsspec.Parse(c.spec)
			require.Equal(t, c.wantName, got.Ref.Name)
			require.Equal(t, c.wantVersion, got.Ref.Version)
			require.Equal(t, c.wantLocalPath, got.LocalPath, "LocalPath mismatch")
			require.Equal(t, c.wantOpaque, got.OpaqueRemote, "OpaqueRemote mismatch")
			require.Equal(t, c.spec, got.RawSpec)
			require.Equal(t, intel.EcosystemNPM, got.Ref.Ecosystem)
		})
	}
}
