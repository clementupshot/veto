package jsspec_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager/jsspec"
)

func TestParse(t *testing.T) {
	cases := []struct {
		spec        string
		wantName    string
		wantVersion string
		wantLocal   bool
	}{
		{"lodash", "lodash", "", false},
		{"lodash@4.17.21", "lodash", "4.17.21", false},
		{"lodash@^4.17", "lodash", "^4.17", false},
		{"@types/node", "@types/node", "", false},
		{"@types/node@20.0.0", "@types/node", "20.0.0", false},
		{"@scope/pkg@~1.2", "@scope/pkg", "~1.2", false},

		// Local / non-registry specs.
		{"./local", "./local", "", true},
		{"../sibling", "../sibling", "", true},
		{"/abs/path", "/abs/path", "", true},
		{"file:./local", "file:./local", "", true},
		{"git+https://github.com/user/repo.git", "git+https://github.com/user/repo.git", "", true},
		{"github:user/repo", "github:user/repo", "", true},
		{"user/repo", "user/repo", "", true}, // npm shorthand
		{"https://example.com/x.tgz", "https://example.com/x.tgz", "", true},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			got := jsspec.Parse(c.spec)
			require.Equal(t, c.wantName, got.Ref.Name)
			require.Equal(t, c.wantVersion, got.Ref.Version)
			require.Equal(t, c.wantLocal, got.Local)
			require.Equal(t, c.spec, got.RawSpec)
			require.Equal(t, intel.EcosystemNPM, got.Ref.Ecosystem)
		})
	}
}
