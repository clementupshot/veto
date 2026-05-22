package argv_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/packagemanager/argv"
)

func TestFirstNonFlagWithTable(t *testing.T) {
	table := argv.FlagsWithValues{
		"--prefix":   {},
		"--registry": {},
		"-p":         {},
	}

	cases := []struct {
		name     string
		args     []string
		wantVerb string
		wantRest []string
		wantOK   bool
	}{
		{
			name:     "empty",
			args:     nil,
			wantVerb: "",
			wantRest: nil,
			wantOK:   false,
		},
		{
			name:     "bare flag (no value) skipped",
			args:     []string{"--verbose", "install", "foo"},
			wantVerb: "install",
			wantRest: []string{"foo"},
			wantOK:   true,
		},
		{
			name:     "flag with value before verb",
			args:     []string{"--prefix", "/tmp", "install", "foo"},
			wantVerb: "install",
			wantRest: []string{"foo"},
			wantOK:   true,
		},
		{
			name:     "--flag=value form is single token",
			args:     []string{"--prefix=/tmp", "install", "foo"},
			wantVerb: "install",
			wantRest: []string{"foo"},
			wantOK:   true,
		},
		{
			name:     "short flag with value",
			args:     []string{"-p", "value", "install", "foo"},
			wantVerb: "install",
			wantRest: []string{"foo"},
			wantOK:   true,
		},
		{
			name:     "mixed flags then positional",
			args:     []string{"--registry", "https://example.com", "--verbose", "install", "foo"},
			wantVerb: "install",
			wantRest: []string{"foo"},
			wantOK:   true,
		},
		{
			name:     "POSIX -- separator forces next token to be verb",
			args:     []string{"--", "--prefix"},
			wantVerb: "--prefix",
			wantRest: []string{},
			wantOK:   true,
		},
		{
			name:     "no positional found",
			args:     []string{"--prefix", "/tmp"},
			wantVerb: "",
			wantRest: nil,
			wantOK:   false,
		},
		{
			name:     "flag-with-value at trailing edge (no following token)",
			args:     []string{"--prefix"},
			wantVerb: "",
			wantRest: nil,
			wantOK:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verb, rest, ok := argv.FirstNonFlagWithTable(c.args, table)
			require.Equal(t, c.wantOK, ok)
			require.Equal(t, c.wantVerb, verb)
			require.Equal(t, c.wantRest, rest)
		})
	}
}

func TestCollectPositionalsWithTable(t *testing.T) {
	table := argv.FlagsWithValues{
		"--registry": {},
		"--prefix":   {},
	}

	cases := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "empty",
			args: nil,
			want: []string{},
		},
		{
			name: "all positionals",
			args: []string{"a", "b", "c"},
			want: []string{"a", "b", "c"},
		},
		{
			name: "bare flag (no value) skipped, positional kept",
			args: []string{"--save-dev", "typescript"},
			want: []string{"typescript"},
		},
		{
			name: "flag with value skipped",
			args: []string{"--registry", "https://example.com", "lodash"},
			want: []string{"lodash"},
		},
		{
			name: "--flag=value form is single token",
			args: []string{"--registry=https://example.com", "lodash"},
			want: []string{"lodash"},
		},
		{
			name: "mixed flags and positionals",
			args: []string{"--registry", "https://example.com", "lodash", "--save-dev", "react"},
			want: []string{"lodash", "react"},
		},
		{
			name: "POSIX -- flips to positional-only mode",
			args: []string{"--registry", "https://example.com", "--", "--evil-pkg", "--also-evil"},
			want: []string{"--evil-pkg", "--also-evil"},
		},
		{
			name: "-- with no value-eating flag pending",
			args: []string{"foo", "--", "--bar"},
			want: []string{"foo", "--bar"},
		},
		{
			name: "flag-with-value at trailing edge does not skip past end",
			args: []string{"lodash", "--registry"},
			want: []string{"lodash"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := argv.CollectPositionalsWithTable(c.args, table)
			require.Equal(t, c.want, got)
		})
	}
}

func TestFirstNonFlagWithTable_NilTable(t *testing.T) {
	args := []string{"--verbose", "install", "foo"}
	verb, rest, ok := argv.FirstNonFlagWithTable(args, nil)
	require.True(t, ok)
	require.Equal(t, "install", verb)
	require.Equal(t, []string{"foo"}, rest)
}
