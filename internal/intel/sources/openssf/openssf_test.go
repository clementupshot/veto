package openssf_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/intel/sources/openssf"
)

// TestFetchRejectsOversizedPayload (M6 parity with aikido/osv): a
// tarball body larger than maxFeedBytes (512 MiB) must be refused for
// that refresh. Without the io.LimitReader+1 cap and the > maxFeedBytes
// guard a compromised upstream could stream a multi-GB tarball and
// OOM the daemon.
func TestFetchRejectsOversizedPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("streams >512 MiB; skipped under -short")
	}
	const maxFeedBytes = 512 << 20
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", `"oversized"`)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("ETag", `"oversized"`)
		w.WriteHeader(http.StatusOK)
		// Stream just over the cap in small chunks so the test
		// process doesn't try to allocate 512 MiB of memory.
		chunk := bytes.Repeat([]byte{0x1f, 0x8b, 0x08}, 1<<20)
		written := 0
		for written <= maxFeedBytes {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			written += len(chunk)
		}
	}))
	defer srv.Close()

	src, err := openssf.New(openssf.Options{
		TarballURL: srv.URL,
		CacheDir:   t.TempDir(),
		Logger:     zerolog.Nop(),
	})
	require.NoError(t, err)

	_, err = src.Fetch(context.Background(), intel.EcosystemNPM)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds size limit")
}
