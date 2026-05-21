package intel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/brynbellomy/go-utils/errors"
)

const baselineFileName = "intel-baseline.json"

// baselineFile is the on-disk schema for the rolling-max baseline + last-
// fresh-fetch timestamps the retention pipeline persists across daemon
// restarts. Without this file every cold start would walk through the
// initial-Refresh window with zero retention floor — exactly the gap H3
// (COR-006 / SEC-002 in the audit) calls out.
//
// version is a hard integer so older daemons can refuse newer schemas;
// missing or unparseable files are treated as "no baseline yet" rather
// than a hard failure (the LOUD failure mode via minHealthyReportCount
// is the real safety net).
type baselineFile struct {
	Version int                       `json:"version"`
	Buckets map[string]baselineBucket `json:"buckets"`
}

type baselineBucket struct {
	Count          int   `json:"count"`
	LastFreshFetch int64 `json:"last_fresh_fetch"`
	HistoricalMax  int   `json:"historical_max"`
}

const baselineSchemaVersion = 1

// bucketKeyString stringifies a sourceEcoKey for the JSON map key. The
// composite form keeps both fields visible in the file so an operator
// can inspect intel-baseline.json without running veto.
func bucketKeyString(k sourceEcoKey) string {
	return k.SourceID + "/" + string(k.Ecosystem)
}

// readBaseline returns the persisted baseline state, or empty maps if
// the file is missing or corrupt. Failures are logged by the caller; we
// fail OPEN (zero baseline) on the persistence side because the LOUD
// failure mode at refresh time catches a genuinely-broken store.
func readBaseline(dir string) (map[sourceEcoKey]time.Time, map[sourceEcoKey]int, error) {
	if dir == "" {
		return map[sourceEcoKey]time.Time{}, map[sourceEcoKey]int{}, nil
	}
	path := filepath.Join(dir, baselineFileName)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[sourceEcoKey]time.Time{}, map[sourceEcoKey]int{}, nil
	}
	if err != nil {
		return nil, nil, errors.With(err, "read baseline").Set("path", path)
	}
	var bf baselineFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return nil, nil, errors.With(err, "parse baseline").Set("path", path)
	}
	if bf.Version != baselineSchemaVersion {
		return nil, nil, fmt.Errorf("baseline schema version %d not supported (expected %d)",
			bf.Version, baselineSchemaVersion)
	}
	last := make(map[sourceEcoKey]time.Time, len(bf.Buckets))
	maxes := make(map[sourceEcoKey]int, len(bf.Buckets))
	for keyStr, b := range bf.Buckets {
		k, ok := parseBucketKey(keyStr)
		if !ok {
			continue
		}
		if b.LastFreshFetch > 0 {
			last[k] = time.Unix(b.LastFreshFetch, 0)
		}
		if b.HistoricalMax > 0 {
			maxes[k] = b.HistoricalMax
		}
	}
	return last, maxes, nil
}

func parseBucketKey(s string) (sourceEcoKey, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return sourceEcoKey{
				SourceID:  s[:i],
				Ecosystem: Ecosystem(s[i+1:]),
			}, true
		}
	}
	return sourceEcoKey{}, false
}

// writeBaseline atomically persists the current per-bucket counts,
// last-fresh-fetch timestamps, and historical maxima. Best-effort —
// returns an error so the caller can log, but the in-memory index is
// already swapped in by the time we get here, so a persistence failure
// is not fatal.
func writeBaseline(
	dir string,
	resolved map[sourceEcoKey][]MalwareReport,
	lastRefreshedAt map[sourceEcoKey]time.Time,
	historicalMax map[sourceEcoKey]int,
) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return errors.With(err, "mkdir baseline dir")
	}
	bf := baselineFile{
		Version: baselineSchemaVersion,
		Buckets: make(map[string]baselineBucket, len(resolved)),
	}
	for k, reports := range resolved {
		bf.Buckets[bucketKeyString(k)] = baselineBucket{
			Count:          len(reports),
			LastFreshFetch: lastRefreshedAt[k].Unix(),
			HistoricalMax:  historicalMax[k],
		}
	}
	buf, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return errors.With(err, "marshal baseline")
	}
	buf = append(buf, '\n')
	path := filepath.Join(dir, baselineFileName)
	tmp, err := os.CreateTemp(dir, baselineFileName+".tmp.")
	if err != nil {
		return errors.With(err, "tmpfile")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		return errors.With(err, "write tmp baseline")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return errors.With(err, "fsync tmp baseline")
	}
	if err := tmp.Close(); err != nil {
		return errors.With(err, "close tmp baseline")
	}
	return os.Rename(tmpPath, path)
}
