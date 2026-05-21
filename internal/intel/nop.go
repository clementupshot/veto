package intel

import "context"

// NopSource is a Source that returns no reports for any ecosystem. It is the
// zero-cost default for disabled or unconfigured sources; wire it in at
// construction time so callers can avoid nil-checks.
type NopSource struct{}

var _ Source = (*NopSource)(nil)

// ID implements Source.
func (NopSource) ID() string { return "nop" }

// Fetch implements Source. Always returns an empty slice and a nil error.
func (NopSource) Fetch(ctx context.Context, eco Ecosystem) ([]MalwareReport, error) {
	return nil, nil
}
