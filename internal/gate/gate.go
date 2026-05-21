// Package gate makes the final allow/refuse decision for a parsed install
// command. It consults the intel.Store for each Install and aggregates the
// verdicts; policy choices about local paths, implicit installs, and on-disk
// manifest expansion live here so the package-manager parsers stay stateless.
package gate

import (
	"github.com/rs/zerolog"

	"github.com/brynbellomy/package-bouncer/internal/intel"
	"github.com/brynbellomy/package-bouncer/internal/packagemanager"
)

// Outcome is the gate's verdict for a complete install command.
type Outcome string

const (
	// OutcomeAllow: no Install matched a malware report. Pass through to the
	// real package manager.
	OutcomeAllow Outcome = "allow"

	// OutcomeRefuse: at least one Install matched malware intel. The bouncer
	// must NOT exec the real package manager.
	OutcomeRefuse Outcome = "refuse"

	// OutcomePassThrough: the command did not describe an install (parser
	// returned nil). The bouncer execs the real binary unchanged.
	OutcomePassThrough Outcome = "passthrough"
)

// Decision is the full result of an evaluation, including per-install
// verdicts so callers can render useful diagnostics.
type Decision struct {
	Outcome  Outcome
	Verdicts []intel.Verdict
}

// Flagged returns the verdicts that produced refusals, in order. Empty when
// Outcome != OutcomeRefuse.
func (d Decision) Flagged() []intel.Verdict {
	out := make([]intel.Verdict, 0, len(d.Verdicts))
	for _, v := range d.Verdicts {
		if v.Flagged() {
			out = append(out, v)
		}
	}
	return out
}

// ManifestExpander turns a parser-extracted manifest reference (e.g. pip's
// `-r requirements.txt`) into the Install records the gate should look up.
// Implementations perform the actual file I/O so the package-manager parsers
// remain pure.
//
// Implementations must be safe for concurrent use. Expand returns wrapped
// errors with the offending path attached as a field when I/O fails; malformed
// lines inside a manifest are skipped silently (over-include is safer than
// crashing the gate mid-install).
type ManifestExpander interface {
	Expand(ref packagemanager.ManifestRef) ([]packagemanager.Install, error)
}

// NopExpander is the zero-cost default ManifestExpander: it returns no
// installs and no error for every ref. Wire it in when manifest expansion is
// not desired, so the gate's call sites stay unconditional.
type NopExpander struct{}

var _ ManifestExpander = NopExpander{}

// Expand implements ManifestExpander. Returns nil, nil.
func (NopExpander) Expand(_ packagemanager.ManifestRef) ([]packagemanager.Install, error) {
	return nil, nil
}

// Policy configures gate behavior.
type Policy struct {
	// AllowLocal: when true, Installs marked Local (file paths, git URLs) are
	// passed through without an intel lookup — there is nothing to look up by
	// name. When false, the gate refuses local installs as well.
	AllowLocal bool

	// ManifestExpander turns ManifestRefs (e.g. `-r requirements.txt`) into
	// additional Install records before lookup. Defaults to NopExpander so
	// callers that don't opt in keep the previous "argv-only" behavior.
	ManifestExpander ManifestExpander
}

// DefaultPolicy returns a Policy with sensible defaults: local installs pass
// and manifest expansion is a no-op (callers wire in pyreq.Expander to enable
// requirements.txt gating).
func DefaultPolicy() Policy {
	return Policy{AllowLocal: true, ManifestExpander: NopExpander{}}
}

// Gate evaluates Installs against an intel store under a policy.
type Gate struct {
	store    intel.Store
	policy   Policy
	expander ManifestExpander
	logger   zerolog.Logger
}

// New builds a Gate. A nil-valued Policy.ManifestExpander is replaced with
// NopExpander so call sites stay nil-free.
func New(store intel.Store, policy Policy) *Gate {
	if policy.ManifestExpander == nil {
		policy.ManifestExpander = NopExpander{}
	}
	return &Gate{
		store:    store,
		policy:   policy,
		expander: policy.ManifestExpander,
		logger:   zerolog.Nop(),
	}
}

// WithLogger returns a copy of g configured with the given logger. The logger
// is used to surface manifest-expansion failures, which are non-fatal —
// missing or unreadable requirements files don't refuse the install on their
// own.
func (g *Gate) WithLogger(logger zerolog.Logger) *Gate {
	copy := *g
	copy.logger = logger
	return &copy
}

// Evaluate returns the decision for the given installs. A nil installs
// argument (parser returned no installs) yields OutcomePassThrough.
// An empty (non-nil) installs argument (parser saw an install verb with no
// explicit specs, e.g. `npm install` resolving from package.json) yields
// OutcomeAllow today — refer to package-bouncer's known-limitations doc.
//
// manifestRefs, when non-empty, are passed through Policy.ManifestExpander
// to discover transitive Installs (pip's `-r requirements.txt`, npm's
// `package.json`, poetry's `pyproject.toml`). Any installs the expander
// produces are gated alongside the argv-named ones.
func (g *Gate) Evaluate(installs []packagemanager.Install, manifestRefs ...packagemanager.ManifestRef) Decision {
	if installs == nil && len(manifestRefs) == 0 {
		return Decision{Outcome: OutcomePassThrough}
	}

	// Expand manifest refs first so a refusal from inside a requirements.txt
	// flips the decision even when argv named no explicit specs.
	expanded := installs
	for _, ref := range manifestRefs {
		extra, err := g.expander.Expand(ref)
		if err != nil {
			// Log and continue: we'd rather gate the explicit args than refuse
			// because a requirements file path was wrong. The caller already
			// sees argv-named installs even if the manifest can't be read.
			g.logger.Warn().
				Err(err).
				Str("path", ref.Path).
				Str("kind", string(ref.Kind)).
				Msg("manifest expansion failed; gating argv-named installs only")
			continue
		}
		expanded = append(expanded, extra...)
	}

	if expanded == nil {
		// Caller passed nil installs and refs that expanded to nothing.
		// Treat as passthrough — the command wasn't an install in any
		// meaningful sense.
		return Decision{Outcome: OutcomePassThrough}
	}

	decision := Decision{Outcome: OutcomeAllow}
	for _, ins := range expanded {
		if ins.Local {
			// Empty-name local lookups are meaningless against a name-keyed store.
			if g.policy.AllowLocal {
				continue
			}
		}
		verdict := g.store.Lookup(ins.Ref)
		decision.Verdicts = append(decision.Verdicts, verdict)
		if verdict.Flagged() {
			decision.Outcome = OutcomeRefuse
		}
	}
	return decision
}
