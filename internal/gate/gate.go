// Package gate makes the final allow/refuse decision for a parsed install
// command. It consults the intel.Store for each Install and aggregates the
// verdicts; policy choices about local paths and implicit installs live here
// so the package-manager parsers stay stateless.
package gate

import (
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

// Policy configures gate behavior.
type Policy struct {
	// AllowLocal: when true, Installs marked Local (file paths, git URLs) are
	// passed through without an intel lookup — there is nothing to look up by
	// name. When false, the gate refuses local installs as well.
	AllowLocal bool
}

// DefaultPolicy returns a Policy with sensible defaults: local installs pass.
func DefaultPolicy() Policy { return Policy{AllowLocal: true} }

// Gate evaluates Installs against an intel store under a policy.
type Gate struct {
	store  intel.Store
	policy Policy
}

// New builds a Gate.
func New(store intel.Store, policy Policy) *Gate {
	return &Gate{store: store, policy: policy}
}

// Evaluate returns the decision for the given installs. A nil installs
// argument (parser returned no installs) yields OutcomePassThrough.
// An empty (non-nil) installs argument (parser saw an install verb with no
// explicit specs, e.g. `npm install` resolving from package.json) yields
// OutcomeAllow today — refer to package-bouncer's known-limitations doc.
//
// @@TODO: when installs is empty-but-non-nil, read the local manifest
// (package.json, requirements.txt, pyproject.toml) and treat the listed
// dependencies as Installs. Today that case allows through.
func (g *Gate) Evaluate(installs []packagemanager.Install) Decision {
	if installs == nil {
		return Decision{Outcome: OutcomePassThrough}
	}

	decision := Decision{Outcome: OutcomeAllow}
	for _, ins := range installs {
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
