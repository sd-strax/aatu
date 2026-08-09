package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/capability"
)

// resolveCaseSeed roots an investigation on a system-of-record case
// (14-case-seed.md §3): it reads the case through the capability layer, fails
// CLOSED on anything short of exactly one case (§2 — a phantom or half-loaded
// case is more dangerous than a visible failure), persists the read via eager
// promotion so case_ref names a durable object (03 §4.13), and builds the
// CaseSeed. The int is the HTTP status the caller should surface on error
// (§2: 404 not-found, 502 SoR unreachable, distinct on purpose).
func (b *Backend) resolveCaseSeed(r *http.Request, caseID, sourceScope string) (seedResolution, int, error) {
	caseID = strings.TrimSpace(caseID)
	if caseID == "" {
		return seedResolution{}, http.StatusBadRequest, fmt.Errorf("empty case id")
	}
	resolver, catalog := b.capabilitySurface()
	if resolver == nil {
		return seedResolution{}, http.StatusServiceUnavailable, fmt.Errorf("capability layer not configured")
	}
	if _, known := catalog.Descriptor("get_external_case_details"); !known {
		return seedResolution{}, http.StatusServiceUnavailable, fmt.Errorf("get_external_case_details is not available in this tenant")
	}

	input := capability.CallInput{Extra: map[string]any{"case_id": caseID}, SourceScope: sourceScope}
	res, err := resolver.Resolve(r.Context(), "get_external_case_details", input)
	if err != nil {
		// Adapter FATAL / template failure: the read did not execute.
		return seedResolution{}, http.StatusBadGateway, fmt.Errorf("read case %q: %w", caseID, err)
	}

	// Fail closed (§2). Only exactly-one-case on COMPLETE coverage seeds.
	switch res.Coverage {
	case capability.CoverageComplete:
		// distinguish not-found (empty COMPLETE) from a real hit below.
	case capability.CoverageUnavailableTenant:
		return seedResolution{}, http.StatusServiceUnavailable, fmt.Errorf("no case system of record is configured for this tenant")
	default: // UNAVAILABLE_TRANSIENT / PARTIAL — the SoR could not be fully read
		return seedResolution{}, http.StatusBadGateway, fmt.Errorf("case system of record unavailable reading %q (%s)", caseID, res.Coverage)
	}
	if len(res.ObservedDataRefs) == 0 {
		// COMPLETE with no case = the SoR answered "no such case" — a typo, not a
		// transient fault. 404, never a silent phantom-rooted investigation (§2).
		return seedResolution{}, http.StatusNotFound, fmt.Errorf("no case matches %q in the system of record", caseID)
	}

	// Persist BEFORE minting case_ref, so the ref is a durable, openable object
	// rather than a dangling deterministic id (§3 step 2).
	if b.cfg.Handler != nil {
		if err := persistInvokeResult(r, b.cfg.Handler.DB(), res); err != nil {
			return seedResolution{}, http.StatusInternalServerError, fmt.Errorf("persist case %q: %w", caseID, err)
		}
	}

	source := caseSource(res)
	if source == "" {
		// The read succeeded but carried no source tool — cannot form a valid
		// CaseSeed (source is required, aggregate.Seed.validate). Fail loudly
		// rather than persist an unlabelled case root.
		return seedResolution{}, http.StatusBadGateway, fmt.Errorf("case %q read carried no source label", caseID)
	}
	seed := aggregate.Seed{
		Type:        aggregate.SeedCase,
		CaseID:      caseID,
		Source:      source,
		CaseRef:     string(res.ObservedDataRefs[0]),
		SourceScope: sourceScope,
	}
	// The case title becomes the investigation title; the seed's summary line
	// ("case servicenow: INC0010001") is the chip. Fall back to the summary when
	// the case carried no title.
	display := seed.Summary()
	if title := caseTitle(res); title != "" {
		display = title
	}
	return seedResolution{Seed: seed, Display: display}, http.StatusOK, nil
}

// caseSource returns the source tool that served the case read (provenance.tool
// of the first normalized ObservedData) — the SoR name, which the caller never
// supplies (the binding that served the read is the truth, §3 step 3).
func caseSource(res capability.CapabilityResult) string {
	for _, n := range res.Normalized {
		for _, od := range n.ObservedData {
			if od.Provenance.Tool != "" {
				return od.Provenance.Tool
			}
		}
	}
	return ""
}

// caseTitle returns the case title the caseNormalizer carried into the
// ObservedData extensions (03 §2.9), or "" when absent.
func caseTitle(res capability.CapabilityResult) string {
	for _, n := range res.Normalized {
		for _, od := range n.ObservedData {
			if t, ok := od.Extensions["title"].(string); ok && t != "" {
				return t
			}
		}
	}
	return ""
}
