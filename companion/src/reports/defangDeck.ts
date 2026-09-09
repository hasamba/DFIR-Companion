import type { PresentationDeck, PresentationSlide } from "../analysis/presentation.js";
import { defangIndicators } from "./defang.js";

// Render the indicators in a presentation deck inert, for the STANDALONE EXPORT only (#892).
//
// The offline deck is a deliverable in the same sense the report is: /cases/:id/present/export
// serves it as an attachment so it can be handed to a stakeholder, and the saved file opens from
// file:// with no CSP. Live attacker URLs, IPs and email addresses have no business travelling in
// it — the same reasoning as defang.ts, which this reuses wholesale.
//
// WHY A SEPARATE PASS, not part of buildPresentationDeck: presentation.ts builds ONE deck that both
// the in-app slide viewer (/cases/:id/present) and this export render. Defanging in the builder
// would defang the analyst's own live briefing view too, leaving it disagreeing with every other
// in-app surface about what an indicator is. Scope-filtering belongs in the builder; making a value
// safe to email belongs at the export boundary, which is here.
//
// Pure + idempotent (defangIndicators is), so re-exporting the same case is stable.

// defangIndicators only rewrites a BARE dotted token when the caller vouches for it as a domain,
// so it never mangles the filenames a forensic report is full of (`vitest.config.ts` has the shape
// of a domain with a two-letter TLD). The report path vouches with caseDomains(state); the deck
// vouches with its own domain-typed IOCs, pooled across every slide so a domain named on one
// slide's IOC list is also defanged where it appears in another slide's prose.
//
// That pool is a near-subset of caseDomains, not an equal: a domain IOC on no slide at all is not
// in it. Deliberate, and it costs nothing that matters — the deck has no autolinker and renders
// through safe-dom text nodes, so a bare hostname is inert either way, while URLs, IPv4 addresses
// and email addresses (the forms a reader can actually click) are defanged unconditionally,
// whatever this pool holds. Taking the real case domains would mean loading the case state a
// second time at the route purely to widen an allow-list for text that cannot be clicked.
function deckDomains(deck: PresentationDeck): string[] {
  const domains = new Set<string>();
  for (const slide of deck.slides) {
    for (const ioc of slide.iocs ?? []) {
      if (ioc.type === "domain") domains.add(ioc.value);
    }
  }
  return [...domains];
}

function defangSlide(slide: PresentationSlide, domains: string[]): PresentationSlide {
  const text = (value: string): string => defangIndicators(value, domains);
  return {
    ...slide,
    title: text(slide.title),
    ...(slide.body !== undefined ? { body: text(slide.body) } : {}),
    ...(slide.description !== undefined ? { description: text(slide.description) } : {}),
    // IOC values are the one place the deck carries a raw indicator as a FIELD rather than as
    // prose, so they are the reason this pass exists. `type` and `verdict` are untouched: the
    // slide badges the indicator by type, and a defanged value must still read as the url/ip/
    // domain it is. The value round-trips back via refangIocValue (see defang.ts).
    ...(slide.iocs ? { iocs: slide.iocs.map((i) => ({ ...i, value: text(i.value) })) } : {}),
  };
}

/** Defang every indicator in `deck`'s prose and IOC values. Call this at the export boundary only. */
export function defangDeck(deck: PresentationDeck): PresentationDeck {
  const domains = deckDomains(deck);
  return { ...deck, slides: deck.slides.map((s) => defangSlide(s, domains)) };
}
