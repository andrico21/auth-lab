# Held objects implementation handoff

Review candidate for Astra. No commit, push, Pages deployment or repository upload is included. Publication to `andrico21/auth-lab` remains gated on the user's successful independent review.

## Baseline and scope

Implements the approved Held Objects v2 design, its A01-A21 acceptance matrix, and both worker notes: collapse recovery uses `#show-internals`, and target sizes are measured after transforms in rendered CSS pixels.

The delivered reviewed source ZIP has SHA-256 `9e295c46e666633e83f971a57e01b329233ddf9114067506a1741afcbb1e15c8`. Its application modules match the repository baseline after the required 1:1 ASCII-hyphen normalization. The delivered Code4/G01-A browser-runner correction is carried forward. Its seek comparisons now use the same completed canonical prefix as the new inventory rather than an in-flight event's old inclusive post-state.

All 130 fixed extended scenarios, the Core-backed presets and configurable Core have explicit inventory authoring. The picker has 141 deduplicated choices. Coverage is logical-owner, configuration and cursor scoped; a catalog count alone does not establish completeness.

## Source review order

1. `src/held-object-state.js`: pure validation, immutable checkpoints, canonical cursors, exact traces, permission filtering and the separate universal-coverage gate.
2. `src/held-object-authoring.js`: declaration helpers. No inference from prose, operation names, attribute catalogs or historical holders.
3. `src/held-objects.js`: exact catalog/source-module dispatch and review-manifest extraction. Family labels such as `ad-ds` are not ownership-dispatch identifiers.
4. `src/held-object-ad.js`, `held-object-kerberos.js`, `held-object-ssh.js`, `held-object-protection.js`, `held-object-web.js`, `held-object-core.js`: explicit protocol-family artifacts, representations, stores, releases, observations and initial bindings.
5. `src/held-object-view.js`, `src/app.js`, `src/player.js`, `src/styles.css`: actual inventory, inspection, replay, geometry, focus and reduced-motion integration.
6. `tests/held-object-*.test.mjs` and the verification tools below. Review source and bounded report sections before opening the generated standalone or historical TAP logs wholesale.

`build.mjs` preserves module-private scope for the new inventory modules inside the single-file bundle. Only their explicit exports are shared. This prevents private names from colliding under the original flat concatenation build; existing module bundling and CSP hash generation remain unchanged.

## Semantic contract

- Artifact identity, representation identity and individual holding/store identity are separate. Context-qualified keys are stable within an immutable scenario/configuration/revision. Equal labels or synthetic values never merge generations.
- Initial holdings are explicit and independent of operation-derived history. Reset is before step one, even when the first navigation row remains highlighted.
- Source events commit atomically at completion unless finer milestones were authored. Whole-message receipt does not occur independently for each animated field chip. A response can be received before it is checked or installed.
- Sending copies a representation. Retained sender holdings survive. Every temporary receipt/output has an explicit release or installation promotion.
- Expired, rejected, consumed and revoked objects are not automatically erased. Authority state, a named actor's knowledge, checks and request/endpoint/policy acceptance remain separate.
- Refresh installation releases R0 and promotes the distinct R1 holding. Issuer consumption or a delayed response alone does neither. Exact identity survives a storage move.
- Ticket ciphertext, local reply/session keys and accepted cache entries are distinct. PKINIT DH values and FAST machine/user/armor contexts remain local or protected as authored. Forest referrals preserve each realm/target and key identity. Configured trust keys are not workstation credentials.
- SPA/browser cookie readability differs from BFF token storage. DPoP request/retry proofs, verifier JWKS generations, PAR handles, assertions, metadata and logout records have independent lifecycles.
- Optional refresh fields in Core and SPA/BFF examples are explanatory policy options, not a concretely selected issued credential. Those inventories do not invent a refresh-token holding. Concrete rotation/offline lessons model their actual refresh credentials. Fixed advanced SAML lessons retain their signed-XML scope; configurable Core separately covers XML Encryption.
- The unrelated initial AD LDAP credential remains an explicitly bounded opaque holding. Missing principal/key/lifetime detail is stated, not fabricated.

`protocolSnapshot()` now returns the canonical `cursor`, `selectedSourceIndex` and the inclusive completed history prefix as `sourceIndex`. Any non-complete milestone excludes its current event from that cumulative instance ledger. `state` is the actual current milestone state, not a forecast. `reconstructProtocolState()` retains its original inclusive completed-prefix API.

## Inventory and exact-object UI

**Show held objects** starts enabled. Compact controls contain names and state/store hints, never raw secret values. The inspector names the exact artifact and holding, creator, logical owner, acquisition cursor, store, representation, permitted fields, checks, scoped acceptance, authority and related IDs.

Current inspection uses actor/representation/field permissions. Removed or rewound selections remain explicitly historical: `No longer held`, `Not yet held`, or `Not created`. They do not become new holdings or actor knowledge. Apply, Reset and scenario/context changes clear stale exact selections atomically.

Exact replay follows the selected artifact, not every occurrence of its attribute type. Full, link, attribute and exact-object views map back to canonical source history. Adjacent synthetic rows do not independently reapply an atomic event.

Ordering uses initial display order, acquisition ordinal and holding ID. Overflow counts hidden known holdings, not model gaps. A focused/selected exact holding is pinned or retained in its open list. Release never substitutes another token generation for focus. Inventory hide recovers to its toggle; component collapse prefers the initiating `#show-internals` checkbox. The hidden scenario select is never a recovery target.

## Conditional geometry

- Full mode: a measured map of at least 1120x730 CSS pixels and independently valid routes uses fixed 316x174 composites with a 164-unit actor, 8-unit gap and 144-unit dock. Three slots mean either three holdings or two holdings plus overflow. Folded logical owners retain separate compartments. Obsolete device/server zones are hidden in this revised grid.
- Compact mode: a measured canvas/viewport of at least 960 CSS pixels, valid reserved envelopes and routes uses final-CSS 82x132 actor buttons plus a 6-pixel gap and 44x44 sibling summary. The 140x140 content stays within the reserved envelope; ports use the actual transformed actor bounds.
- External mode: narrow views, invalid composite routes/bounds, supported movement or custom layouts use the independently valid base map and an accessible logical-owner list. A fallback never repairs or conceals invalid actor geometry.

Visibility and individual acquisitions do not reflow actors. Responsive mode changes can recompute the approved layout once. Geometry and transformed bounds participate in route/cache identity. Logical AS/TGS and CLI/agent owners are never reassigned to the visual parent. Reduced motion uses the same semantic commits without packet-frame animation.

## Reproducible checks

Application build and tests remain Bun-only, with no application dependencies or install step:

```sh
bun run build
bun test --isolate --timeout=900000 tests/held-object-*.test.mjs
bun tools/verification/held-objects-check.mjs
bun run test
```

The source acceptance tool uses the application's actual `scenarioSnapshot()` pipeline without repeatedly rendering the catalog. It validates all choices, every applicable normalized Core combination, and the required interaction cases. It records family-state equality and full/link/exact canonical projection evidence. Its manifest includes initial holdings, exact representations, event/milestone bindings, coverage scopes, limitations and Core exclusions. This is semantic source evidence, not native-browser evidence.

Native acceptance uses optional external QA tooling, not a project runtime dependency:

```sh
PLAYWRIGHT_MODULE=/absolute/path/to/playwright-core/index.mjs \
CHROMIUM_EXECUTABLE=/absolute/path/to/chrome \
bun tools/verification/held-objects-browser-check.mjs
```

The native tool checks modular source HTTP, standalone HTTP and standalone `file://`; all choices at initial/final cursors; dense folded/expanded layouts; routes; rendered 44-pixel targets; keyboard exact-object lifecycle; touch; reduced motion; no external application requests; and source/emitted state equality. It changes Chrome's actual default browser zoom through its own isolated settings page and verifies the resulting CSS layout viewport and visual scale. It does not substitute CSS zoom, pinch scaling or a smaller viewport for real browser zoom.

The preserved broader regression tool remains available:

```sh
PLAYWRIGHT_MODULE=/absolute/path/to/playwright-core/index.mjs \
CHROMIUM_EXECUTABLE=/absolute/path/to/chrome \
bun tools/verification/native-browser-acceptance.mjs
```

Evidence is under `docs/verification/held-objects/`. `AUTH_LAB_HELD_EVIDENCE_DIR` redirects new held-object reports; `AUTH_LAB_QA_EVIDENCE_DIR` redirects the preserved broader gate. Reports bind exact source/artifact identities and distinguish observed native checks from the DOM harness. The source regression report lists the actual bounded per-file Bun invocations/results.

## Acceptance evidence map

| Acceptance | Primary behavior evidence |
| --- | --- |
| A01 | Explicit seeded/empty/partial/unmodeled engine cases; initial family inventories; native initial cursors |
| A02 | AD cache variants, PKINIT, FAST bootstrap/armor/user boundaries and forest cached paths |
| A03 | Authored protocol clock, retained expired credentials, explicit eviction and history |
| A04-A06 | Copy/delivery milestones, protected receipt/checks, request-scoped API failures and verifier acquisition |
| A07-A08 | R0/R1 replacement/delay; offline session and browser logout separation |
| A09-A10 | SPA/BFF cookie readability; native/backend PKCE and callback ownership |
| A11-A12 | Device/CIBA pending handles; exchange lineage; exact DPoP proofs, mTLS and issuer outputs |
| A13-A14 | SAML/JWE permission boundaries; local FIDO private keys and TOTP input/provisioning |
| A15 | SSH reissuance, agent copies, revocation publication/installation and existing connection |
| A16-A18 | Equal-cursor differential checks, frame/speed invariance, context rejection and stale-selection clearing |
| A19-A20 | Native full/compact/external geometry, keyboard/focus, touch, reduced motion and actual browser zoom |
| A21 | Generated per-choice manifest, normalized Core matrix, all required interactions and rejecting universal gate |

## Review and manual limits

Use the final machine-readable status reports for observed pass/fail counts and exact artifact hashes. Historical 802-test evidence is baseline evidence only. No live KDC, Keycloak, SSH server, CA or security-key interoperability is claimed. Screen-reader speech/comprehension and cross-engine behavior are not inferred from Chromium or an accessibility tree. The old G01 label is not automatically closed by planning approval or a source test run. Astra's independent implementation review remains required before publication.
