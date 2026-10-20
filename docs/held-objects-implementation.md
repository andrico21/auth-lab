# Held objects implementation handoff

Review candidate for Astra. No push, Pages deployment or repository upload has been performed. Publication to `andrico21/auth-lab` remains gated on the user's successful independent review.

## Baseline and scope

Implements the approved Held Objects v2 design, its A01-A21 acceptance matrix, and both worker notes: collapse recovery uses `#show-internals`, and target sizes are measured after transforms in rendered CSS pixels.

The approved input baseline source ZIP has SHA-256 `9e295c46e666633e83f971a57e01b329233ddf9114067506a1741afcbb1e15c8`. Its application modules match the repository baseline after the required 1:1 ASCII-hyphen normalization. The delivered Code4/G01-A browser-runner correction is carried forward. Its seek comparisons now use the same completed canonical prefix as the new inventory rather than an in-flight event's old inclusive post-state.

All 130 fixed extended scenarios, the Core-backed presets and configurable Core have explicit inventory authoring. The picker has 141 deduplicated choices. Coverage is logical-owner, configuration and cursor scoped; a catalog count alone does not establish completeness.

## Code1 implementation corrections

This candidate addresses the independent HC01-HC09 findings. The approved pure checkpoint and explicit-family architecture is retained; independent acceptance is still required.

| Finding | Corrected contract |
| --- | --- |
| HC01 | Exact replay binds each occurrence to its message/effect representation and holding. A decoded selection cannot replace historical compact JWE bytes. Local JWE checks explicitly use the decoded view and that occurrence actor's field permissions. |
| HC02 | Packet routes use the same authored message interval as canonical receipt. Full journeys, connection intervals and exact-row intervals share that boundary; receipt remains distinct from checking and installation. |
| HC03 | AD local input/key and bridge password/cookie/verifier readers are explicitly declared. PAR/JAR/JARM servers can inspect a delivered verifier; acquisition still gates availability and protected inner fields remain restricted. |
| HC04 | Local Device cancellation cleans client polling/display state without deleting the issuer's still-valid pending transaction. A restart has distinct generation identities and rejects late old results. |
| HC05 | SSH server acceptance and client completion differ. The client acquires the authenticated connection on success/result receipt, not during a server-local policy/MIC check. |
| HC06 | Hello enrollment returns an authenticator-owned platform result; the browser assembles the WebAuthn response with its original client data. Private keys stay with the authenticator; roaming conversion retains its separate CTAP result. |
| HC07 | Core CIBA does not synthesize an unauthored provider session/cookie transfer at an internal factor check. Explicit factor, approval and token events remain independent. |
| HC08 | Owner-picker selection always opens that owner's complete inventory. Dock overflow can toggle its current owner; a separate collapse action closes the list. |
| HC09 | Redraw recovery preserves both exact holding identity and originating list/dock/inspector region. Another equivalent control is a fallback only when the original region/control is absent; removal/collapse recover to the owner picker. |

Kerberos and SSH have explicit visual acceptance beyond overlap checks: folded/expanded logical-owner names, source-family column/row relationships, composite-frame attachment and real focus/target geometry. Registry-only actors absent from the whole lesson do not reserve blank cells. Actual participants from the entire journey remain reserved independently of the current cursor.

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

Exact replay follows the selected artifact, not every occurrence of its attribute type. It preserves occurrence-specific representation values and permissions rather than rewriting them from the selected holding. Full, link, attribute and exact-object views map back to canonical source history. Adjacent synthetic rows do not independently reapply an atomic event.

Ordering uses initial display order, acquisition ordinal and holding ID. Overflow counts hidden known holdings, not model gaps. A focused/selected exact holding is pinned or retained in its open list. Recovery first matches the exact key in its originating region; a duplicate dock control cannot steal list focus. Release never substitutes another token generation. Inventory hide recovers to its toggle; component collapse prefers the initiating `#show-internals` checkbox; explicit list collapse returns to its owner picker. The hidden scenario select is never a recovery target.

## Conditional geometry

- Full mode: a measured map of at least 1120x730 CSS pixels and independently valid routes uses fixed 316x174 composites with a 164-unit actor, 8-unit gap and 144-unit dock. Declared reference positions of full-journey physical participants determine preferred columns and vertical tiers. Aliased logical children do not reserve duplicate cells; inert registry-only owners remain reachable in the inventory list without forcing empty map rows. Placement minimizes necessary column changes, then displacement within at most nine reserved cells. Rows use 240-unit pitch, leaving the approved 66-unit lane. Three slots mean three holdings or two holdings plus overflow. Folded logical owners retain separate named controls.
- Compact mode: a measured canvas/viewport of at least 960 CSS pixels, valid reserved envelopes and routes uses final-CSS 82x132 actor buttons plus a 6-pixel gap and 44x44 sibling summary. The 140x140 content stays within the reserved envelope; ports use the actual transformed actor bounds.
- External mode: narrow views, invalid composite routes/bounds, supported movement or custom layouts use the independently valid base map and an accessible logical-owner list. A fallback never repairs or conceals invalid actor geometry.

Inventory visibility and individual acquisitions do not reflow actors. Responsive mode or deliberate component-internals changes can recompute the reference-derived layout once. Geometry and transformed bounds participate in route/cache identity. Logical AS/TGS and CLI/agent owners are never reassigned to the visual parent. Reduced motion uses the same semantic commits without packet-frame animation.

The checked **Show step attributes** control continues to expose the complete names-only set in full, compact and external inventory modes. Placement avoids entire reserved actor/inventory composites, not just actor centers. If no panel-sized region is free, the same named group moves below the map; it is never silently hidden or replaced by the single current packet field. Keyboard-focused help is remeasured after its `:focus-within` hint appears, including nested F2 help, so the extra text does not push the panel past the viewport.

The animation layouts retain each family's authored composition rather than imposing an OIDC template: AD person/workstation/KDC columns with the service on its adjacent row; FAST client/KDC order; SSH user/CLI/agent and IdP/CA relationships; and a centered cache-only GSS client/KDC/host row without an unused person cell. Basic web and native-client groupings remain intact. Missing references or unprovable routes decline full mode rather than inventing placement. Docked object and logical-owner names wrap to two lines, with a separate count line for merged owners, inside unchanged 44-pixel targets.

Connection keyboard focus uses a visible halo along the actual SVG path. The global rectangular outline is suppressed only on connection hit paths; other controls retain their normal focus rings. A path's bounding box is not a connector and must never appear as a rectangle through actor cards or inventories.

Graph focus targets reserve the animation controls' measured height plus clearance through CSS scroll margins. The existing resize observer also watches the control bar, so wrapping at narrow widths updates the reservation without moving participants or changing protocol state. Focused native checks scroll top-row participants and inventory controls beneath the sticky bar, focus them, dismiss participant help with Escape where applicable, and require hit-testing at the focused target's center to return that target.

## Observed verification

Runtime: Bun 1.4.3 and native Chromium 155.0.8059.84. The current standalone is 2,251,749 bytes with SHA-256 `2bef714560d305c5b64e0b6e79eb6f125c3fe121d2ac4324ff8d9082eed41651`. Reports record the exercised source and artifact identities.

| Observed check | Result |
| --- | --- |
| Semantic source gate | Passed: 141 choices, 921 normalized Core configurations, 86 required interactions and 28,030 equal-cursor comparisons |
| Full source regression suite | Current-candidate full-suite regeneration follows browser acceptance; the reviewed submission's 1,092/72-file result is historical, not a result for this correction |
| Held-object native gate | Passed in source HTTP, standalone HTTP and standalone file: all 141 choices retain full inventories at initial/final collapsed desktop cursors; 36 dense layouts per mode exercise full/compact/external geometry, rendered targets/routes, complete step names, exact-object lifecycle/replay, actual 200%/400% browser zoom, touch, reduced motion, source/emitted state equality and no unexpected CSP violations/external application requests |
| Animation-area regression | Passed in all three loading modes: paused username/password exchange at 1920 pixels for web/native clients, 1480-pixel compact and 390-pixel external layouts; authored columns, complete visible names, path-following focus and unchanged canonical snapshots. Dense layout coverage contains 18 folded and 18 expanded cases per mode. |
| Preserved broader native gate | Passed: 224 collapsed/expanded catalog variants per loading mode and 297 recorded checks, including long-context rejection/recovery, responsive help, non-modal Tab/Escape, protocol preservation and enforcing eval/inline-script/fetch CSP probes in all three loading modes |
| Focused native acceptance | All three loading modes preserve exact holding focus and canonical state through full/compact/external switching; internal-owner collapse recovers to `#show-internals`; nested F2 help stays inside the viewport |
| Sticky-toolbar focus regression | Passed in all three loading modes: six participant/inventory cases per mode across 1920, 1480, 1050 and 390-pixel widths; focused controls clear the rendered sticky bar, center hit-testing reaches the target, and complete canonical snapshots remain unchanged |
| Announcement cadence | In all three loading modes, one receipt-related live-region update across many actual animation frames; no per-frame inventory announcement |
| Delivered-file smoke | Exact R1 replay through source rows 4/5/6 equals the full snapshot at event 6/complete; compact actors measure 82x132 and summary controls 44x44 rendered CSS pixels; the complete step names remain visible; no external application requests or unexpected CSP violations |

The machine-readable reports retain exact identities, commands or scenario details and observed results. Superseded or cancelled attempts are not passing evidence. Screen-reader speech/comprehension is not established by the DOM mutation or keyboard checks.

The final full-suite report was regenerated after all browser jobs finished. An earlier concurrent run timed out in one `advanced-ui.test.mjs` lifecycle case at the unchanged 900,000-ms per-test limit; that failed report/log are preserved separately and are not passing evidence. No application/test source or timeout changed between runs.

## Reproducible checks

Application build and tests remain Bun-only, with no application dependencies or install step:

```sh
bun run build
bun test --isolate --timeout=900000 tests/held-object-*.test.mjs
bun tools/verification/held-objects-check.mjs
bun tools/verification/run-regressions.mjs
```

The source acceptance tool uses the application's actual `scenarioSnapshot()` pipeline without repeatedly rendering the catalog. It validates all choices, every applicable normalized Core combination, and the required interaction cases. It records family-state equality and full/link/exact canonical projection evidence. Its manifest includes initial holdings, exact representations, event/milestone bindings, coverage scopes, limitations and Core exclusions. This is semantic source evidence, not native-browser evidence.

Native acceptance uses optional external QA tooling, not a project runtime dependency:

```sh
PLAYWRIGHT_MODULE=/absolute/path/to/playwright-core/index.mjs \
CHROMIUM_EXECUTABLE=/absolute/path/to/chrome \
bun tools/verification/held-objects-browser-check.mjs
```

The native tool checks modular source HTTP, standalone HTTP and standalone `file://`; all choices at initial/final cursors; dense folded/expanded layouts; routes; rendered 44-pixel targets; keyboard exact-object lifecycle; touch; reduced motion; no external application requests; and source/emitted state equality. It changes Chrome's actual default browser zoom through its own isolated settings page and verifies the resulting CSS layout viewport and visual scale. It does not substitute CSS zoom, pinch scaling or a smaller viewport for real browser zoom.

Focused native and delivered-file evidence use the same optional Playwright/Chromium environment:

```sh
export PLAYWRIGHT_MODULE=/absolute/path/to/playwright-core/index.mjs
export CHROMIUM_EXECUTABLE=/absolute/path/to/chrome
bun tools/verification/run-focused-native.mjs
bun tools/verification/review-file-smoke.mjs /absolute/path/to/auth-lab-held-objects.html
```

The focused runner serves its own ephemeral loopback origin. The file runner defaults to `dist/auth-flow-studio.html` when no file argument is supplied; passing the delivered HTML additionally requires it to match the current build. Both use the checkout containing the script by default, independent of the working directory. The regression/focused runners accept an optional project directory; the file runner accepts it after the optional HTML path. All three support `--help`.

The preserved broader regression tool remains available:

```sh
PLAYWRIGHT_MODULE=/absolute/path/to/playwright-core/index.mjs \
CHROMIUM_EXECUTABLE=/absolute/path/to/chrome \
bun tools/verification/native-browser-acceptance.mjs
```

Evidence is under `docs/verification/held-objects/`. `AUTH_LAB_HELD_EVIDENCE_DIR` redirects new held-object reports; `AUTH_LAB_QA_EVIDENCE_DIR` redirects the preserved broader gate. Reports bind exact source/artifact identities and distinguish observed native checks from the DOM harness. The source regression report lists the actual bounded per-file Bun invocations/results.

The full-regression, focused-native and delivered-file report generators are shipped under `tools/verification/`. Their reports record the exact runner SHA-256 and actual regeneration command. The complete source runner uses four workers, each launching the current Bun executable with `test --isolate --timeout=900000` for one test file, and hashes the shared test helpers as well as application/test inputs. No published current report depends on an unshipped temporary runner or a fixed preview port.

The test DOM compiles selector structure once per lookup and stops `querySelector()` at the first document-order match. Matching nodes are not cached across mutations. This removes test-only traversal overhead without changing production rendering or pretending to establish browser geometry, CSP enforcement or screen-reader behavior. Playback tests assert selected queues, actual packets and control behavior rather than private dispatch-tag spellings.

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

## Review package

| File | Purpose |
| --- | --- |
| `auth-lab-held-objects.html` | Offline standalone application; identity recorded above |
| `auth-lab-held-objects-code.zip` | Complete source, tests, build/workflows, documentation, current status/manifests and a small representative screenshot set; no Git database or QA dependencies |
| `auth-lab-held-objects-verification.zip` | Complete generated verification directory, including native captures, logs and clearly named superseded attempts |
| `held-objects-implementation.md` | This handoff, available without extracting the source archive |
| `SHA256SUMS.txt` | Checksums for the standalone, both archives and handoff |

Both archives use the `auth-lab-held-objects/` project root. Extracting the verification archive beside the source archive restores the full relative evidence tree. Raw report execution paths remain unchanged; packaged evidence uses the corresponding project-relative paths. Start the independent review with this handoff and the source ZIP, not by reading the minified standalone or entire coverage manifest into one context.

## Review and manual limits

Use the final machine-readable status reports for observed pass/fail counts and exact artifact hashes. Historical 802-test evidence is baseline evidence only. Automated native acceptance is established for the recorded Chromium version; this handoff does not declare the overall manual G01 gate closed. No live KDC, Keycloak, SSH server, CA or security-key interoperability is claimed. Screen-reader speech/comprehension and cross-engine behavior are not inferred from Chromium or an accessibility tree. Astra's independent implementation review remains required before publication.
