# DNSSEC reviewer navigation

This is repository navigation and reproduction guidance, not release acceptance. Astra's [R10 closure review](inputs/dnssec-r10-closure-review.html), dated 25 October 2026, **closes DNS-R10 for corrections-03 and identifies no further required correction**. Original scoped closures and dispositions remain preserved. The user subsequently authorized publication with the footer-name correction to **Kirill Andrienko**, without retesting; this does not accept human G01 or performance conditions.

## Independently reviewed correction snapshot

Read the [closure disposition](corrections/independent-r10-closure-disposition.json) and [response ledger](corrections/response-ledger.json), then the [implementation handoff](implementation.md), [current progress](current-progress.json) and [open gates](open-gates.json). Scoped independent closure is complete. Publication is separately user-authorized; human acceptance, measured performance and overall release acceptance remain unapproved.

The [publication input](../verification/dnssec-publication/publication-input.json) records the post-review credit-label correction, matching native-verifier label and rebuilt standalone. No local tests were rerun. Identities and executed checks below describe the independently reviewed baseline, not fresh verification of the later footer text.

- Base checkpoint: `c99ebd6fec16e01dc9fef6c9590d534b8f1daf85`; no new committed checkpoint.
- Current [R10 inputs01](../verification/dnssec-r10-correction/candidate-inputs-01.json): 231 application/test files, SHA256 `1b5a3350e5e2b778efb52dccb46473e197df1ec202e3cd202618540c1988f234`.
- Current standalone: 5,243,123 bytes, SHA256 `5e13671a57cfb0d4c827b4eb6af52fc6d0d53f48c5816c8e7bcc423e54022f54`.
- Current [R10 Source01](../verification/dnssec-r10-correction/source-contract-01/status.json) and [Emitted01](../verification/dnssec-r10-correction/emitted-contract-01/status.json): 159/159 cases each, 1,068 checkpoints, 27,031 prefixes and exact complete case equality. All 435 authority inputs, including 354 originals and eight layers, are unchanged.
- Current normal full regression: 1,996 pass / 0 fail across 121 files, unchanged input guard and timeout. Numeric: 502 checks; compiled/held: 317 choices, 921 Core configurations, 86 interactions. The 62 affected source tests and ten compiled UI tests pass. New native evidence is two narrow headless native source/offline exact-inspector surfaces, not a Native04 rerun.
- [Frozen worker summary](../verification/dnssec-r10-correction/final-gates-summary-01.json) retains executed evidence and historical boundaries, including its then-pending independent closure. The subsequent closure report resolves that state without restamping the old summary. [Documentation-only consistency checks](../verification/dnssec-r10-closure/disposition-consistency-01.json) verify current identities, links, gate states and unchanged deliveries. No new native, full-suite or performance sweep is implied.

The original reviewed snapshot was 225 files (`dd9a3527335c0949086340c8e04c2d0ca51e206d7954debd01043492eb245068`) and HTML `9d18f50483f7106b55e744461d073742521df26f760149e8c9d9e6a4957b6625`; the historical section below is not relabelled as current proof. [Regression revision metadata03](../verification/dnssec-review-corrections/regression-test-revisions-03.json) retains actual failing-before attempts, retrospective before02, locator/harness repairs, removed incidental wording/copy/size assertions and the full-regression VM repair. Failed, cancelled and superseded runs remain attributable, not partial acceptance.

The preceding [corrections02 recheck](inputs/dnssec-corrections-02-recheck.html) independently verified the three corrections02 fixes; publisher-declaration and target-provenance were not checked by the earlier recheck and remain separately recorded. DNS-C04 and DNS-R09-focus-identity are one closed issue. R10 was preexisting in both earlier packets and is now independently closed. Corrections03 still changes only one source module and two tests; 158 other complete canonical cases and all steps/outcome/inspection identities remain unchanged, with 11 changed prefixes in the affected case.

## R10 inspection and preserved correction read order

Start with DNS09 / `cname-bogus-target`. At the cache boundary, inspect Recursive resolver / Result cache / `lab-dnssec09:alias-cache` / Complete cache record. At T=1792713600 it is secure, received and validated at T, remaining TTL 300, expiry T+300, signature/proof bound T+3600. The separate target remains bogus with a five-second failure cache and the application receives SERVFAIL/refuses the address. Rewind before creation, compare full/field/exact prefixes, and verify T+6 eligibility versus rejection at original expiry. [Literal before/after](../verification/dnssec-r10-correction/regression-revisions-01.json) and [four-case preservation](../verification/dnssec-r10-correction/semantic-delta-01.json) provide the bounded checks; no worksheet was modified.

1. DNS05 validating-stub custody, exact history and warm TTL/receipt boundaries: DNS-R01/R02/C02.
2. Actual DNS07/08 cache insertion/reuse plus exported ancestor-delegation, NSEC3 and DNAME authority: DNS-R03/R04.
3. DNS14 withdrawal/convergence/latest-old-cache cohorts and distinct capability/publisher/operator dimensions: DNS-R05/R06.
4. DNS05/06 rendered current-prefix query/response flags, retained error context, concrete retry IDs, full/field/exact rewind and reset: DNS-R07.
5. Full chapter text at 390px touch and genuine 200% browser zoom, including longest active DNS16 `dsync-notify-trigger`, disabled DNS02 `equivalent-presentation`, DNS05 warm transport label and legacy MCP09 controls: DNS-R08.
6. Ordinary DNS16 CSYNC NS/glue versus CDS/CDNSKEY DS intent and directly reachable RFC7477 source: DNS-R09. Focus the exact non-first CDNSKEY source6, advance the cursor and close its external popup; focus must remain on that same semantic source, not another link sharing the RFC URL.
7. Readable actors/verdicts with raw identifiers in details and policy-scoped insecure refusal, plus DNS12 selected fresh-keyset revalidation versus normal secure reuse: C01/C03.

No lesson/case, source event, field/exact replay row, protocol deadline or acceptance threshold is removed to obtain a pass. Retries use the existing canonical descriptor aggregation, bounded by the current source prefix; the rendered comparison retains every reached query event and its own flags.

The [authority index](contract-errata/README.md) describes all eight additive layers. The current eighth layer moves unchanged expected namespace values to the declared consumer shape; the parent-supplied schema mapping is not claimed to have been independently discovered. Original 354 inputs, all prior sealed layers and original 205 signature tuples remain unchanged. Added signed R04 material is separately catalogued; authoring independence is not OS sandboxing or native cryptography.

Retained corrections02 performance evidence covers all nine original keys in [Disposition04](../verification/dnssec-review-corrections/performance-dispositions-04.json) and five prior additional keys in [continuity](../verification/dnssec-review-corrections/performance-prior-correction-continuity-01.json). Its five material flags and zero variability flags remain unaccepted; non-reproduction is not owner closure. This is not a new R10 measurement or an unchanged-latency claim. G01, six inherited measured conditions, seven historical flags, six frozen-P0 variable cells, six sibling-origin omissions, 21 scoped P6 closures, four optional deferrals, N01 and conformance limits remain separate. Windows/PAM/search document version3 stays outside this correction.

## Scope and case authority

The [worker plan](inputs/worker-plan.html) defines the expansion. The exact [named-case manifest](scenario-manifest.json) is the authority for case IDs, defaults, source groups and per-lesson acceptance. There are **22 required lessons and 159 named cases**. Each default aliases its first named case; defaults are already included, not 22 additional cases. The following table is a navigation index, not a replacement case list.

| Plan | Runtime ID | Lesson | Named cases |
| --- | --- | --- | ---: |
| DNS01 | lab-dnssec01 | Follow a signed lookup | 4 |
| DNS02 | lab-dnssec02 | From zone data to signatures | 7 |
| DNS03 | lab-dnssec03 | Cross a delegation boundary | 7 |
| DNS04 | lab-dnssec04 | Explain a validation decision | 11 |
| DNS05 | lab-dnssec05 | Stub validation and the AD flag | 7 |
| DNS06 | lab-dnssec06 | Who validates when DNS is forwarded? | 8 |
| DNS07 | lab-dnssec07 | Prove that a name or type does not exist with NSEC | 7 |
| DNS08 | lab-dnssec08 | NSEC3 and Opt-Out | 6 |
| DNS09 | lab-dnssec09 | Wildcards and aliases across zones | 7 |
| DNS10 | lab-dnssec10 | Reuse validated cache data | 10 |
| DNS11 | lab-dnssec11 | Large answers, EDNS and encrypted transport | 6 |
| DNS12 | lab-dnssec12 | Refresh signatures and roll a ZSK | 6 |
| DNS13 | lab-dnssec13 | Roll a KSK or combined signing key | 6 |
| DNS14 | lab-dnssec14 | Change algorithms and digest policy | 8 |
| DNS15 | lab-dnssec15 | Install and maintain a trust anchor | 7 |
| DNS16 | lab-dnssec16 | Maintain parent DS with CDS/CDNSKEY | 10 |
| DNS17 | lab-dnssec17 | Bootstrap DS and operate automation safely | 8 |
| DNS18 | lab-dnssec18 | Operate multiple signers/providers | 7 |
| DNS19 | lab-dnssec19 | Publish and replicate a signed zone | 7 |
| DNS20 | lab-dnssec20 | Diagnose failure and recovery | 7 |
| DNS21 | lab-dnssec21 | Compact denial of existence | 7 |
| DNS22 | lab-dnssec22 | Private DNS, local anchors and conditional forwarding | 6 |
| Total | | | 159 |

## Inspecting a lesson

Open the delivered `auth-flow-studio-dnssec.html` beside `START-HERE.md`; it is deliberately not duplicated inside the ZIP. Alternatively serve the extracted `source/` directory and open [source index](../../index.html). A local reproduction build creates `dist/auth-flow-studio.html` inside that extraction. Choose the DNSSEC workspace, then the lesson by title and the named case using the variant control. Compare the selected case with the manifest before interpreting the trace. Case selection/reset is distinct from advancing an existing trace.

- **Full journey:** use Play/Pause and the timeline/step controls to inspect transfers, local computation, receipts and decisions in order. Journey explains the decision; Fields exposes message/RR structure; Crypto exposes covered bytes, keys, digests and numeric evidence. Inspect the decision and protocol state as well as the visible packet. A received RRset is not automatically authenticated or accepted.
- **Ordinary field:** select a meaningful field from the inspector/attribute controls and use **Replay path**. This follows that field across its actual operations, not a substitute full-journey animation. Use **Full journey** or **Return to full journey** to leave the filtered path.
- **Exact object:** select a concrete held object and its representation, inspect its exact identity/value and use **Replay exact history**. This follows that artifact generation rather than every object sharing a field name. Compare current holdings with historical knowledge: history alone does not imply present possession. Private signing material is not a transmitted DNS record.
- **Rewind:** seek backward in full, ordinary-field and exact-object replay. At equal canonical source prefixes, compare holdings, accepted evidence, validation owner, cache generation/namespace/deadline and application result, including prerequisites hidden by a filter. Do not compare filtered row numbers as though they were source-prefix numbers.
- **Chapters:** use lesson chapter controls to reach the authored phases, then inspect the surrounding state. Chapter navigation leaves a filtered trace and selects the chapter's first source step; it is not a fresh case or a new trust initialization. Unavailable chapters are not fabricated actions. Return to the full journey and reset before comparing another case.

Useful focused comparisons include DNS01 cold/warm/tampered answers, DNS05 trusted versus forged AD, DNS07/DNS08 denial completeness and Opt-Out, DNS09 wildcard signing owner versus receipt owner, DNS10 expiry, DNS13 rollover clocks, DNS15 interrupted hold-down, DNS16 rejected parent changes, DNS18 provider coordination, DNS21 CO cache context and DNS22 separate client trust contexts. These are navigation suggestions, not a reduction of the 159-case requirement.

## Authority and independence

The [29 source groups](source-groups.json) map claims to primary RFC/IANA sources, including later updates and individually applicable errata. The [source ledger](source-ledger.json), [resolution ledger](source-ledger-resolution.json), [publication ledger](source-ledger-publication.json), [resolution dispositions](source-dispositions-resolution.md) and [publication dispositions](source-dispositions-publication.md) preserve capture and interpretation boundaries. A source index or retained HTTP failure is not successful normative-source content.

The [original freeze](contract-freeze.json) and 354 original inputs remain immutable. Eight additive layers end with cache namespace location. **Current expected input is [effective-cache-namespace-location/worksheet.json](contract-errata/effective-cache-namespace-location/worksheet.json)**, SHA256 `d88705d909df1043d7a5c0295e35272afae6ab01af73aac7faa766c5061f164d`, 6,731,500 bytes. [Eighth check](../verification/dnssec-review-corrections/independent-eighth-overlay-check-01.json) preserves its original scope. Current R10 Source01/Emitted01 guard all 435 files unchanged. R10 uses literal independent cache-state expectations; no original checkpoint or ninth layer was needed. Archive/checksum/offline-build integrity remains separate.

Input auditors report no production/evaluator access. Corrections were additive after production work existed, not retroactively represented as pre-evaluator evidence or as OS-sandboxed work. An evidence reference alone establishes neither receipt nor authentication, checker invocation, possession or validation ownership.

The [original numeric fixture identities](numeric/FINAL-FIXTURE-IDENTITIES.json), [post-freeze numeric catalog](numeric/post-freeze-contract-errata/POST-FREEZE-CATALOG.json) and [completion numeric catalog](numeric/post-freeze-completion/POST-FREEZE-COMPLETION-CATALOG.json) are independent numerical authorities. Failed/withdrawn attempts remain distinguishable from active evidence. Public application projections omit fixture-generation private scalars and TSIG secret references. The numeric runner checks source arithmetic/reference matching against sealed independent inputs; independently captured pinned Python/OpenSSL producers are separate evidence, not production browser cryptography.

A Source-generated canonical-prefix reference is **projection equivalence data, not an independent expected-outcome oracle**. Independent worksheet checkpoints supply the outcome boundary. Exact Source/emitted equality does not independently validate the protocol rules, nor replace native UI or human accessibility review.

## Historical identified proofs for the old reviewed candidate

Old reviewed standalone:5,202,353 bytes, SHA256 `9d18f50483f7106b55e744461d073742521df26f760149e8c9d9e6a4957b6625`; old225-file source: `dd9a3527335c0949086340c8e04c2d0ca51e206d7954debd01043492eb245068`. See [candidate13 identity](../verification/dnssec-expansion/candidate-13-input-identity.json). All below results retain historical identified-byte scope, not corrected-source acceptance.

- [Source11](../verification/dnssec-expansion/contract-source-11/status.json) and [emitted07](../verification/dnssec-expansion/contract-emitted-07/status.json): all 159 cases, 1,059 independent checkpoints and 26,935 canonical prefixes pass. Emitted07 completes 8,746 actual UI positions, 2,385 seeks and 159 resets in 508.24 seconds within the unchanged 900-second deadline.
- [Candidate13 Source/emitted equivalence](../verification/dnssec-expansion/candidate13-source-emitted-equivalence.json): all 159 complete canonical case records match exactly. [Touch-repair Source equivalence](../verification/dnssec-expansion/touch-popup-source-equivalence.json) proves unchanged complete case references before/after the input-only fix.
- [Numeric09](../verification/dnssec-expansion/numeric-source-09/numeric-status.json): 480 checks pass for candidate13.
- [Chapter/layout03](../verification/dnssec-expansion/native-layout-03/native-status.json): all 858 cells pass, including 786 chapter/internals/loading-mode states and 66 real inspections. [First viewport03](../verification/dnssec-expansion/native-first-viewport-03/status.json): all 24 initial animation-area viewports pass with unchanged identities.
- [Full/field/exact touch smoke](../verification/dnssec-expansion/native-touch-journey-after-01/status.json): 12 actual forward/backward replays across 4 theme/motion contexts, reset, F2 and Escape focus return pass. This focused regression does not replace the complete native matrix.
- [Complete native interaction04](../verification/dnssec-expansion/native-interaction-04/native-status.json): all 288 required task cells and 312 total cells pass across 12 tasks, three loading modes, both themes, desktop/touch and both motion preferences. [Native acceptance index](../verification/dnssec-expansion/native-current-acceptance.json) distinguishes this representative UI coverage from exhaustive semantic coverage.
- [Genuine headed zoom05](../verification/dnssec-expansion/native-zoom-05/native-status.json): all 72 required tasks and 76 total cells pass across eight tasks, three loading modes and real 100/150/200% Chrome zoom. [Zoom acceptance](../verification/dnssec-expansion/native-zoom-current-acceptance.json) binds actual DPR, visual-viewport scale, trusted controls and bounded screenshots.
- [Fresh performance impact](../verification/dnssec-expansion/performance-impact-summary.json): collection complete, 36 sample groups, 27 comparison cells, 146 unchanged source checks and zero collection errors. **Eight material regressions and one variability flag remain open**, not waived. The separate supplement completes 108 actions in 18 latency contexts and nine separately instrumented diagnostic contexts.
- [Final executed preservation gates](../verification/dnssec-expansion/final-gates-summary.json):1,935 passing tests across116 files;317 compiled/held choices;921 Core configurations;86 interaction cases;64,784 equal-cursor comparisons;31 expansion and nine JWT verification-only vector cases. These guards passed on the historical reviewed candidate, not the corrected snapshot. Raw per-file logs, compiled/held records and cryptographic output remain attributable.
- [Candidate13 case outcomes](../verification/dnssec-expansion/per-case-outcomes-candidate13.json) and [fragment consolidation](../verification/dnssec-expansion/review-fragment-consolidation-candidate13.json): 159 exact final-outcome comparisons and 636 exact raw-fragment/aggregate checks. These are derived navigation/inventory proofs, not new executions or independent oracles.
- [Empirical zoom-input repair](../verification/dnssec-expansion/native-zoom-pointer-coordinate-repair.json) and [native pointer probe](../verification/dnssec-expansion/native-coordinate-probe-02/status.json) distinguish Chrome's file-hash pointer-scale bug from application behavior. Reapplying genuine Chrome zoom restores input coordinates; zoom05 now passes the unchanged complete matrix with actual DPR, visual viewport, bounds and exact values checked.
- [Touch field activation before](../verification/dnssec-expansion/native-field-tap-before-01/status.json) and [identical native smoke after](../verification/dnssec-expansion/native-field-tap-after-01/status.json): one activation starts ordinary replay on both desktop and touch after the fix. Touch compatibility mouseover previously placed help over the field before click.
- [Complete interaction03 disposition](../verification/dnssec-expansion/native-interaction-03-disposition.json): all 144 desktop task cells passed; all 144 touch task cells failed at ordinary-field activation. This failed matrix remains failed, not partial acceptance or a driver-error waiver. The shared help fix preserves mouse hover, keyboard-visible focus and explicit F2/Escape; complete candidate13 interaction04 is the passing replacement.

- **Historical build12 proofs, not candidate13 acceptance:**
- [Source10 status](../verification/dnssec-expansion/contract-source-10/status.json): all 159 cases, 1,059 independent checkpoints and 26,935 canonical prefixes pass for the corrected grid.
- [Numeric-source-08 status](../verification/dnssec-expansion/numeric-source-08/numeric-status.json):480 historical checks pass against build12.
- [Complete chapter/layout status](../verification/dnssec-expansion/native-layout-02/native-status.json): all 858 cells pass, including 786 chapter/internals/loading-mode states and 66 real object/help/payload inspections.
- [Transport-grid source equivalence](../verification/dnssec-expansion/transport-grid-source-equivalence.json): all 159 canonical case records and 26,935 state/custody prefixes remain exactly equal before/after the position-only correction.
- [Emitted06 status](../verification/dnssec-expansion/contract-emitted-06/status.json): all 159 cases, 1,059 independent checkpoints and 26,935 canonical prefixes pass in 481.91 seconds within the unchanged 900-second deadline. The unchanged emitted IIFE completed 8,746 actual UI positions, 2,385 seeks and 159 resets.
- [Current Source/emitted equivalence](../verification/dnssec-expansion/current-source-emitted-equivalence.json): all 159 complete canonical case records match exactly, including outcomes, IDs and field/exact inspections.
- [Initial animation-area viewports](../verification/dnssec-expansion/native-first-viewport-01/status.json): all 24 real-navigation cells pass across three loading modes, both themes and desktop/touch. The first physical participant is fully visible below sticky controls without changing the initial horizontal graph view.
- [Retained interaction02 disposition](../verification/dnssec-expansion/native-interaction-02-disposition.json) distinguishes48 short-touch driver failures from browser-closed interruption cells. The [trusted touch repair smoke](../verification/dnssec-expansion/native-touch-drag-smoke-01/status.json) passes48exact seeks across both themes and motion settings without increasing correction bounds. It does not replace the complete288-cell interaction matrix.
- [Current case outcome index](../verification/dnssec-expansion/per-case-outcomes-current.json) and [fragment consolidation](../verification/dnssec-expansion/review-fragment-consolidation-current.json) preserve159 exact final-outcome comparisons and636 fragment-to-complete-aggregate checks. They are derived navigation/inventory proofs, not new executions or independent expected outcomes.
- [Emitted05 timeout disposition](../verification/dnssec-expansion/emitted-contract-05-timeout-triage.json) preserves the earlier incomplete103-case diagnostic attempt. It is not promoted to acceptance.
- [Pre-grid emitted04 status](../verification/dnssec-expansion/contract-emitted-04/status.json) and [pre-grid Source/emitted equivalence](../verification/dnssec-expansion/source-emitted-equivalence.json) retain their earlier identified-byte scope only. They are not promoted into current-candidate standalone acceptance.

These are recorded results, not executions performed by writing this guide. Failed, timed-out and earlier-grid runs remain historical evidence, not partial acceptance. No timeout, correction bound or performance threshold was raised. User/system processes were not terminated to obtain a pass. Native, performance and final-regression records identify their own complete runs; the packager separately verifies exact inventory/member bytes, current source identity and an extracted-source offline rebuild. Packaging integrity and measured performance collection do not supply Astra, human accessibility or release-owner acceptance.

## Portable reproduction in a separate extraction

Use a fresh source-ZIP extraction, not the frozen working candidate. Run from its repository root with Bun installed (the repository pins Bun in its workflows). The application build requires no dependency installation, Git checkout metadata or network fetch. Node/npm are not required. The source ZIP must include the build inputs and verification inputs, not only application modules. The following are reviewer commands, not claims that they have been executed here.

```sh
bun build.mjs --source-version
mkdir reviewer-reproduction
bun tools/verification/check-dnssec-contract.mjs --root . --worksheet docs/dnssec-expansion/contract-errata/effective-cache-namespace-location/worksheet.json --out reviewer-reproduction/source --mode source
bun tools/verification/check-dnssec-contract.mjs --root . --worksheet docs/dnssec-expansion/contract-errata/effective-cache-namespace-location/worksheet.json --out reviewer-reproduction/emitted --mode emitted
bun tools/verification/check-dnssec-numeric.mjs --out reviewer-reproduction/numeric
```

Choose a new parent name on each reproduction. The contract runner requires an existing output parent and a nonexistent output directory; it refuses overwrite. Numeric output must also be new. Run these serially, without competing browser/performance/regression jobs. Emitted mode requires the preceding build and executes the emitted application through the DOM harness; it is not a native-browser conformance run. Read each output's `status.json` (numeric: `numeric-status.json`) and failures, not just process startup or a partial `journal.jsonl`. The contract outputs include canonical-prefix references for equivalence comparison, not independent oracle creation. Reproduction can be substantial and is separate from reading the delivered proofs.

To reproduce/check the additive authority transforms without modifying originals, use the existing checks in order:

```sh
bun tools/verification/apply-dnssec-contract-errata.mjs --check
bun tools/verification/apply-dnssec-completion-errata.mjs --check
bun tools/verification/apply-dnssec-receipt-errata.mjs --check
bun tools/verification/apply-dnssec-client-context-errata.mjs --check
bun tools/verification/apply-dnssec-cache-kind-errata.mjs --check
bun tools/verification/apply-dnssec-review-corrections-errata.mjs --check
bun tools/verification/apply-dnssec-mixed-path-policy-errata.mjs --check
bun tools/verification/apply-dnssec-cache-namespace-location-errata.mjs --check
bun tools/verification/freeze-dnssec-contract.mjs --check
```

The build emits `dist/auth-flow-studio.html`, self-contained for offline `file:` use. Source HTTP needs the local source files served together; external reference links are optional reading, not lesson runtime dependencies. Source-ZIP offline build behavior does not imply every independent numeric producer or native-browser toolchain is bundled or runnable offline.

### Display version precedence

The [version contract](version-contract.json) and [build source](../../build.mjs) define this precedence:

1. `--source-version` forces the source HTML `data-build-version` marker, currently **1.0**.
2. Otherwise `AUTH_FLOW_STUDIO_VERSION` supplies an explicit label.
3. Otherwise `GITHUB_REF_TYPE=tag` selects `GITHUB_REF_NAME`.
4. Otherwise the source HTML marker supplies **1.0**.

A leading `v` before a numeric version is removed and the label is escaped as data. The package metadata version is not this display-version authority. Plain `bun run build` can inherit explicit/tag environment inputs; `bun build.mjs --source-version` is the deterministic source-version command even inside a tag environment. Tag injection is not a runtime GitHub query, Git requirement or proof of publication. The historical [footer smoke](../verification/dnssec-expansion/footer-version-02/footer-version-status.json) and [input binding](../verification/dnssec-expansion/footer-version-02/current-candidate-binding.json) record five builds and six native UI cases in the isolated candidate13 clone. Their byte-identical default-build claim identifies the old reviewed HTML, not a new tagged-footer run on current bytes. Current source-version HTML is separately bound by Inputs04 and package rebuild integrity. Live GitHub workflow execution/publication is not claimed.

## Boundaries that remain in force

The inherited [21 scoped closures](../verification/p6c-mcp01-closure/independent-closure-status.json) remain closed within their reviewed scope. They are neither reopened by this guide nor promoted into independent DNSSEC acceptance. [Inherited release gates](../verification/p6c-mcp01-closure/current-release-gates.json) and the current open-gates record preserve their limits.

Manual **G01 remains open**: DOM/native checks, screenshots, touch and zoom cannot establish human speech/comprehension acceptance. Its inherited and additional DNSSEC journeys remain in open-gates. Historical measurements retain their own identities: original expansion eight material/one variable; corrections01 six material/six variable; reviewed corrections02 five material/zero variable. R10 was not remeasured. Every retained original/additional key remains accounted for without acceptance or waiver; six prior measured conditions, seven historical flags and six frozen-P0 variation cells remain unchanged.

No live DNS lookup, BIND/Unbound/Knot/PowerDNS, signer, resolver, registry, transfer server or DoT interoperability is claimed. Authored fixtures and numerical QA are not installed-service, native cryptographic implementation, cross-engine or general platform conformance. Native evidence retains its stated task/loading scope. DNS-R10 is independently closed only for the identified corrections03 candidate; do not extend that closure to human/release acceptance, an owner waiver, commit, push, deployment or publication authorization.
