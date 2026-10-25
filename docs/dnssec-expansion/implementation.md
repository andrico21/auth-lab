# DNSSEC independently closed correction handoff

## Review and publication

Astra's [R10 closure review](inputs/dnssec-r10-closure-review.html), dated 25 October 2026, SHA256 `b60da5cb2ffa32fd766168ebd214eaca92626a2e6da2e700a64c424771b96407`, **independently closes DNS-R10 for corrections-03 and identifies no further required correction**. Its [performed closure disposition](corrections/independent-r10-closure-disposition.json) preserves DNS-R01 through DNS-R09, C01-C03, one **DNS-C04 = DNS-R09-focus-identity** issue and the two separately verified semantic follow-ups. The preceding [corrections02 recheck](inputs/dnssec-corrections-02-recheck.html) remains an unchanged historical report, not the latest pending verdict.

**Required DNSSEC correction work is independently closed for the exact candidate below.** The retained worker suite records 1,996 passes and zero failures; delivery inventory, checksums, extracted offline build and independent relocation remain separate successful integrity records. This documentation-only update changes no source/test/build or old evidence. Human G01, performance-owner acceptance, overall release acceptance and publication authorization remain open; no commit, push or deployment is performed.

| Identity | Corrected working candidate |
| --- | --- |
| Base checkpoint | `c99ebd6fec16e01dc9fef6c9590d534b8f1daf85` |
| Branch | `expansion/dnssec` |
| Application/test inputs | 231 files, SHA256 `1b5a3350e5e2b778efb52dccb46473e197df1ec202e3cd202618540c1988f234` |
| Standalone | 5,243,123 bytes, SHA256 `5e13671a57cfb0d4c827b4eb6af52fc6d0d53f48c5816c8e7bcc423e54022f54` |
| Current worksheet | Eighth layer, SHA256 `d88705d909df1043d7a5c0295e35272afae6ab01af73aac7faa766c5061f164d` |

[R10 inputs01](../verification/dnssec-r10-correction/candidate-inputs-01.json) binds the unchanged 231-file source/test map and 138 verification inputs. The reviewed product delta remains one application module and two existing test files. Corrections02 was `f9876de1...` / `0b1c9bdb...`; earlier packets retain their actual identities. **Corrections03 is now independently closed within DNS-R10 scope**, not a new committed checkpoint. Its delivered documentation and checksums remain frozen; current repository closure records are separate.

## Implemented corrections

The [response ledger](corrections/response-ledger.json) records source changes, consumer invariants, before/after attribution, current evidence and independent-closure boundaries per finding.

| Finding | Implemented behavior |
| --- | --- |
| DNS-R01 | Independent stub creates and retains its own evidence/cache in `stub-public-v1`; the fetch-only resolver gains no anchor or unsent verdict. Exact history and rewind preserve custody. |
| DNS-R02 | Actual carried RRset and ordinary RRSIG occurrences determine outgoing TTL metadata. Warm 240 and NTA 299 preserve signed Original TTL/RDATA. Actual target namespace caches use their own RRset/signature tuple; unsigned targets report null signature TTL and Original TTL rather than inheriting signed-alias metadata. |
| DNS-R03 | Actual new validated NXDOMAIN entries declare negative kind and use reusable name/class keys. NODATA, compact denial, failures, namespaces and expiry remain distinct. |
| DNS-R04 | Exported denial evaluator enforces ancestor NS/no-SOA authority and DNAME subtree limits, including signed NSEC3 controls. DS absence at a cut does not authorize child A/AAAA/CNAME denial. |
| DNS-R05 | Old-DS withdrawal, convergence, latest old-containing receipt and cache drain precede child DNSKEY/signature retirement. Late-old 13-only, fresh 13-only and dual-capable evaluator cohorts are checked. |
| DNS-R06 | Registry requirements, illustrated capability, arithmetic fixture coverage, publisher policy and operator acceptance remain separate. All eight DNS14 sessions now permit the declared publisher algorithms 13/15 through a lesson-local override; shared modern signing stays 13 and operator, validation and digest policy remain unchanged. Mixed paths retain coexisting constraints. |
| DNS-R07 | DNS05/06 show canonical query/response AD/CD/DO, delivery/RCODE, checking/reliance owners and all actual reached query identities. Prefix-bounded retries remain 1/2/3; rewind/reset invent no future receipt or response to an undelivered local attempt. |
| DNS-R08 | Chapter-specific wrapping/bounded width preserve full labels independently of diagram scrolling. Actual 390px touch and genuine 200% checks include all 22 defaults, three longest active/disabled variants and legacy MCP controls. |
| DNS-R09 | Ordinary DNS16 directly explains CSYNC NS/glue versus CDS/CDNSKEY DS intent and exposes RFC7477 through existing field metadata. Stable field/source-index identity preserves the exact focused link during redraw even when three links share one href. Parent authentication/publication remains separate. |
| DNS-R10 | Independently secure alias cache uses its own received tuple, existing successful validation witness timestamp and signature-bound proof deadline. Remaining TTL is 300 at T, original expiry T+300; the target's independent failure remains five seconds and the overall result remains SERVFAIL/refusal. |

C01 adds readable actors/verdicts with raw identifiers in details; authenticated unsigned delegation is insecure, not automatically forged, and secure-only refusal is explained only when the current application result reaches it. C02 separates fresh authority receipt, cache reuse, stub delivery and application use. C03 explicitly declares DNS12's selected fresh-keyset revalidation policy, ordinary unexpired secure-cache reuse and the fact that DNSKEY withdrawal does not instantly revoke accepted cache.

Two bounded integration repairs are included: compilation includes the new public review fixture before its consumers, with actual compiled boot/catalog smoke in CI; an already user-closed index skips rendering and synchronously refreshes current contents on reopening. Startup remains default-open, every field/control remains available, and no extra cache was added.

The prior [corrections02 disposition](corrections/independent-recheck-02-disposition.json) records three verified fixes without claiming the preceding review covered the two semantic defects. DNS-C04 and the source-focus worker alias denote one issue. R10 was preexisting in corrections01/02, not introduced by those three fixes; its subsequent [independent closure](corrections/independent-r10-closure-disposition.json) is now recorded separately.

Content remains 22 lessons and 159 named cases in five families. Defaults alias named cases rather than adding cases. The reviewed footer used **Kirill**; the user subsequently authorized the sole source-text correction to **Kirill Andrienko** and publication without retesting. Display version **1.0**, profile/repository links and [version precedence](version-contract.json) are unchanged. `--source-version` remains the byte-reproducible source build.

## Executed verification

Retained worker evidence remains under `docs/verification/dnssec-r10-correction/`; its [final summary](../verification/dnssec-r10-correction/final-gates-summary-01.json) keeps the original executed records and then-pending closure state. The later closure report resolves that state without rewriting it. [Closure-only validation](../verification/dnssec-r10-closure/disposition-consistency-01.json) checks current identities, links and gate consistency; no unrelated native, protocol, full-regression or performance run is requested.

| Check | Observed result | Evidence |
| --- | --- | --- |
| Complete source | 159/159 cases; 1,068 checkpoints; 27,031 prefixes; 32,128,966 assertions; 354 originals preserved | [R10 Source01](../verification/dnssec-r10-correction/source-contract-01/status.json) |
| Complete emitted app | 159/159 cases; 32,170,934 assertions; 8,766 actual UI positions; 2,385 seeks; 159 resets; unchanged 900-second deadline | [R10 Emitted01](../verification/dnssec-r10-correction/emitted-contract-01/status.json) |
| Exact complete case equality | All 159 source/emitted case records equal without exclusions; 158 reviewed case records unchanged, only 11 bogus-target prefixes differ | [Equivalence01](../verification/dnssec-r10-correction/source-emitted-equivalence-01.json), [reviewed delta](../verification/dnssec-r10-correction/reviewed-source-case-delta-01.json) |
| Full regression | 1,996 pass, 0 fail, 121 files; exact input identity unchanged and original 900000ms per-test timeout | [R10 regression01](../verification/dnssec-r10-correction/regressions-01/held-objects-regression-status.json) |
| Numeric/source bindings | 502 checks; 33 keys, 181 RRsets, 212 signatures, 23 DS, 29 NSEC3 | [R10 Numeric01](../verification/dnssec-r10-correction/numeric-01/numeric-status.json) |
| Narrow native inspector | Two real headless Chromium source HTTP/offline-file inspectors; alias 300/T/T+300, target five-second failure, application error; genuine offline exact-history/rewind | [Native inspector01](../verification/dnssec-r10-correction/native-inspector-01.json), [runtime mode](../verification/dnssec-r10-correction/native-runtime-01.json) |
| Focused/actual compiled consumers | 62 affected source/lifetime tests across six files; ten actual compiled-IIFE UI tests | [Source after02](../verification/dnssec-r10-correction/focused-after-02.json), [compiled01](../verification/dnssec-r10-correction/compiled-teaching-01.json) |
| Compiled/held preservation | 317 compiled/held choices; 921 Core configurations; 86 interactions; 64,784 equal-cursor comparisons | [R10 compiled01](../verification/dnssec-r10-correction/compiled-smoke-01/compiled-bundle-status.json), [held01](../verification/dnssec-r10-correction/held-01/held-objects-source-status.json) |
| Retained legacy vectors | Earlier 31 expansion / nine JWT records remain attributed; unchanged numerical inputs, not a new R10 vector execution | [Earlier expansion03](../verification/dnssec-review-corrections/legacy-crypto-03.json), [earlier JWT03](../verification/dnssec-review-corrections/legacy-jwt-crypto-03.json) |

Canonical reference case arrays are compared without normalization/exclusions. Their headers differ only by source/emitted mode. Raw status records deliberately retain mode-specific assertion and actual-UI counters; they are not claimed byte-identical.

The two current [parent-viewed native captures](../verification/dnssec-r10-correction/native-visual-inspection-01.json) show the corrected actual resolver Result cache in source HTTP and the offline standalone, using genuine scenario/case/timeline/inventory controls. The offline native exact-history path retains the same cache values; returning to initial full history removes current cache state/custody. Status text read from possibly hidden rewind DOM is not claimed visible. No full native/mobile/zoom/performance sweep was repeated for this metadata fix.

Historical Native04's 60 cells/978 bounds and six exact non-first CDNSKEY contexts were bound to corrections02 and audited by Astra. They are not relabelled as new R10 executions. Current source/compiled focus controls remain in the ten-test UI suite. Earlier blank/wrong-target/help-obscured captures keep their disclosed limits; no human G01 or platform-conformance claim follows.

## Authority, R10 regression and historical provenance

The [original freeze](contract-freeze.json), all 354 original inputs and all 435 current authority inputs remain unchanged. [Eight additive layers](contract-errata/README.md) are preserved exactly; R10 adds no ninth layer and rewrites no checkpoint or numeric tuple. Its independent expected alias/target values are literal regression assertions from the supplied review and existing per-entry signature-deadline meaning. The parent-supplied earlier cache namespace mapping, after-production authoring and absence of OS-sandbox/preimplementation guarantees retain their original limits.

R04's [additional catalog](numeric/review-corrections/PUBLIC-CATALOG.json), SHA256 `7f2eba596704ba73bddc3d20a1616b8ecce9cd6b8b4a57229df0a511b1c43f28`, adds seven independently signed tuples and eight NSEC3 references without replacing the original 205 signatures. Its independent structured report records 105 byte/hash predicates and seven OpenSSL verifications, not verbatim stdout or browser/live-service crypto. Public projections exclude private generation scalars and TSIG secret references.

R10's two new regressions [failed before the product fix](../verification/dnssec-r10-correction/focused-before-01.json), 0 pass / 2 fail, at contradictory cache values and rendered validation time. After explicit replay-endpoint presence strengthening, [final identical test bytes replayed against the exact reviewed product](../verification/dnssec-r10-correction/final-regression-attribution-01.json) also fail 0/2. This second run is explicitly retrospective, not invented before-fix chronology or the full historical test identity. Final source62/compiled10 and full1,996/0 pass. Eligibility at T+6/T+299 and rejection at T+300 never renew original receipt or stored creation-clock metadata.

[Four-case before/after preservation](../verification/dnssec-r10-correction/semantic-delta-01.json) proves the entire target and aggregate caches, wire packets, signed/public tuple representations, source structure and application results remain exact for secure/insecure/bogus CNAME targets and DNAME. Only `remainingTtl`, `validatedAt` and `authenticatedProofDeadline` of the bogus-target alias change. The proof deadline is the alias signature's T+3600 bound, not its effective T+300 cache expiry. Validation time comes from the existing primary alias evidence, without another check or exchange.

[Corrected before02](../verification/dnssec-review-corrections/focused-before-02/status.json) observed 12 pass/24 fail on reviewed production with four corrected test overlays. It is retrospective, not fabricated chronological timing or nine independent closure counts. [Revision metadata03](../verification/dnssec-review-corrections/regression-test-revisions-03.json) retains locator/harness corrections and removal of incidental wording/copy/size assertions instead of re-pinning them.

Historical failed/partial evidence remains intact: missing compiler module, retry-descriptor failures, cancelled contract runs, VM-only missing clone APIs and native input/zoom probes. Their original identities, limits and repairs are retained in corrections01/02. Prior worker full totals were 1,987/1, then 1,988/0 and corrections02's 1,994/0; these are not new R10 runs. The earlier source-only followup-compiled01 is not an emitted proof. Native04's observed physical zoom workaround remains identified historical evidence, not a product/browser repair claim.

## Performance dispositions

The retained [comparison02](../verification/dnssec-review-corrections/performance-comparison-02/next-performance-status.json) measured the reviewed corrections02 source `f9876de1...` and HTML `0b1c9bdb...`: 36 sample groups, 27 cells, 146 unchanged guards and zero collection errors. **No R10 timings were collected and no unchanged-latency claim is made.** [Disposition04](../verification/dnssec-review-corrections/performance-dispositions-04.json) covers all nine original keys; [prior-correction continuity](../verification/dnssec-review-corrections/performance-prior-correction-continuity-01.json) retains five additional earlier keys. All remain unaccepted owner conditions.

| Key | Scope | Baseline median ms | Measured corrections02 median ms | Delta ms | Measured flags |
| --- | --- | ---: | ---: | ---: | --- |
| source-http/closed/selection | Original | 390.02 | 255.97 | -134.05 | not reproduced |
| source-http/closed/replay-start | Original | 125.63 | 194.44 | +68.81 | material |
| source-http/open/playing-filter | Original | 132.15 | 123.53 | -8.62 | not reproduced |
| standalone-http/default/startup | Original | 3002.02 | 3832.38 | +830.35 | material |
| standalone-http/closed/selection | Original | 387.44 | 237.80 | -149.65 | not reproduced |
| standalone-http/closed/replay-start | Original | 126.88 | 194.43 | +67.55 | material |
| standalone-file/default/startup | Original | 2957.44 | 3853.15 | +895.71 | material |
| standalone-file/closed/selection | Original | 352.76 | 221.30 | -131.46 | not reproduced |
| standalone-file/closed/replay-start | Original | 138.82 | 194.11 | +55.29 | material |
| source-http/default/startup | Prior added | 2920.43 | 3581.96 | +661.54 | not reproduced |
| source-http/open/idle-filter | Prior added | 127.33 | 138.67 | +11.34 | not reproduced |
| source-http/open/selection | Prior added | 840.17 | 774.05 | -66.12 | not reproduced |
| source-http/open/replay-start | Prior added | 129.27 | 111.10 | -18.18 | not reproduced |
| source-http/closed/playing-filter | Prior added | 121.85 | 123.97 | +2.12 | not reproduced |

These five measured material conditions remain open; the reviewed collection had zero variability flags. Four original and five prior additional flags were not reproduced in that collection, not owner-closed or waived. Unflagged does not mean zero cost: measured source-HTTP startup was still 661.54ms higher. None of these records is restamped as a new R10 measurement. Owner `andrico21` must explicitly disposition remaining costs and earlier measurement conditions; functional verification does not accept them.

[Pre-change profiles](../verification/dnssec-review-corrections/performance-profile-interpretation-01.json) support avoiding closed-index render work. They did not isolate the entire startup or remaining replay cost; no blanket root cause is asserted. Profiling wall time is not latency evidence, and default-open startup was not hidden to improve results.

## Scoped closure, remaining external conditions and delivery

1. Required DNSSEC correction work is independently closed for corrections03. Original nine scoped closures, C01-C03, one C04 focus issue and separately verified semantic follow-ups remain preserved; no new required correction was identified.
2. Actual-human G01 speech/comprehension remains open. Native screenshots, keyboard/touch and zoom cannot perform it.
3. Retained performance conditions await explicit owner decisions; R10 was not remeasured and no inherited condition is waived.
4. Preserve six inherited measured conditions, seven historical flags, six frozen-P0 variable cells and six sibling-origin omissions.
5. Preserve 21 scoped P6 closures without reopening/broadening them, four optional deferrals, N01 and live/native/cross-engine limits.
6. Scoped independent review is successful and the user has now authorized commit and push, including the footer-name correction without retesting. This is not human G01 acceptance, overall release acceptance or a performance-owner waiver.

[START-HERE](START-HERE.md) records the performed closure and unchanged reviewed delivery; no replacement packet is needed. [Reviewer navigation](reviewer-navigation.md) retains lesson IDs and reproduction commands. Package and relocation records establish integrity, not release acceptance. The separate Windows protection/PAM/hidden-search-tags version 3 assignment is next, but its authoritative plan file is absent from the supplied artifacts and checkout documentation; it must be supplied before implementation.
