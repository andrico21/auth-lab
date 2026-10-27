# Windows protection/PAM: accepted candidate-07 closure and release-gate handoff

The [supplied independent closure review](../verification/windows-protection-expansion/closure-01/reviewed-inputs/closure-review.html.input.txt) closes WP-R06-B on exact candidate-07, completing WP-R06. The immutable [candidate-07 closure authority](corrections/candidate07-closure-status.json) preserves WP-R06-A and the six earlier whole-finding closures: WP-R01, WP-R02, WP-R03, WP-R04, WP-R05 (original PAM01 scope) and WP-R07. **All seven whole findings are closed within reviewed scopes**, not universally re-certified at current bytes. Functional review is complete; release acceptance remains unresolved. Read [current progress](current-progress.json), [open gates](open-gates.json) and the [implementation handoff](implementation.md) before owner disposition. No further Astra corrective upload or new packet is required, and no publication is authorized.

## Accepted immutable candidate-07 siblings

The accepted folder remains available for owner checks at `C:\TempPersistent\oauth-lab\auth-flow-studio-windows-protection-review\candidate-07-compact`:

1. `auth-flow-studio-windows-protection-source-and-review.zip`
2. `auth-flow-studio-windows-protection.html`
3. `START-HERE.md`

Keep all delivered siblings byte-unchanged, including `SHA256SUMS.txt` and `packaging-status.json`. The three-file list records the accepted submission, not a request for another upload. Candidate-06 and all earlier packets remain byte-unchanged historical evidence. The repository metadata now records closure separately; it does not reseal or replace the accepted packet.

## Exact bytes and authority

| Binding | Value |
|---|---|
| Published parent | `ae9dffe2da2bca33c01daee1eaacfcbedfc95aa0`; this is a working-tree candidate, not a new commit |
| Current canonical app/test files | 256; SHA256 `b743e4fc4cc8f9a804c55c1d8b2f8a0f845fab9caf94bb66d0d75c4a3396b825` |
| Current standalone | 5,583,631 bytes; SHA256 `9ff001b8d035a90e732a9bea8ccce944226e8c9a81729ab224d3b4b75fdb6694` |
| Supplied candidate-07 closure review | 108,038 bytes; SHA256 `c9a780fa332b9ff3e008b9396dcf7d02c4962f550951dc502076e99f2491fcd3` |
| Supplied candidate-05 review | 94,918 bytes; SHA256 `029ec2870e00fa331560826b484c3c0d6acd8bdf7b243d000105b050d20bd8e9` |
| Reviewed candidate-05 | 255 canonical files; source `0031e25c8f64de6dd986370c3b3176b71c2fd93a774ec066f0926d17c16cabb0`; HTML `ca9fbb47b3de9a565911f44fc29ba319076e85feace235ba82cf6c20bb3a88cb` / 5,582,983 bytes |

Canonical identity is SHA256 of sorted relative path + NUL + exact bytes + NUL, including every app, asset and test input. The complete per-file map is in `corrections-04/current-inputs-02.json` under the verification directory below. The earlier candidate-05 review remains at `corrections-04/reviewed-inputs/candidate05-review.html.input.txt`; the current closure copy is linked above under `closure-01/reviewed-inputs/closure-review.html.input.txt`.

The original version-3 plan (`8e66f18b60f352b4d3020af11369b829828cb473cbc8edcccacbe104abc8fc8d`), candidate-02 review and candidate-04 recheck remain authoritative where not superseded. The accepted candidate-07 footer remains **1.0 / Kirill Andrienko / https://github.com/andrico21/auth-lab** in its immutable artifact. The current user-authorized release is **1.1**, with no `v` prefix; its separate [publication record](publication-1.1.json) binds the new display marker without changing application or test modules.

## Read order

Start with the [candidate-07 closure authority](corrections/candidate07-closure-status.json), [exact closure copy](../verification/windows-protection-expansion/closure-01/reviewed-inputs/closure-review.html.input.txt), [current progress](current-progress.json) and [open gates](open-gates.json). The closure authority records exact accepted bytes and preserves the older candidate-05 and recheck authorities rather than replacing their scoped decisions.

The following extracted-packet read order is historical submission context, not an active request to re-close B. Paths are relative to extracted `source/`; verification shorthand means `docs/verification/windows-protection-expansion/corrections-04/`. ZIP-root `review/REVIEWER-PROBES.md` describes the retained supplied/adapted scripts, diffs, prerequisite and four original worker outputs; it does not contain the later independent closure receipt.

1. `docs/windows-protection-expansion/corrections/candidate05-closure-status.json`: historical immutable independent authority, reviewed bytes, A closed, B core verified and classification then open. The older `recheck-closure-status.json` remains the earlier six-closure authority; the new candidate-07 authority supersedes only the pending B status.
2. `docs/windows-protection-expansion/corrections/candidate06-changed-file-index.json`, `candidate06-product.patch` and `candidate06-qa-producers.patch`: the bounded delta from candidate-05, exact before/final identities and QA-only changes.
3. `src/app.js` (`renderPamConfiguration`) and `tests/pam-result-disclosure.test.mjs`: the generic classification and additive behavioral contracts. No canonical model/evaluator change.
4. `docs/windows-protection-expansion/corrections/response-ledger.json#/currentRecheck`, `implementation.md` and `manifest.json` in that expansion directory: current response and scope. `retainedHistoricalCandidate05` and older retained sections are historical, including old pending closure wording.
5. Verification `classification-smoke-summary-01.json`, `classification-final-before-01.json`, `classification-after-02.json`, and the source/emitted before/after reports: actual summary and JSON category inspection, including replay/rewind and the nonregistered fixture qualification.
6. Verification `native-summary-01.json`, `native-original-assertions-preserved-01.json`, `native-01/` and `visual-disclosures-01/`: actual Chromium cells, unchanged old assertions, added classification checks and two separately counted visible category frames.
7. Verification `full-suite-summary-01.json`, all 135 raw logs under `full-suite-01/`, `focused-summary-01.json`, `compiled-01/compiled-bundle-status.json` and `build-summary-02.json`.
8. Current Windows/PAM `results-source.json` and `results-runtime.json`, verification `canonical-source-01.json`, `source-outcomes-01.json`, `existing-unix-source-01.json`, and `corrections/existing-operation-dispositions-01.json`: fresh source proof and the exact limited browser subset.
9. `docs/windows-protection-expansion/performance-results.json`, `preserved-release-conditions.json` and the package input/scope manifests: unchanged open gates, compact omissions and retained inputs.

## Bounded correction

The shared renderer partitions the existing canonical `pamResults` map into three disclosures:

- **Completed API aggregate results**: genuine completed public API phases only. Earlier public results remain visible; public `password` appears only after its actual final public return.
- **Internal password dispatch results**: completed `prelim`/`update` evidence, including failures, never labelled as separate application calls. Explanation: `prelim and update are internal passes inside the enclosing pam_chauthtok call, not separate application calls.`
- **Pending / not-started results**: `not evaluated` values regardless of phase; never presented as completed APIs.

Empty result maps retain the three disclosure elements so existing open/focus state survives rewind. Classification uses the shared phase metadata, not scenario-name patches. No result-map migration, model/evaluator/compiler change, secret recreation, lifetime extension, repeated verification, flag change, new selectable variant or outcome repinning occurred. The original 134 test files are unchanged.

The six reached-change LLOG04 variants are checked before the public call, after preliminary dispatch, through conversation/policy/backend/sender-local preparation, after update and at final return, including rewind. Unsupported, expired-account and authentication-rejection controls invent no change call or result. Four PAM01 success/preliminary-failure/update-failure/unsupported references retain the same boundaries. An additive `prelimOk:false` factory control stops before candidate collection, update and commit; it is not a registered lesson or emitted selectable case.

## Historical worker scripts: actual substantive results

The later independent reviewer used Node v24.22.1, not worker Bun: 236 passed / 0 failed across ten files; UI source 17,965 checks / 958 positions (607 checks / 36 source-only positions), emitted 17,360 checks / 922 positions; adapted PAM support 5,163 / 5,165, 62 contracts and zero failures; 35,350 full-preservation, 7,300 provenance and 4,583 adaptation-audit checks. These supplied reviewer observations are distinct from the retained worker executions below, not reruns by this documentation update and not native/human/performance acceptance.

The following historical paragraphs concern the original candidate-05 reviewer scripts supplied with candidate-07. Their review-line references are to that earlier report, not to the new closure review.

The supplied review's `ui05-probe` and `pam05-probe` now ran in both source and emitted modes against the exact source/HTML above, with pinned Bun 1.4.2 and automatic installs disabled. Both UI outputs have `disclosureMislabels: []`; both PAM outputs have `contractFailures: []` and all 62 contracts passed. Source/emitted observation arrays match exactly. These are worker executions, not a new independent Astra/Node/native/browser/performance acceptance.

Only the two emitted hash pins and the one PAM classification expression changed. The original PAM expression tests canonical `pamResults` for internal keys; a hash-pin-only copy would still flag six reached-change variants because those compatible keys intentionally remain. That is not a rendered-public-disclosure failure. Review lines 417-420 allow this renderer-only design and lines 827-830 permit accurate classification adaptation. The adapted expression parses the actual completed-public disclosure JSON, retaining every other assertion, expectation and original label. Originals, diffs and full outputs remain inspectable; the six old-predicate mismatches are derived from captured canonical values, not claimed as a new unadapted-script run. The literal original emitted script also has a superseded HTML pin.

See `review/REVIEWER-PROBES.md` for exact commands and all four observed counts. Inspect the failure arrays, not merely process exit. No app/test/model/compiler or existing QA producer changed after candidate-06; the following broader results remain their original actual runs on identical bytes, not reruns for this packaging-only addition.

## Existing observed verification on unchanged product bytes

| Check | Result and evidence class |
|---|---|
| Final exact new contract file before / after | Reviewed product: 4 passed / 14 failed; corrected renderer: 18 passed / 0 failed |
| Direct source and actual emitted-script disclosure inspection | Each mode: 913 positions, 13,101 checks, 0 failures; actual summaries/JSON, full and representative field/exact views, rewind |
| Affected PAM/inspector/shared UI suite | 305 passed / 0 failed across 12 files, including disclosure focus/open behavior |
| Complete pinned local regression | 2,395 passed / 0 failed across all 135 files; one actual scheduled run with unchanged execution inputs and all raw logs supplied |
| Actual Chromium collection | 141 / 141 cells passed, 0 failed, 0 unperformed; 47 in each source-HTTP, emitted-HTTP and offline-file mode |
| Chromium assertion preservation/addition | All original 531 correction and 2,820 lifetime checks remain exact; separate 41,253 classification checks, 2,844 prefix observations, 0 failures |
| Visible disclosure supplement | Two actual offline-bundle frames, pending and completed; outside the 141-cell denominator, not human/AT acceptance |
| Actual compiled script smoke | All 328 choices passed with stable final input identities |
| Fresh canonical source collector | 110 cases / 128 executions / 4,660 completed prefixes; complete execution bodies and terminal bytes equal reviewed candidate-05 |
| Unchanged literal outcome projection | 992 original expected fields retained; DERIVED via that fresh whole-body identity to candidate-05 direct field observations, not another direct extraction or independent oracle run |
| Existing Unix source/held/sender checks | Six models / 55 executions / 1,331 prefixes including initial; every authored step and full state, including `pamEvaluation` and `pamResults`, exactly unchanged; no fields excluded or normalized |
| Final-source no-install rebuild | Exact current standalone bytes reproduced; earlier intermediate-fixture build remains separately identified |

Counts overlap and must not be added into a larger unique-case claim. Each browser mode contains 29 existing-consumer controls, four PAM01 references at four stages, setup and browser-errors. Those references account for 12 canonical / 48 staged cells and 474 prefix observations. No current Windows browser execution or full 128-execution browser sweep is claimed.

The nonregistered `prelimOk:false` factory is source-derived in both smoke modes. The emitted-mode bridge feeds its data to the actual unmodified emitted renderer; this is not independent emitted-factory execution. Real Chromium coverage remains the declared registered/reference plan.

## Historical failures and QA changes stay visible

The new contract's original no-op focus fixture initially produced 15 passed / 3 failed after the renderer fix. `focus-diagnostic-01.json` shows that fixture never tracked the active element even before navigation. The corrected setup follows the existing focus regression convention; no product focus helper or behavioral assertion was weakened. The exact final test bytes separately produce the before/after results above.

The first emitted-mode source-derived fixture adapter hit the existing foreign-prototype/plain-object guard, so that collection is incomplete, not classification proof. Its original producer/report remain. The corrected QA-only adapter bridges genuine source fixture data into the VM realm; it does not relax the model guard. Complete before-source and before-emitted reports then reproduce the classification defect; all failures and exact producers remain separate from the successful after reports. Repeated classification failures are observations of one remaining P2 issue, not additional findings.

Candidate-05's earlier literal/rendered/browser/compiled/full-suite failures remain historical failures with their original source and producer scope. Do not read old failed runs as current failures or restamp them as passes. The accepted sender-local creation/public-delivery selector and all old custody, pending, flags, replay and history assertions are preserved.

## Local schedule is not CI or performance proof

The pinned Bun 1.4.2 local runner executes standalone boot exclusively, then four workers run the remaining files. The original standalone test body and limits remain unchanged: 5,000 ms VM, 900,000 ms per test and 1,800,000 ms per file process.

CI still uses `bun run test`, expanding to `bun test --isolate --timeout=900000 tests/*.test.mjs`. That exact invocation has **not** been observed passing here. Local scheduling does not apply in CI and does not close the five-second load-sensitive VM boot risk. Neither functional checks nor scheduling diagnostics establish startup-performance acceptance.

## Compact packet, checksum binding and rebuild

The packet retains every canonical app/test input, all 253 original frozen authority/configuration/oracle/review inputs plus the prior recheck and new candidate-05 review, and all 75 required captures. The mandatory 11,674,269-byte S24 SMB2 PDF remains supplied even if ZIP size exceeds the single-digit-MiB target. Actual ZIP size and warning are in `packaging-status.json`; inputs were not dropped to meet a size target. Twenty-five original capture HTTP statuses remain unrecorded; byte hashes do not prove successful live retrieval.

`review/PACKAGING-INPUT.json` and `CONTENTS.json` bind selected payloads and omitted members' exact SHA256/bytes/reasons. Historical bulk raw state/DOM/input dumps, profiles and external browser/dependency bundles remain local/on demand. The current classification reports and raw regression logs are supplied. Do not infer that all historical/numeric/browser collectors are self-contained offline replays.

Extract beside the external HTML and this entrypoint, then use pinned Bun 1.4.2 first in PATH:

~~~sh
unzip auth-flow-studio-windows-protection-source-and-review.zip
sha256sum -c review/SHA256SUMS
cd source
bun --no-install build.mjs --source-version
cmp dist/auth-flow-studio.html ../auth-flow-studio-windows-protection.html
~~~

No Node/npm or application install step is needed for the historical packet rebuild recipe above. The in-ZIP checksum binds selected payloads and the external HTML/entrypoint, excluding itself and `CONTENTS.json` to avoid self-reference. The external checksum additionally binds final ZIP/status. The sibling packaging status records its actual inventory, hashes and extracted build. A separate independent-relocation receipt cannot change a delivered packet byte. Packaging integrity alone is not independent closure or release authority; independent B closure is now recorded separately in the candidate-07 authority linked above.

## Preserved gates and publication

WP-R06 is complete and all seven whole findings are closed within reviewed scopes. A and the six prior whole-finding closures retain their accepted-byte scopes. G01 remains open with owner `andrico21`; native Windows/DC remains unperformed for 88 cases. The historical installed-PAM result is 164 matches plus one qualified divergence across 165 calls, not a new native run. Current correction performance is unmeasured and owner disposition remains open. Candidate-02's two material startup flags and one baseline-only variation, six P6 conditions, five DNSSEC material conditions and earlier-key/P0/live/cross-engine limits remain qualified and unaccepted/unwaived. Prior scoped P6/P6C, DNSSEC and WIN-11 closures are preserved, not converted into blanket conformance.

The independent review itself grants no publication, human acceptance or performance waiver. The user has separately requested the **1.1** repository commit and push; the [publication record](publication-1.1.json) scopes that authorization and its version-only artifact delta. Accepted candidate-07 remains unchanged for owner checks, and no new Astra corrective upload is required. Human, performance and native-platform conditions remain separate and unwaived; Pages still depends on the existing CI gate.
