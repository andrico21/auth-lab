# Expansion native acceptance

`tools/verification/run-expansion-native.mjs` is permanent actual Chromium/Playwright acceptance tooling. It is not imported by the app, does not install dependencies, and does not replace the existing HC01-HC09 native runners, full regression suite or offline cryptographic validators. Authoring this runner did not execute a browser, test, build or benchmark. A report, not this document, establishes an exercised result.

## Current four-finding correction recheck

The independent review closes the original nineteen findings and requests NET-05, WIN-09, WIN-10 and SMB-R01. The current twelve-SMB-preserving candidate uses `run-review-corrections-native.mjs` for deliberately targeted three-mode acceptance and `package-review-corrections.mjs` for the separate recheck package. See [the current handoff](implementation.md#current-four-finding-recheck-candidate) and [portable commands](../../tools/verification/README.md#smb-correction-recheck). The source regression runs only after browser work, alongside separate emitted-bundle and numeric evidence. Current reports are under `docs/verification/review-corrections-recheck/`; earlier correction reports retain their predecessor identities.

That scoped report is not a replacement full run of the original 61-preset/all-catalog browser, zoom, touch or performance gates described below. Earlier broad reports remain artifact-specific historical evidence. Their requirements and strict original packager are not weakened or relabeled as current results.


## Prerequisites and invocation

Build the expansion checkout first using the existing Bun build command, then freeze its sources, supplied favicon files in `assets/`, worksheets, manifest and standalone artifact for the duration of the run. Do not run the full regression suite concurrently with browser acceptance.

The native QA dependency is pinned separately from the dependency-free application in `tools/verification/native-qa/package.json` and `bun.lock`. For a fresh QA checkout:

```sh
bun install --cwd tools/verification/native-qa --frozen-lockfile --ignore-scripts
export PLAYWRIGHT_MODULE="$PWD/tools/verification/native-qa/node_modules/playwright-core/index.mjs"
```

This installs only Playwright Core 1.64.1, not a browser. Provision an appropriate Chromium executable separately and set `CHROMIUM_EXECUTABLE`; the observed review run records its exact version and executable hash. An already provisioned pinned QA environment can be reused without reinstalling it. Supply:

- `PLAYWRIGHT_MODULE`: absolute path to the installed Playwright entry module. If omitted, the runner resolves the existing `playwright` package from its own location. The report discovers Playwright and playwright-core package versions, package/entry SHA-256 values and actual paths; it does not claim an unobserved version or an unpinned install is reproducible.
- `CHROMIUM_EXECUTABLE`: installed Chromium executable. If omitted, use Playwright's existing executable path. Nothing is downloaded. The report records the executable SHA-256 and `browser.version()` from the actual launched Chromium.
- `LD_LIBRARY_PATH`: externally supplied shared-library search path when required by the provisioned Chromium. It is inherited unchanged and recorded.
- `AUTH_LAB_EXPANSION_BASELINE_ROOT`: accepted `22242f2da7b19761856dfcecf422fb615ac04090` checkout, with its accepted built artifact. The prepared workstation copy is `/home/andrico/.cache/auth-lab-held-qa/expansion-baseline-22242f2`. A fresh review package can supply an extracted offline baseline archive instead. Its standalone must hash to `82df991efa584a9280aa898c0436537ad2f721afe27c941a350f20977c2d060e`; mismatch fails, rather than silently benchmarking a different baseline.
- `AUTH_LAB_EXPANSION_EVIDENCE_DIR`: optional evidence root, default `docs/verification/expansion` under the checkout derived from `import.meta.url`.

With those environment values exported:

```sh
bun tools/verification/run-expansion-native.mjs --jobs=2
```

An optional first positional argument selects another project directory. `--help` does not load browser dependencies. `--jobs=1` through `--jobs=4` bounds concurrent mode workers; default is two. The comparative performance phase is always serial and precedes acceptance workers. `--mode=source-http` (also `standalone-http` or `standalone-file`) and repeatable `--id=lab-win-ntlmv2-domain` are diagnostic subsets, explicitly never complete acceptance. Default executes all 61 manifest IDs, all three modes, all widths, eight deep representatives, native history navigation and regressions. Missing baseline environment on a default full invocation is a recorded failure, not an invented before/after result.

## Exercised surfaces

The runner serves its own ephemeral `127.0.0.1` HTTP origin. It loads source HTTP, standalone HTTP and standalone `file:` documents in real browser contexts with CSP enabled. Acceptance requests outside that origin or the exact standalone file are rejected and reported, as are runtime errors and CSP violations.

The preserved `native-browser-acceptance.mjs` gate also decodes the supplied SVG, ICO and Apple touch icons in all three loading modes under enforcing CSP. It compares embedded icon bytes with the source files and rendered 32-pixel PNGs with source HTTP, while a deliberate off-site image probe must be blocked by `img-src` before reaching request interception. The standalone's only image permission is `data:`; source mode uses same-origin icon files.

Every ID is discovered by typing into the actual universal picker and clicking the actual option. Before Play, the visible teaching profile must expose prerequisites, support and completion, with irrelevant Web toolbars absent. Actual Journey/Fields/Crypto buttons must preserve both protocol and held snapshots. Real Play/Pause, keyboard seek, Reset, keyboard connection replay, current-profile field replay and exact held-object history are exercised. Network global field search and clearing are checked without changing canonical state. Native `page.goBack()` and `page.goForward()` traverse actual browser history between Windows and Network routes.

For all IDs and modes, initial and terminal DOM geometry is measured at 1920, 1480 and 390 CSS pixels: participant and dock bounds/overlaps, 44-pixel inventory targets, graph containment, document overflow and complete logical-owner coverage. Real SVG paths are sampled using `getPointAtLength()` and `getScreenCTM()` at intervals no greater than one SVG unit, against rendered card/dock rectangles. At each width, paused mid-flight fields exercise an actual transfer, local computation and, where present, a logical-component exchange; visible packets, logical endpoint highlights, local arrow suppression, field-label overlap and clipping are checked. Eligible internal components are also expanded through the real checkbox, repeating geometry and active-field checks while requiring unchanged canonical protocol state and holdings before/after expansion. This is centerline sampling, not a claim about every antialiased painted pixel; existing painted-route baseline checks remain separate gates.

Terminal Windows, Kerberos SPAKE and PAKE state is checked against independent worksheet contracts and explicit protocol outcomes at every viewport. Network lessons additionally visit each independently authored expected milestone and compare its concrete state paths. Connection replay starts through the actual SVG route's keyboard action; the player's actual filtered queue is completed through its seek API before comparison with the same canonical full-source prefix. The global seek control intentionally navigates the full journey instead. Actual timeline clicks pause exact-object rows and open their progressive field disclosures before visible-value checks.

Windows local creations, legitimate plain acquisitions, decryptions and explicitly authored verification/acceptance observations contribute local field-history operations. Observation rows remain limited to that actor's declared field readers. The W12/W21 preflight denials therefore have replayable local error creation without inventing a TLS channel, credential transfer or remote logon.

After mode workers close, a serial surface phase uses actual `hasTouch`/mobile contexts for exact-inventory taps in Web, Windows, AD DS, Kerberos SPAKE, SSH, Network and PAKE. Separate desktop contexts set Chrome's actual default browser zoom through `chrome.settingsPrivate` at 200% and 400%; CSS layout width and visual scale distinguish this from CSS/pinch zoom. Those seven journeys are checked for geometry at both zoom levels. Default zoom is restored even after failure.

The eight deep fixtures check independent specification boundaries:

- W01: AUTHENTICATE receipt, DC validation, result delivery, context acceptance and application authorization remain distinct.
- W09/W10: H has only the opaque representation of the same exact delegated credential on receipt; decoded credential possession begins at local unwrap, not logon. Actual exact history renders protected network and legitimate H-local decoded rows. Long field disclosures are opened by real summary clicks before visible-value assertions.
- PAP and wired EAP-TLS 1.3: Access-Accept delivery and verification do not authorize the port; NAS enforcement does. NAS never acquires endpoint TLS private keys/secrets or EMSK.
- Kerberos SPAKE: response receipt is not factor validation; AS reply receipt, client validation and TGT cache acceptance are separate. The client's opaque TGT bytes are actually displayed in its inspector and exact wire-history row; decoded ticket/cookie bodies never become client holdings. Service-ticket receipt is not an application session.
- SPAKE2 and SPAKE2+: output keys are independently local and never message objects. Peer verification, reciprocal local transport handoff, in-flight confirmation, receipt and receiver confirmation are separately checked; no application authorization is implied.

N01 checks the actual BFF redemption inspector's Server exchange label. The zero-width provisioned-object history regression pauses halfway through the real R0 initial row and verifies the canonical initial snapshot remains unchanged after another browser delay.

## Performance evidence

With the accepted baseline supplied, each mode gets three fresh isolated browser-context samples per checkout, alternating baseline and expansion. Cold means empty browser storage/HTTP cache, not flushed OS filesystem caches. Startup ends at real held-view readiness plus two animation frames; picker filtering uses the same human query `refresh` on both versions, followed by the same `lab-refresh-rotation` selection through its actual option. The accepted baseline does not index internal scenario IDs, so benchmarking an ID-only query would be invalid. Replay-start latency ends at positive playing progress plus two animation frames. A second real `basic` search must reveal the Basic option while the same journey remains playing with monotonic progress. Timings include Playwright round trips. Reports retain raw observations, min/median/p95/max, source and standalone bytes/hashes, rendered DOM node/HTML-byte counts and browser resource transfer bytes. File transfer sizes may legitimately be zero.

A material-regression flag requires both a median increase above 25% and above 100 ms for startup or 50 ms for an interaction. Flags remain visible for review, not suppressed or converted into causal conclusions. Three samples are descriptive, not statistically significant. The selection phase also retains Chrome Performance counters before/after the real click, outside its elapsed timing: node/heap counts and script, layout, style and task durations. `Nodes` includes detached nodes; `liveNodesAfter` counts the current document separately. These counters locate aggregate work but do not attribute it to a particular function. Review the recorded deltas and explain any material regression before publication. These measurements do not establish continuous frame rate.

### Native cost attribution

With the same pinned browser/dependency environment and `AUTH_LAB_EXPANSION_BASELINE_ROOT`, run this after other browser jobs finish:

```sh
bun tools/verification/profile-expansion-replay.mjs
```

The permanent diagnostic creates a unique evidence directory under `AUTH_LAB_EXPANSION_EVIDENCE_DIR`. Fresh baseline/expanded standalone-file contexts start on Basic for an idle `refresh` search, then select the same refresh journey for real Play and in-play `basic` search. All three phases repeat after closing the field index through its actual UI button. Twelve phases retain CPU samples, raw Chrome timeline traces, marker-bounded inclusive native-event durations, Performance counters and source/dependency identities. Counter windows exclude profiler startup/shutdown. Instrumented timings are not substituted for uninstrumented all-mode medians; overlapping trace durations must not be summed. Promote the final report and all twenty-four raw files unchanged under `performance/`; disposition and packaging validate their hashes.

## Evidence and limits

Each invocation creates a unique timestamped directory containing `expansion-native-status.json` and selected source-mode representative screenshots: all eight final scenes at 1920, their active transfer/local/component fields, EAP-TLS final scenes also at 1480 and 390, and expanded local SAM/LSA and TOTP-component scenes at 1920. Captures record actual bounds and hashes. Failed scenario captures are separate. Prior runs and accepted held-object reports are not overwritten. Failures include mode, ID/phase and stack, are retained while other scenarios continue where possible, and set a nonzero exit status. A setup failure still emits a failed report after the evidence directory can be created.

Reports include runner SHA-256, exact regeneration argv, runtime/Bun version, dependency identities, per-source snapshot hashes, independent manifest and worksheet hashes, standalone bytes/hash and before/after identity checks. `complete` requires the full scenario/mode/deep/regression scope, seven native-touch journeys and fourteen actual-browser-zoom scenes per mode, and available comparative performance; a passing diagnostic subset can still have `complete: false`. Screenshots are supporting captures, not inferred pass evidence.

Manual G01 remains open. No real screen-reader speech/comprehension, cross-engine result, live protocol interoperability or cryptographic-vector pass is claimed by this runner. Publication remains gated on independent Astra review. The existing compiled-bundle offline smoke retains its behavior, now advertises Bun and records its runner hash, regeneration argv and runtime identity; it still is not native acceptance.

## Scenario disposition and review archives

Promote unchanged final reports and their captures under `docs/verification/expansion/`: `offline/`, `native/`, `performance/`, `baseline-held/`, `baseline-ui/`, `focused-native/`, `review-file/` and `regressions/`. Keep the two crypto reports at that root; failed or superseded work belongs under `attempts/`, never in place of a required successful gate.

```sh
bun tools/verification/expansion-disposition.mjs
bun tools/verification/package-expansion-review.mjs --out=/absolute/new-review-directory --baseline-archive=/absolute/accepted-22242f2.tar
```

Use the same Bun executable for both commands; packaging also requires `zip` and `unzip` on PATH. The first consumes the independent 61-ID manifest and worksheets, actual model metadata and exact per-choice source/compiled/native/regression evidence. It records separate source, native, performance and interoperability dispositions without inventing expected state from the runtime builder. Missing, partial, failed or stale evidence is an error. The recorded performance caveat preserves every material default-open interaction flag.

The package tool validates those dispositions and gate identities, preserves reports unchanged, extracts its generated source ZIP into a newly owned temporary directory, compares every included file and runs the real Bun build there. The rebuild must byte-match the delivered standalone. Outputs are a source ZIP, standalone HTML, verification ZIP, `SHA256SUMS` and `review-package-status.json`.

The source ZIP contains application/build/test sources, documentation, worksheets, text/JSON evidence, regenerators and QA package manifests/locks, but no `.git`, installed dependencies or verification PNGs, including the whitelisted representatives. The verification ZIP restores all omitted captures at repository-relative paths and includes the accepted baseline TAR, final evidence, separately identified attempts and all verification tools/fixtures/provenance/licenses. Extract it over the source ZIP to inspect captures. Installed browsers and packages are not bundled.

Packaging never publishes, reruns acceptance gates or grants Astra approval. Manual G01, real assistive-technology comprehension, cross-engine behavior and live interoperability remain explicitly unestablished.

