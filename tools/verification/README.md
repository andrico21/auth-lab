# Verification tools

Run these commands from the repository root; `--help` lists each tool's arguments. The default project is the repository containing the scripts, independent of the current working directory. General evidence goes to `docs/verification` or `AUTH_LAB_QA_EVIDENCE_DIR`; held-object evidence uses `docs/verification/held-objects` or `AUTH_LAB_HELD_EVIDENCE_DIR`. The scripts do not change application source or contact identity providers.

## SMB correction recheck

The current candidate addresses NET-05, WIN-09, WIN-10 and SMB-R01 from the independent review that closes the original nineteen findings. Its separate evidence is under `docs/verification/review-corrections-recheck/`. Earlier correction/expansion/native/performance reports remain tied to their recorded predecessor hashes. This flow preserves all twelve SMB scenarios without repeating full catalog, zoom, touch or performance matrices.

Use an existing matching Playwright Core/Chromium installation. The application still needs no dependency installation. Numeric QA has its own exact-pinned package; install it only if it is not already provisioned. Provision the two exact Bun executables separately:

```sh
bun --cwd tools/verification/expansion-crypto install --frozen-lockfile --ignore-scripts
# Run focused source/mounted assertions before rebuilding:
bun test --isolate --timeout=900000 \
  tests/windows-auth-lab.test.mjs tests/held-object-windows.test.mjs \
  tests/network-access-lab.test.mjs tests/held-object-network.test.mjs \
  tests/review-network-replay-ui.test.mjs \
  tests/smb-access-lab.test.mjs tests/smb-multichannel-lab.test.mjs tests/smb-ui.test.mjs
bun run build
bun tools/verification/run-review-corrections-crypto.mjs \
  --bun142=/absolute/path/to/bun-1.4.2 \
  --bun143=/absolute/path/to/bun-1.4.3 \
  --out=docs/verification/review-corrections-recheck/crypto
AUTH_LAB_QA_EVIDENCE_DIR=docs/verification/review-corrections-recheck/compiled \
  bun tools/verification/compiled-bundle-smoke.mjs
PLAYWRIGHT_MODULE=/absolute/path/to/playwright-core/index.mjs \
CHROMIUM_EXECUTABLE=/absolute/path/to/chrome \
  bun tools/verification/run-review-corrections-native.mjs
# Finish all browser work before the bounded full suite:
AUTH_LAB_HELD_EVIDENCE_DIR=docs/verification/review-corrections-recheck/regressions \
  bun tools/verification/run-regressions.mjs
bun tools/verification/package-review-corrections.mjs \
  --incoming=/absolute/path/to/auth-flow-studio-smb311-corrections-source.zip \
  --review=/absolute/path/to/auth-flow-studio-smb311-corrections-review.html \
  --out=/absolute/path/to/new-external-recheck-review-directory
```

Use Bun 1.4.2 for the build/native/regression/package commands to reproduce the observed CI-pinned run. `LD_LIBRARY_PATH` may be supplied when the provisioned Chromium needs external runtime libraries. `AUTH_LAB_REVIEW_EVIDENCE_DIR` overrides the targeted native directory; the package tool's `--evidence-root` selects a complete alternative evidence tree.

`run-review-corrections-crypto.mjs` executes the permanent independent vector verifier with each supplied Bun binary. It retains raw JSON, actual argv/exit/runtime, output hashes, its own hash and the regeneration command; it does not manufacture expected bytes. Negative transcript fixtures are derived by the separately documented Python generator in `expansion-crypto/`.

The native tool uses actual source HTTP, built HTTP and built `file:` surfaces with CSP enabled. It preserves the previous targeted SMB/navigation/profile/SPAKE/PAKE/icon coverage and adds all 53 receiver-local decoded RadSec occurrences, three actual field replay paths with exact full-prefix equality, six H-side resource receipt/acceptance paths, eleven Windows AES early/completed key contexts and five actual SMB ticket-key explanations. The three WinRM captures are accurately named `*-winrm-protected-command-result.png`. The tool has no request interception, avoiding Playwright's implicit ICO interception behavior.

The package gate requires exact source/runner/artifact hashes, all current test files passing, all twelve SMB IDs and the four findings' native coverage in all three modes, numeric inputs/primary sources, the reviewed predecessor source ZIP and the immutable independent review. It writes a four-finding disposition pending independent recheck, while retaining the review's nineteen closures. It extracts the source ZIP, byte-compares every file and runs a real offline Bun rebuild that must match the standalone. The verification ZIP preserves both inputs and current failed attempts; historical captures stay in their earlier packages. No publication is performed or authorized.


## Windows, Network and PAKE expansion

The expansion retains the complete baseline gates below and adds independently authored per-preset contracts, numerical cryptographic QA and native acceptance for all 61 new IDs. See [the expansion verification contract](../../docs/expansion/native-verification.md) for exact scope, isolated dependency pins, baseline performance setup and honest manual/interoperability limits.

```sh
bun --cwd tools/verification/expansion-crypto install --frozen-lockfile --ignore-scripts
bun run verify:crypto
bun run build
bun run verify:expansion
```

Native verification uses the separately pinned `tools/verification/native-qa` package or the already provisioned matching QA environment. Neither optional QA package is imported into the application or required for its offline build. The native runner creates unique result directories, records source/worksheet/manifest/standalone and runner identities, and never downloads dependencies or a browser. Run the bounded full regression generator only after CPU-heavy browser gates finish.

`profile-expansion-replay.mjs` is the permanent cost-attribution diagnostic for material idle-search, replay-start or in-play search flags. It retains CPU profiles and marker-bounded Chrome traces for the same baseline/expanded app paths with the field index open and closed through its actual control. Instrumented results do not replace the uninstrumented acceptance medians or clear their flags.

After all real gates pass, `expansion-disposition.mjs` produces the scenario-by-scenario review manifest. `package-expansion-review.mjs` builds the local reviewer archives and proves a fresh extracted-source Bun rebuild is byte-identical to the standalone. Both reject missing or stale evidence; see the linked contract for their invocation and archive overlay layout. Neither authorizes publication before Astra review.

## Native browser

```sh
bun tools/verification/native-browser-acceptance.mjs
```

Requires a local Playwright package and Chromium installation. `PLAYWRIGHT_MODULE` and `CHROMIUM_EXECUTABLE` can specify their absolute paths. In the hosted execution environment, the script can also discover Playwright through `CODEX_PRIMARY_RUNTIME_NODE_MODULES`; no hosted runtime path is hardcoded.

The script serves the modular source and the compiled HTML on an ephemeral loopback port, then opens both in real Chromium. It also opens the compiled HTML directly through `file://` to test the intended offline use. Its code1-correction output is `code1-correction-native-browser-status.json`; screenshots have the same prefix. Original release evidence is preserved. The report includes the exact standalone byte count/SHA-256, source entry hash, deterministic source snapshot hash and actual browser/version; successful execution rechecks the source/artifact hashes before claiming acceptance. Screenshots include expanded participant and nested attribute help while the panels are open, including narrow widths. A missing executable produces `verified: false`, never a simulated pass. It does not download a browser automatically.

| Check | Coverage in each of the three loading modes |
| --- | --- |
| Catalog/layout | Every registered scenario, collapsed and expanded internals, actual browser card rectangles and SVG path coordinates; overlaps, page overflow and unintended text clipping. Intentional CSS ellipsis/clamping is reported separately. |
| Favicon/touch icons | The supplied SVG, ICO and Apple touch icon decode under enforced CSP. Standalone icon bytes match the supplied files and rendered 32-pixel PNGs match source HTTP. |
| Participant help | Basic control plus SSH certificate, Device, SSSD and GSS; AD DS, Keycloak bridges with TOTP/WebAuthn, PKINIT, FAST AS/TGS, dense child-domain forest and third-forest comparison. Every visible new actor and expanded AS/TGS receives hover/focus/F2/Tab/nested field help/Escape checks, from an empty popup and after legacy help. |
| Protocol/state | Forest search, collapse while a child is focused, field replay, complete source-prefix comparison, timeline seek, keyboard movement; SSH zero-speed pause. UI changes must retain the correct protocol state. |
| Responsive study | Each representative new family at 1600×1050 and 390×844; additionally 800×525 and 400×263 CSS viewports to exercise the desktop reflow space equivalent to 200%/400% zoom. Reduced motion, expanded internals, viewport-contained help and reachable sticky Play controls. |
| Runtime context | Long SSH issuer/CA/host and Kerberos realm/SPN values at narrow width. Full context remains available below the graph, no page/history storage, reset on reload. |
| CSP/network | No application violations or external requests before deliberate probes. Eval, unapproved inline script, forbidden fetch and off-site images must trigger enforcing `securitypolicyviolation` records attributed to `script-src`/`connect-src`/`img-src`; neither forbidden fetch nor image may reach request interception. A failed `file://` fetch alone does not pass. |

The enforcing probe uses CDP `Runtime.evaluate` with `allowUnsafeEvalBlockedByCSP: false`. Ordinary debugger evaluation permits unsafe eval by default, even when the page policy forbids it. The gate requires all four attributable enforcing violations and proves forbidden fetch/image requests never reach interception/network.

Playwright automatically aborts `/favicon.ico` requests whenever interception is enabled, even if its URL does not match a route handler, and suppresses their request events. The native runner temporarily removes interception only during the three ordinary icon decodes, then restores it in `finally` before catalog acceptance and deliberate CSP probes. CSP and passive request/error observers remain active throughout; all recorded requests must still satisfy the origin/file boundary. No icon URL or application policy is changed to evade this framework behavior.

Reduced CSS viewports exercise desktop zoom-equivalent reflow but **are not browser UI zoom**. The report explicitly records `zoomIsBrowserUiZoom: false`; no CSS `zoom` is applied because it would preserve a different `innerWidth` and create misleading overlay failures. Also test browser-menu 200%/400% zoom manually, including OS scale/device pixel ratio and assistive technology. Screenshots and the automated checks do not replace a visual review of typography, clipping and legibility.

Historical baseline limitation: the original build and Code1-correction environments had no callable native browser. The recorded browser download returned HTTP 403, "Calls to this URL are not allowed", for the Chrome 151 distribution. Those logs are pre-feature baseline evidence, not results for the current candidate. Use the held-objects reports below for freshly exercised source, emitted-artifact and native-browser checks; do not infer native keyboard, CSS or CSP behavior from the offline checks.

Manual browser review should additionally cover browser Back/Forward during replay, browser-menu zoom, focus restoration across every kind of resize/rerender, pointer/touch movement and all product-specific version/profile boundaries. Only Chromium is exercised; do not claim cross-engine support from this gate alone. The script does not establish behavior against a real KDC, IdP, security key, CA, or SSH server.

## Offline independent geometry

```sh
bun tools/verification/independent-geometry-check.mjs
```

Mounts the app in its existing DOM harness, renders every registered model and preset, and independently samples the emitted cubic connection paths against the declared logical card size. It checks finite positions, canvas bounds, card overlaps, collapsed/expanded layouts and preservation of protocol state during visual expansion. `independent-geometry-status.json` explicitly labels this as offline. It cannot establish actual browser text wrapping, CSS layout, CSP enforcement or visual quality.

## Compiled HTML smoke check

```sh
bun run build
bun tools/verification/compiled-bundle-smoke.mjs
```

Parses the actual emitted JavaScript as one program, verifies exact SHA-256 script/style hashes against the emitted CSP, evaluates the bundle in the offline DOM harness, then selects every scenario. This catches concatenation conflicts and missing build modules that source-module tests can miss. It writes compiled-bundle-status.json; it does not emulate CSP enforcement or browser layout.

## Regression suite

```sh
bun run test
```

The supplied source snapshot passed 465 tests with Node 24.19.0 before implementation. Use the final verification report for results after implementation. Its purpose-built DOM harness verifies application projections and event handling; it is explicitly not a native browser, protocol endpoint or cryptographic implementation.

## HTML2 R1 emitted-context acceptance

```sh
bun tools/verification/html2-r1-bundle-check.mjs
```

After building the final standalone, executes its actual inline bundle in the deterministic DOM harness. It applies each reported service principal, alone and together with an alternate realm, then checks the full TGS reply, focused Send value/state, animated packet, independent workstation host acquisition and Reset/base-fixture preservation. The evidence records the exact compiled artifact hash. This is emitted-code/handler evidence; it does not close G01 or verify native browser layout/CSP enforcement.

## Code3 environment acceptance in the emitted bundle

```sh
bun tools/verification/code3-environment-bundle-check.mjs
```

Build first. This independent tool evaluates the actual inline IIFE with only the DOM harness, then exercises twelve AD/Keycloak Apply cases: realm254/255/2048 and unqualified/matching/conflicting service principals. It checks rejection/error association and exact old context/model/playback preservation, corrected Apply without Reset, parsed name/realm values in full/focused Send and packet/state, and Reset/base immutability. The report records exact artifact bytes/hash and explicitly marks native browser acceptance false. These are handler/value checks, not browser layout, native keyboard or enforced CSP evidence.

## Held objects source and native acceptance

```sh
bun run build
bun test --isolate --timeout=900000 tests/held-object-*.test.mjs
bun tools/verification/held-objects-check.mjs
```

The semantic gate uses the application's actual source-generation pipeline. It checks every picker choice and applicable normalized Core configuration, required interaction cases, exact identities, bounded temporary retention, state bindings and equal canonical full/link/object cursors. It emits `held-objects-source-status.json` and `held-objects-coverage-manifest.json`. Structural validity and universal coverage are separate gates; incomplete supported actor/cursor declarations fail the latter.

### Complete source regression report

```sh
bun tools/verification/run-regressions.mjs
```

Runs every `tests/*.test.mjs` file in four bounded workers, using a fresh current-Bun process with `test --isolate --timeout=900000` per file. `held-objects-regression-status.json` records each command, exit status, pass/fail totals, log path and application/test/helper identities before and after the run. An optional project-directory argument overrides the checkout default.

### Main native acceptance

```sh
PLAYWRIGHT_MODULE=/absolute/path/to/playwright-core/index.mjs \
CHROMIUM_EXECUTABLE=/absolute/path/to/chrome \
bun tools/verification/held-objects-browser-check.mjs
```

Playwright and Chromium are optional external QA tooling, not application dependencies. The runner never downloads them. It creates and removes its own isolated persistent Chrome profile so the real browser settings page is available for 200%/400% default browser zoom. Incognito contexts cannot open that page. It verifies the resulting CSS layout viewport and `visualViewport.scale`, rather than substituting CSS zoom, pinch scaling or viewport emulation.

Native checks cover modular source HTTP, standalone HTTP and standalone `file://`; initial/final inventories for every choice; dense folded/expanded full/compact/external layouts; actor/dock routes; final rendered target sizes; complete visible step-attribute names and collision-aware fallback; exact-object keyboard lifecycle and R1 replay/full-source equality; touch; reduced motion; source/emitted state equality; and no external application requests or unexpected CSP violations. The 1480-pixel desktop case exercises the measured compact range; every loading mode must actually produce full, compact and external geometry.

Animation-area cases additionally exercise the paused username/password exchange in the basic web and native-client configurations, compact desktop and narrow external layouts. They check actual participant-column relationships, visible complete step names, path-following focus without an SVG bounding rectangle, and preservation of the complete canonical snapshot. Route clearance includes compact summary bounds. Captures center the map using ordinary scrolling; narrow captures show the actual scroll viewport, not the offscreen full-width canvas.

Active local/IPC probes separately exercise the exact basic-Keycloak PKCE preparation, AD account-key selection, FAST computer armor, SSH CLI preparation, agent signing and CLI-to-agent exchange. They seek two meaningful visible times for every authored payload field (or explicitly record the existing local-action/title fallback when there is no payload), compare complete canonical snapshots across redraw/folding/layout changes, and measure route/focus stroke, marker glyph, chip/orb paint and full readable field values. Expected field membership comes from independent authored lab ledgers or the explicit Core fixture, never the UI field selector; rendered names and current-packet highlights must agree across folding and widths for each field/time. True local computation must be stationary and non-directional; folded IPC must retain motion/direction and its visible Local IPC channel. Actual SVG transfer paths must remain at least 12 world units from the local glyph center (0.01-unit numeric tolerance for rendered coordinates) and cannot cross the full/compact local U interior. These active captures are distinct from final-state family composition evidence. Active-scene cameras move the pointer away and use Escape to dismiss incidental participant hover help without moving SVG keyboard focus. Target-center hit testing remains required, and camera diagnostics are saved before a failed assertion.

Code1 acceptance checks actual displayed compact-JWE/local decoded values from both selected representations; packet phase and displayed protocol state immediately around authored receipt in full/connection/exact replay; repeated owner returns; and exact focus identity plus originating region with separate resize/removal/collapse fallbacks. Non-holding picker, merged-owner, compact, overflow and trace-exit triggers must retain their own identity and region on redraw. Every inactive scenario selection must clear the preceding packet, active-message text and phase. CSP records accumulate host-side across all application navigations/reloads. Touch opens the real exact-object inspector separately in source HTTP, standalone HTTP and standalone file, with a per-mode record.

The Code2 HC03 check starts from the actual SPA/BFF client holding after preparation, opens its exact inspector and invokes exact-object history through the application control. In each loading mode it selects the token-request occurrence inspected as Realm A and compares the queue and rendered verifier to the original authored value. Pre-delivery absence, same-event request-copy release, SPA browser readability and BFF browser exclusion are checked separately; current completed inventories alone do not establish receipt-occurrence readability. The explicit verifier reader declaration does not widen shared defaults, state/nonce readers or protected representations.


Kerberos/SSH composition checks independently cover AD, FAST, forest, SSH certificate enrollment/reissue, Device/SSSD and GSS with internals folded/expanded. They measure complete logical-owner label ranges, frame attachment, family-specific participant order, adjacent row spacing, the centered active GSS row, seven physical forest cards and stable shared SSH anchors across expansion. The full graph and complete top row must clear the measured sticky toolbar; viewport captures retain the actual controls, target-center hit-testing and camera bounds. These assertions accompany inspection of the regenerated evidence-directory PNGs; overlap-free bounds or differently scrolled cache copies alone are not a readability claim.

Every picker choice must retain full inventories at both initial and final cursors in the collapsed 1920-pixel desktop sweep. Cached/failed AD and forest journeys and Kerberos-to-Keycloak bridges remain included. Reservations cover physical actors participating anywhere in the selected journey, independently of the cursor; collapsed aliases and owners absent from the whole lesson do not add empty cells. A crowded column cannot silently reduce this desktop coverage to compact summaries.

### Focused native and delivered-file reports

```sh
export PLAYWRIGHT_MODULE=/absolute/path/to/playwright-core/index.mjs
export CHROMIUM_EXECUTABLE=/absolute/path/to/chrome
bun tools/verification/run-focused-native.mjs
bun tools/verification/review-file-smoke.mjs /absolute/path/to/auth-lab-held-objects.html
```

The focused runner owns an ephemeral loopback server and checks source HTTP, standalone HTTP and standalone file: exact holding focus/state across full/compact/external changes, collapse recovery, viewport-contained nested F2 help and one receipt announcement across multiple animation frames. It also scrolls top-row participant/inventory targets beneath the sticky controls at 1920/1480/1050/390 pixels and requires focus recovery to clear the measured toolbar, preserve canonical state and return the target from center hit-testing. Participant help is dismissed with a real Escape before hit-testing its anchor. Its report is `held-objects-focused-native-status.json`.

The file runner defaults to the checkout's `dist/auth-flow-studio.html` if no HTML argument is supplied. A delivered-file argument must match that build's SHA-256. It opens the actual file, checks exact R1 replay/full-state equality, measured compact controls and visible step names, and rejects unexpected runtime/CSP errors or external application requests. It then removes the actual custom element and requires its WeakRef to clear after separate browser tasks and Chrome full heap collections, catching retained global listener roots. Its report is `review-file-smoke-status.json`; it does not replace the broader enforcing-CSP probes or certify all memory behavior.

The regression and focused runners accept `[project-directory]`; the file runner accepts `[standalone.html] [project-directory]`. All three record their shipped runner SHA-256 and actual regeneration command. No temporary script, hardcoded checkout path or fixed preview port is required.

Run the full regression generator after browser acceptance jobs finish, not alongside them. Its four workers include CPU-heavy synchronous lifecycle tests; an earlier concurrent run reached the unchanged 900,000-ms per-test limit, while the complete same-source run passed after the browser jobs finished. Keep the original timeout and retain a failed attempt separately rather than treating it as passing evidence.

New reports/screenshots default to `docs/verification/held-objects/`; set `AUTH_LAB_HELD_EVIDENCE_DIR` to redirect them. The preserved broader runner uses `AUTH_LAB_QA_EVIDENCE_DIR`. Its accepted long-realm fixture is 244 characters; the separate 364-character rejection/recovery case retains G01-A's same-task atomicity probe. Hover fixtures leave the previous actor, reveal an unobstructed point below sticky controls, verify it with `elementFromPoint`, then send a genuine pointer move. This avoids the SDK retrying after an interactive help panel legitimately covers its trigger. No forced hover or synthetic mouse event substitutes for the user gesture.

The accepted Held Objects submission retained twenty-seven representative native captures. The expansion additionally whitelists eight desktop/compact/mobile captures; `.gitignore` excludes other bulk PNGs and superseded attempts from future source control. The expansion source ZIP deliberately omits all verification PNGs, including representatives; its verification ZIP overlays every omitted capture at the original repository-relative path. Current status reports, manifests, raw profiling data and regression logs remain in the source package.

The help panels are non-modal: Tab can leave a panel whose only control is Close. After verifying that exit, the runner focuses the actor and presses F2 again before testing Escape. It never tries to focus a now-hidden Close control or depends on completing the sequence before the blur timeout.

Read the [held-objects handoff](../../docs/held-objects-implementation.md) and final machine-readable reports for exact observed results and identities. Superseded attempts are kept separately and are not passing evidence. Real screen-reader speech/comprehension and cross-engine/live-service interoperability are not inferred from these gates.
