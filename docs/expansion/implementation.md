# Expansion and SMB review-correction handoff

The [independent acceptance recheck](../reviewer-handoff/auth-flow-studio-smb311-recheck-review.html) accepts NET-05, WIN-09, WIN-10 and SMB-R01 and preserves all original nineteen closures in their reported scope. No new blocking defect was found in the reviewed changes. All twelve SMB scenarios and the supplied favicon remain intact. WIN-11 is a nonblocking P3 field-history omission queued for the next small cleanup, not a reason to reopen WIN-10. Publication follows this acceptance using the unchanged reviewed application bytes; only review, closure and publication-handoff metadata are added or updated after acceptance. The original reviewed archives and run evidence remain unchanged. Manual G01 and the broader/performance gates remain open.

## Accepted baseline and fixed scope

- Accepted Held Objects Code3 baseline: commit `22242f2da7b19761856dfcecf422fb615ac04090`.
- Accepted standalone SHA-256: `82df991efa584a9280aa898c0436537ad2f721afe27c941a350f20977c2d060e` (2,257,970 bytes).
- Approved input: `auth-flow-studio-expansion-worker-plan.html` supplied by the user.
- Required additions: 23 Windows, 23 Network, 8 Kerberos SPAKE and 7 standalone PAKE fixed presets. The independent [plan manifest](plan-manifest.json) preserves all 61 IDs, prerequisites and terminal boundaries from that plan. It is not generated from runtime builders.
- Five primary workspaces: Web sign-in, Windows sign-in and remote access, Kerberos, SSH access, Network access. Foundations is a secondary entry. Grouped workspaces use registered family metadata and allowlisted routes.
- The subsequently supplied `favicons.zip` set is integrated unchanged. Unrelated logo redesign and live-service interoperability certification remain outside this implementation.

## Current four-finding recheck candidate

- Standalone: **2,898,880 bytes**, SHA-256 `9a3fc759c77502b52dd7b4d5da0851d706b36e7a0bf0afbe73aca0555798e924`.
- Requesting review: SHA-256 `c67d9fa079e9af33d3d8f392028702a898d2f0e401fb92643aa72d81d56a6abe`, retained byte-for-byte under `docs/reviewer-handoff/`. It reviewed predecessor HTML `8cbb6ae4...` and source ZIP `87a326e18cb4c4b060306687eaf3079a993771100df24e10aaefc2954788e520`.
- Accepting review: `auth-flow-studio-smb311-recheck-review.html`, SHA-256 `d83a8930e52a4f6e7630e7cee7a71dfac116bb15305ef9795f025fa71bf3128c`. Its exact accepted inputs are source ZIP `ccdcdd1803708555175400253a3b88b870ae1fed530f6c395e0c4e3712bfaa4a`, verification ZIP `d31c6a9d8ab573195ec628c39678595746b5438c13a2b2acb547b55601244356` and the standalone above.
- Current evidence: `docs/verification/review-corrections-recheck/`. Portable [regeneration commands](../../tools/verification/README.md#smb-correction-recheck) use the permanent native, numeric, full-regression, compiled-bundle and package generators.
- The original 61-ID manifest, all twelve SMB scenarios, 203 extended scenarios and 214 deduplicated choices remain. No next-plan NFS, workstation/elevation, MCP, JWT, Kubernetes or logo work is included.

| Current finding | Implemented behavior |
| --- | --- |
| NET-05 | All 53 recovered fields across eight RadSec events have receiver-local `decrypt` operations with decoded representation and exact value/source provenance. Genuine inspection context remains excluded globally. NAS identity, protected EAP and response-authenticator fields replay through the actual app and preserve the canonical prefix. |
| WIN-09 | `resource-result` is receipt-only. H's local `resource-result-accept` verifies/unwraps/correlates and acquires plaintext before H knows the outcome. WinRM output copies the accepted exact value with `derivedFrom`/`valueProvenance`; shared RDP consumers use the same acceptance. First-hop sessions and disclosed credentials survive ACL denial. The unimplemented protected-result-integrity rejection branch is explicitly outside the bounded model. |
| WIN-10 | H creates a distinct Windows AES `acceptor-subkey` inside ticket-session-key-protected AP-REP. C acquires it only at `mutual-verify`. Early client binding uses its available initiator key; reverse binding/authInfo and non-CredSSP WinRM completed-context bodies use the accepted key. AP-REP encryption, CredSSP inner-TLS application bodies and NTLM ExportedSessionKey remain distinct. |
| SMB-R01 | Actual ticket-key help distinguishes the ticket, initiator and exported server acceptor keys across all five affected Kerberos variants, without changing the already-correct SMB state machine. |

| Current check | Observed scope | Evidence under `docs/verification/review-corrections-recheck/` |
| --- | --- | --- |
| Focused source/mounted checks | Corrected actor/key/result custody and provenance; all 53 field replays, representative mounted Replay paths and unchanged inspect exclusion. Initial exhaustive test setup failure is retained; registering/restoring the model glossary corrected the test without weakening replay filtering. | `attempts/focused-initial.log` and current full-regression file records |
| Emitted bundle | All 214 choices passed, including executable/style CSP hashes | `compiled/compiled-bundle-status.json` |
| Real Chromium | Each mode passes all 12 SMB scenarios, all 53 RadSec decode occurrences, 3 actual field replays, 6 downstream-result paths, 11 Windows AES contexts and 5 displayed SMB explanations, plus preserved navigation/profile/SPAKE/PAKE/icon checks | `native/review-corrections-recheck-native-status.json` |
| Independent numerics | Unchanged numerical inputs; all 31 cases freshly passed on Bun 1.4.2 and 1.4.3 | `crypto/execution.json` and its two raw reports |
| Full bounded regression | **1,505/1,505 tests across all 87 files**, Bun 1.4.2, zero failures and unchanged source/test identities | `regressions/held-objects-regression-status.json` and all per-file logs |
| Review package | Current-evidence guards, extracted-file comparison and actual offline Bun rebuild/byte equality | External `review-package-status.json` |

The app was rebuilt once after focused checks. Browser work finished before the full regression. Actual built-app visual inspection confirmed decoded NAS replay and a C-owned plain acceptor-key holding created by H and acquired at mutual verification. Native reports bind source/runner/HTML hashes and capture hashes; WinRM images are now named `*-winrm-protected-command-result.png`, not field-replay images.

Current native coverage remains targeted: source HTTP, standalone HTTP and standalone file, all SMB cases at 1920 CSS pixels, with configured Kerberos and successful multichannel also at 1480 and 390. Nine current captures are retained. There is no fresh full-catalog native, browser zoom/touch, performance, cross-engine, live-protocol or manual assistive-technology signoff. The seven historical performance flags below are not newly measured current regressions or cleared flags. The generated pre-review disposition retains its original pending-review status and bytes; the subsequent `independent-closure-status.json` records the four accepted repairs and all nineteen preserved closures.

Acceptance recording matched all 154 application/build/configuration/test/asset files against the reviewed source package and matched the standalone and both reviewed ZIP hashes. No product code or tests changed, and no new build, suite or browser run was performed. Original reports, disposition, captures and package metadata remain immutable evidence for their recorded execution.

WIN-11 is queued with its full [six-fixed/seven-derived scope and constraints](windows-protocol.md#win-11---queued-nonblocking-field-history-cleanup). Its raw CredSSP/RDP field-only path omits H's local acceptor-key creation; exact held history, key custody and completed-context selection are already correct. Do not add the plain key to transmitted packet objects. The broader next-plan scope in the preserved acceptance review remains queued.

## Reviewed predecessor: original nineteen closures

- Standalone: **2,894,460 bytes**, SHA-256 `8cbb6ae44090eb7e4d1a46eebf22bf2b00756c47f4ccaaa9b7d907e3010b9651`.
- Input SMB source ZIP: SHA-256 `db39bafb05bfce96b4af42042ad9184efcfa0428c12cfb97e371005153fe639c`; original independent review and validation remain under `docs/reviewer-handoff/`.
- Additive inventory: [SMB01-SMB12](../smb-scenarios.json), including ten base lessons and successful/rejected multichannel binding. The original 61-ID manifest is unchanged. Current catalog: **203 extended scenarios, 214 deduplicated choices**.
- Preserved favicon: source files and standalone embedded SVG, ICO and Apple touch icon. Build and CSP embedding remain enabled.
- Predecessor evidence root: `docs/verification/review-corrections/`. Its original generator versions and commands are preserved in the reviewed predecessor source ZIP, rather than being claimed as current-run hashes.

### Independently closed original findings

| Finding | Corrected invariant |
| --- | --- |
| WIN-01 | Raw CredSSP failure is a protected TSRequest errorCode, not HTTP. |
| WIN-02 | HTTP responses consume an outstanding request; final mechanism/body records share the correct carrier, with later local acceptance. |
| WIN-03 | NTLM server domain and user account domain remain distinct. |
| WIN-04 | Bare Negotiate does not imply NTLM; the comparison declares its NTLM-only configuration. |
| WIN-05 | Nondelegating WinRM authors Create-shell, protected command/receive and the returned second-hop failure. |
| WIN-06 | KDC principal keys are authoritative provisioned keys, distinct from client-derived handles and NTLM records. |
| WIN-07 | Opaque WinRM receipt grants no shell/result knowledge until local protected-response recovery. |
| WIN-08 | Selected transport, TLS and credential prerequisites match each illustrated profile. |
| NET-01 | RFC 9190 exporter uses EAP Type 0x0D and splits 128 bytes into MSK/EMSK. |
| NET-02 | Applicable requests and their decoded views retain mandatory NAS identity. |
| NET-03 | RadSec wire ciphertext and endpoint-decoded RADIUS are exact, separate representations with delayed local acquisitions. |
| NET-04 | RFC 3579 and RFC 2869 are identified as Informational. |
| PAKE-01 | Initial optimistic KRB-ERROR is PREAUTH_REQUIRED; continuation uses MORE_PREAUTH_DATA_REQUIRED. |
| PAKE-02 | Negative fixtures change one participant's identity view while preserving its peer's official transcript and role-specific confirmation. |
| PAKE-03 | Initial PA-FX-COOKIE has exact opaque echo, KDC-only state and independent replacement/disposal. |
| ARCH-01 | SPAKE local derivation, verification, cache and disposal replay at original canonical cursors; cache projection updates rather than duplicates an existing use. |
| ARCH-02 | Structured cryptographic detail renders escaped readable parameters, including actual CredSSP binding inputs. |
| ARCH-03 | PAKE field cleanup uses supported eviction labels. |
| UX-01 | Enter/Space related and ready-made navigation retain live, visible keyboard focus on the selected starter or Play. |

The predecessor `correction-disposition.json` recorded nineteen locally addressed findings pending review. The subsequent independent recheck now closes all nineteen in their reported scope. Its four additional findings are the current task above; the old list is not reopened.

### Historical acceptance for reviewed predecessor

| Check | Observed predecessor scope | Report under `docs/verification/review-corrections/` |
| --- | --- | --- |
| Built application | All 214 choices passed emitted-code/CSP-hash smoke | `compiled/compiled-bundle-status.json` |
| Actual browser | All 12 SMB IDs plus 8 profiles, 5 navigation cases, 5 field replays, 2 RadSec and 2 WinRM boundaries and 3 supplied icons per loading mode; all three modes passed | `native/review-corrections-native-status.json` |
| Independent numerics | 31 cases passed on each of Bun 1.4.2 and 1.4.3 | `crypto/execution.json` and its two reports |
| Full source suite | 1,490 tests across all 86 files passed on Bun 1.4.2; zero failures and unchanged source/test identities | `regressions/held-objects-regression-status.json` and per-file logs |
| Package reproducibility | Strict current-evidence checks plus actual extracted-source rebuild/byte comparison | External `review-package-status.json` generated by `package-review-corrections.mjs` |

Native checks use real Chromium 155.0.8059.84 with CSP enabled and frozen source/artifact identities. All SMB IDs use 1920 CSS pixels; configured Kerberos and successful multichannel also use 1480 and 390. The map and structured CredSSP profile were additionally inspected through the actual built browser surface. The first integration caught duplicate SPAKE service-cache use; it was fixed at its authored event, without relaxing engine validation. Failed/superseded focused/native attempts remain under `attempts/`.

This pass intentionally does not repeat the full 61-preset/all-catalog browser matrix, browser zoom, touch, assistive-technology or comparative performance sweeps. Their earlier results below are historical, not current certification. No automatic result closes G01, clears retained material performance flags, establishes cross-engine/live interoperability or grants Astra approval.


## Historical pre-correction production changes

- Added complete Windows, Network, Kerberos SPAKE and standalone PAKE builders with canonical protocol effects, occurrence-specific held-object adapters, field definitions, profiles and independent worksheets. The catalog has 191 extended scenarios and 202 deduplicated choices.
- Added metadata-driven workspace/family navigation, allowlisted routes, starting-credential/profile/completion disclosure before Play, related comparisons and presentation-only Journey/Fields/Cryptographic detail controls. New profiled lessons scope their initial field indexes; typed search remains global.
- Added generic network/PAKE actor art and explicit human/local/IPC/server/protocol channel semantics. N01 now labels the BFF token request as a server exchange over backchannel HTTPS.
- Preserved HC01-HC09 reader boundaries and canonical replay. Fixed the zero-width initial-object cursor, Windows local creation/decryption/acquisition/verification histories, and an authored unknown-realm NAS/proxy placement that native fitting had masked. Windows observation rows retain their declared readers; W12/W21 early denials do not invent a network transfer.
- Reused keyed field-index rows rather than replacing the entire global index on legacy selection, while updating counts, context and selection. Core-to-legacy-to-Core availability/replay and focus behavior were exercised.
- The first full suite exposed obsolete DOM-replacement assertions and a 900,000-ms advanced factor-helper timeout. Behavior-based keyboard/focus assertions remain; implementation-only replacement assumptions were removed. Two anonymous global resize/blur listeners retained every disconnected component and its full field DOM. Actual forced-GC WeakRef probes isolated those roots, and real Chromium reproduced the retained component. The callbacks are now owned and removed on disconnect; the permanent delivered-file runner adds an actual custom-element collection regression. Timeouts were not raised.
- Added the supplied SVG favicon, 16/32/48-pixel ICO fallback and 180-pixel Apple touch icon in `assets/`. Source uses same-origin files; the build embeds all three unchanged as image data URLs. Only `img-src` gains those loading permissions; executable hashes and connection restrictions remain intact. Application JavaScript and CSS are byte-identical to the pre-favicon candidate.

## Historical pre-correction verification

The prior favicon-enabled candidate was 2,771,420 bytes, SHA-256 `92ab17825e1a410940edc7b52a4a1a2f8f7e252c3dd340499a7ce420e3775775`. Its Host Bun 1.4.3 and pinned CI Bun 1.4.2 builds were identical. The following reports refer to that recorded artifact, not to the corrected SMB candidate. Its offline/native runs used Bun 1.4.2, Chromium 155.0.8059.84 and Playwright Core 1.64.1.

| Gate | Observed result | Final evidence under `docs/verification/expansion/` |
| --- | --- | --- |
| Compiled inline bundle | All 202 choices passed | `offline/compiled-bundle-status.json` |
| Declared geometry | 288 collapsed/expanded scenes, 953,825 path samples, no failures | `offline/independent-geometry-status.json` |
| Canonical source semantics | 202 choices, 921 Core configurations, 86 interactions, 36,243 equal-cursor comparisons | `offline/held-objects-source-status.json` and coverage manifest |
| Preserved emitted-context checks | Code3: 12 cases; HTML2 R1: 4 cases, all passed | `offline/code3-environment-bundle-status.json`, `offline/html2-r1-bundle-status.json` |
| Complete expansion native | All 61 IDs in all three modes and all three widths; eight deep cases, seven native-touch cases and fourteen actual-browser-zoom scenes per mode; no failures | `native/expansion-native-status.json` |
| Preserved native UI/accessibility | 573 checks; each mode covered 202 choices in 288 scenes, including 86 expanded scenes, plus supplied-icon decode/byte/pixel equality and off-site-image CSP rejection | `baseline-ui/code1-correction-native-browser-status.json` |
| Preserved held-object native | Each mode passed all 202 initial/final inventories, 36 responsive layouts and HC01-HC09/SSH/Kerberos/local/IPC/exact-value/focus checks | `baseline-held/held-objects-native-status.json` |
| Focused native | All three modes passed responsive/sticky focus, nested F2 help and atomic receipt announcements | `focused-native/held-objects-focused-native-status.json` |
| Actual standalone file | Exact R1/full-prefix equality, compact geometry, 44-pixel targets, CSP/runtime/network checks and actual disconnected-component collection passed | `review-file/review-file-smoke-status.json` |
| Independent cryptographic computations | All 31 cases passed on both Bun 1.4.3 and exact CI Bun 1.4.2 | `crypto-vectors-status.json`, `crypto-vectors-bun142-status.json` |
| Native cost attribution | Twelve baseline/expanded open/closed-index idle-search/replay/in-play-search phases, twenty-four hashed raw CPU/trace files | `performance/expansion-replay-profile-status.json` |
| Full bounded regression | 1,436 tests across 81 files, zero failures; source identity unchanged | `regressions/held-objects-regression-status.json` and all per-file logs |

The full regression ran only after all browser jobs had finished, using unchanged test deadlines. Every failed/superseded attempt remains separately identified under `attempts/`; none substitutes for a final gate. The reviewer package's external status and checksums identify its fresh-source rebuild, extracted-file comparisons and delivered artifact bytes.

The final eight whitelisted desktop/compact/mobile captures and actual browser-rendered SVG/ICO favicon captures were visually inspected. The 390-pixel graph intentionally remains horizontally scrollable with a separate external inventory, not a squeezed unreadable actor grid. This visual inspection does not establish manual screen-reader comprehension or close G01.

## Historical performance and retained material flags

The comparison alternates three fresh isolated contexts per checkout/mode on the same environment. Cold means empty browser storage/HTTP cache, not flushed OS caches. Real Playwright actions and two animation frames are included. These medians are descriptive, not statistically significant. The unchanged material threshold requires both >25% and >100 ms startup or >50 ms interaction growth.

| Loading mode | Metric | Baseline median ms | Expansion median ms | Material flag |
| --- | --- | ---: | ---: | --- |
| Source HTTP | Startup | 1908.6 | 2044.6 | No |
| Source HTTP | Search | 132.4 | 184.6 | Yes |
| Source HTTP | Selection | 861.5 | 683.1 | No |
| Source HTTP | Replay start | 172.8 | 313.5 | Yes |
| Source HTTP | Search while playing | 150.1 | 260.3 | Yes |
| Standalone HTTP | Startup | 1913.0 | 2095.5 | No |
| Standalone HTTP | Search | 135.9 | 185.7 | No |
| Standalone HTTP | Selection | 928.1 | 695.2 | No |
| Standalone HTTP | Replay start | 145.3 | 267.0 | Yes |
| Standalone HTTP | Search while playing | 140.6 | 246.8 | Yes |
| Standalone file | Startup | 1956.6 | 2081.4 | No |
| Standalone file | Search | 125.1 | 174.7 | No |
| Standalone file | Selection | 868.2 | 696.0 | No |
| Standalone file | Replay start | 178.3 | 306.3 | Yes |
| Standalone file | Search while playing | 138.0 | 245.0 | Yes |

The original material legacy-selection regression was resolved by keyed row reuse. The seven replay/search flags above remain in the final report, not hidden behind its behavioral `passed` result. These compare the complete expansion with the accepted Held Objects baseline, not favicon-only before/after performance; application JavaScript and CSS are unchanged by the favicon addition.

Native tracing locates the remaining cost in Blink prepaint/compositing, paint and picker/catalog layout for the larger visible legacy global field index. The visibility-control diagnostic keeps application bytes, catalog and retained field rows unchanged, and closes the pane through its real UI. Idle search starts on Basic; replay and in-play search use the shared refresh journey. Every search preserves its active journey. Closing the pane removes most prepaint cost; the separate idle-search phase still records the larger catalog's picker/layout work:

| Profiled checkout / index | Retained field DOM rows | Idle layout ms | Idle PrePaint ms | Replay PrePaint ms | Playing-search PrePaint ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline / open | 2510 | 36.0 | 15.6 | 62.0 | 90.3 |
| Expansion / open | 5474 | 40.7 | 22.6 | 82.0 | 158.3 |
| Baseline / closed | 2510 | 15.5 | 2.4 | 4.9 | 4.0 |
| Expansion / closed | 5474 | 22.1 | 4.0 | 3.1 | 8.7 |

These are single instrumented diagnostic phases, not replacement latency medians; native trace durations are inclusive and must not be summed. The raw profiles/traces, markers, identities and exact commands are shipped. The conservative choice preserves accepted global-field discovery/focus behavior rather than introducing virtualization or silently hiding the index. New profiled lessons already use journey-scoped initial indexes. Users can close the global pane during legacy playback; its default-open cost remains an explicit review caveat.

## Verification isolation

The application has no runtime package dependencies and remains one offline HTML file. Cryptographic verification dependencies are exact-pinned under `tools/verification/expansion-crypto/`, including their lockfile, provenance and licenses. Native QA has its own `tools/verification/native-qa` Playwright Core 1.64.1 manifest/lock; its frozen installation succeeded with pinned Bun 1.4.2. Neither QA package is imported into the application or included in its build.

The previous favicon-only delta changed no cryptographic-verifier input. This correction pass changes the role-asymmetric transcript-negative fixtures and runs their permanent numeric verifier freshly on both Bun versions. The current raw reports and invocation metadata are under `docs/verification/review-corrections/crypto/`; the packaging gate verifies their runner, dependency, primary-source and fixture digests.

The application build is `bun run build`. The full suite is `bun run test`; comprehensive browser jobs must finish before the heavy full regression generator is started. Verification reports must identify their actual source snapshot, standalone bytes, runner hashes, environment and regeneration command. Accepted Held Objects reports are historical baseline evidence, not proof for this expansion.

## Review and publication boundary

The final reviewer package must include the expanded standalone, complete buildable source, permanent verification tools, independent scenario worksheets, actual reports and hashes. It must be separate from the accepted Held Objects submission. No automatic check closes manual G01, establishes screen-reader speech/comprehension, or proves cross-engine or live Windows/KDC/RADIUS interoperability.
