# Code3 environment corrections - 1.1.3

Version 1.1.3 repairs **R2 and R3** from the independent [Code3 final review](reviews/auth-lab-code3-final-review.html). Invalid environment input now produces a recoverable field-associated error before replacing the active context or model. A realm-qualified service principal is parsed into a service name and its realm before constructing a fixed single-realm lesson.

The reviewer independently confirmed **R1 and F01-F19 closed** in 1.1.2. **G01 remains open**: no native-browser acceptance is claimed. The supplied review is included unchanged, SHA-256 `76d08bda39a2456c52b6f56fb391a9b4f97a7f23c1a4e3ed819b6dc7fdbcc557`.

## Reviewed input and scope

Reviewed 1.1.2 source ZIP: SHA-256 `f4b12f17f4c44957bf8be04213e2b254e3e76a452275116c14aea33b211500e4`. Reviewed standalone: **1,828,361 bytes**, SHA-256 `1a69e1ccf8abdc66296e165c1c90a136fa684d23438d3b4843c46f8a0100d58b`. Its release records are preserved in [1.1.2-release-status.json](verification/1.1.2-release-status.json) and [1.1.2-source-manifest.json](verification/1.1.2-source-manifest.json). Earlier Code1 and HTML2 evidence remains historical.

Changes cover `app.js`, `runtime-environment.js`, `scenario-context.js`, the AD and crypto constructors, the new shared `kerberos-context.js`, and the standalone build's module order. New independent tests and an emitted-bundle acceptance tool accompany the fixes. Scenario IDs and selected success/failure policies are preserved: 27 AD/bridge models, 17 crypto models, 87 added presets, 130 extended scenarios and 141 picker choices. No website deployment is included.

## R2: shared validation and candidate-before-commit Apply

The previous form accepted a 255-character realm while the new AD constructor rejected it after Apply had already committed it. The resulting invalid current model could throw again when the operator tried to correct the draft.

The form and AD/crypto constructors now use one shared input contract. The selected realm limit is **1-254 ASCII letters, digits, dots, underscores or hyphens, starting with a letter or digit**. This is explicitly a bounded teaching-app contract, **not a universal RFC Kerberos realm-length rule**. An empty override restores the preset's example realm. The form explains the limit beside the field.

Apply validates the active input, constructs an immutable candidate context, normalizes its service identity, and invokes the candidate model constructor before committing context or revision. Constructor errors return a recoverable inline result. The handler identifies the affected field with `aria-invalid` and `aria-errormessage`; valid input clears that association. Unknown construction errors receive a plain recoverable message without exposing internals.

On rejection, committed context, revision, active model, cached scene, player queue/status, selected moment, visited links, packet and reconstructed protocol state remain intact. The draft stays editable. Correcting it and applying again succeeds without Reset. Active-field merging retains previously applied values for inactive fields, so a rejected hidden Kerberos draft cannot enter a later SSH-only transaction. Successful Apply uses the already constructed candidate and resets playback/context normally; Reset restores the authored fixture.

## R3: bounded parsed service identity

The shared contract produces one frozen service identity before any symbolic request, proof or credential is issued. Both AD/bridge and all PKINIT/FAST constructors consume it. Accepted principal input is bounded to 2,048 characters and the documented service-name syntax.

| Input | Fixed single-realm behavior |
| --- | --- |
| `HTTP/server.corp.example` | Use that service name in the preset's effective Kerberos realm. |
| `HTTP/server.corp.example@CORP.EXAMPLE`, with realm `CORP.EXAMPLE` | Separate the exact matching qualifier; `sname` is `HTTP/server.corp.example`, and service realm is `CORP.EXAMPLE`. |
| `cifs/review.other.example@OTHER.EXAMPLE`, with blank realm override | Reject: the effective example account realm is `A.EXAMPLE`. The message points to the separate cross-realm lessons. |
| Conflicting case/realm, multiple `@`, or backslash notation | Reject rather than silently reinterpret it. General escaped principal syntax is outside this lab contract. |

Realm matching is exact. The parser does not silently change the account realm, generate forest referrals or modify the independent `host/ws01.a.example` acquisition. Raw qualified input remains in the draft for editing; applied context stores the normalized service name. Request `sname`, proof target/realm, clear ticket name/realm, protected `EncTGSRepPart` schematic, issued/cached target and full/focused Send all derive from the same identity. Accepted matching qualification constructs the same reference fixture as its unqualified form.

The generic projection and participant-row helpers also normalize a matching qualified context retained by a caller after fixture construction, using that model's effective realm. They cannot reintroduce `@REALM` into a separately constructed service name. No ciphertext or signature is text-patched, and original model definitions/events/state remain unchanged.

[RFC 1964 §2.1.1](https://www.rfc-editor.org/rfc/rfc1964.html#section-2.1.1) defines principal-string separators and quoting; this lab explicitly restricts the supported input subset. [RFC 4120 §5.2.2](https://www.rfc-editor.org/rfc/rfc4120.html#section-5.2.2), [§5.3](https://www.rfc-editor.org/rfc/rfc4120.html#section-5.3) and [§5.4.2](https://www.rfc-editor.org/rfc/rfc4120.html#section-5.4.2) represent principal name and realm separately in principal identity, tickets and protected replies. The rejected qualifier is not ordinary service-name text.

## Independent acceptance evidence

Final evidence is in [verification/code3-correction](verification/code3-correction); [release-status.json](verification/release-status.json) identifies the current final bytes. Historical full-suite passes do not substitute for testing this revision. The complete frozen-source run passed **802/802** in **556.234 seconds** with Node.js 24.19.0, with zero failures, cancellations, skips or todo cases. All 106 captured source/test/build inputs remained unchanged. The final build followed that run because a bundle integration test can rebuild `dist`.

The independent `tests/code3-environment-contract.test.mjs` passed **27/27**, with zero failures, skips or cancellations, in **134.572 seconds**. The identical frozen file against the immutable 1.1.2 source ZIP produced **4 passes and 23 failures**, in **75.039 seconds**. This preserves existing valid boundary/unqualified behavior while reproducing the new counterexamples. Logs and their actual hashes are retained.

Coverage includes the accepted 254-character boundary, rejected 255/2,048-character realms, visible error/field association, exact rejected context/model/playback preservation, injected constructor failure, corrected Apply without Reset, inactive draft isolation, unqualified/matching/conflicting SPNs in AD and Keycloak, shared PKINIT/FAST behavior, request/ticket/proof/reply/cache consistency, focused Send and packet value, direct projection/participant rows, Reset and immutable base fixtures. Existing R1 regressions remain in the complete suite.

Additional independent peer probes exercised the actual Apply handlers in **AD, Keycloak bridge, PKINIT and FAST TGS**, plus **8** raw-context projection/row cases. They verified rejection while playing or paused, candidate construction before commit, recovery without Reset and unchanged source hashes. Their original-location scripts, output and scope are preserved as execution transcripts in `peer-probes`; their relative imports are not portable from that archive location. Use the maintained tests and runner below for reruns. A first probe comparison mistake is retained as an explicitly superseded attempt; no application change resulted from that attempt.

The same folder retains a separately labeled historical constructor probe across 44 AD/crypto models: 132 matching contexts and 308 rejected contexts. Its output includes the intermediate raw-projection counterexample that led to the subsequent projector repair. That historical source snapshot is excluded from final-source acceptance counts; the later 4-family/8-projection probe covers the corrected source.

The portable `tools/verification/code3-environment-bundle-check.mjs` evaluates the actual emitted inline IIFE with only the deterministic DOM harness. Its **12/12** named cases pass for the two reported model families across realm lengths 254, 255 and 2,048 and unqualified/matching/conflicting principals, including rejection preservation, recovery and Reset. It records exact artifact bytes/SHA-256 and `nativeBrowser: false`. The previous HTML2 emitted-context check passes **4/4** R1 cases against those same bytes. Broader catalog smoke passes all **141** choices and exact CSP hashes. Offline geometry passes **224** scene variants and **825,829** sampled points without errors.

The first emitted-tool attempt is preserved in [code3-environment-bundle-attempt1](verification/code3-correction/code3-environment-bundle-attempt1): 6 cases passed and 6 failed because the verifier incorrectly required raw source-event index zero while an attribute trace was selected. A restarted focused trace correctly has visible/trace position zero and a source index at the attribute's first occurrence (9 for AD, 7 for the bridge). Only that verifier assertion was corrected; the application, regression tests and final HTML bytes remained unchanged. The maintained runner asserts the first trace step and its source index in focused mode, and source index zero in full mode.

Final standalone: **1,833,704 bytes**, SHA-256 `918b601be9ac8c3e1832097a0a214ac1ff3a43f8d7a678a92e6bf7082f9689bd`. The source/test/tool manifest has **112 files**, with canonical SHA-256 `546e2336550ae62209166554749e9ba6a54b292e580e2f727e1e0e6a6ac8e177` (UTF-8 JSON with sorted keys and compact separators). The delivered standalone and `dist/auth-flow-studio.html` in the source ZIP are byte-identical. No application or regression-test source changed after the complete run; the final emitted-tool correction and rerun are recorded separately above.

To rerun from the repository root with Node.js:

```sh
node --test --test-concurrency=4 --test-reporter=tap tests/*.test.mjs
node build.mjs
AUTH_LAB_QA_EVIDENCE_DIR=docs/verification/code3-correction node tools/verification/code3-environment-bundle-check.mjs
AUTH_LAB_QA_EVIDENCE_DIR=docs/verification/code3-correction node tools/verification/html2-r1-bundle-check.mjs
AUTH_LAB_QA_EVIDENCE_DIR=docs/verification/code3-correction node tools/verification/compiled-bundle-smoke.mjs
AUTH_LAB_QA_EVIDENCE_DIR=docs/verification/code3-correction node tools/verification/independent-geometry-check.mjs
```

## G01 and remaining limits

**G01 remains open.** Fresh capability discovery again found no usable browser executable or callable native-browser tool; no download was retried. The final preflight binds the corrected final artifact hash and records `verified: false`, zero native checks and zero screenshots, with the reason “No Chromium executable is installed.” This is a blocked gate, not an acceptance pass.

The prepared native runner covers modular HTTP source, HTTP standalone and direct `file://`; new actor families; collapsed/expanded internals; participant/nested help; F2/Tab/Escape and focus restoration; replay/seek; long values and narrow/reduced-motion layouts; and attributable CSP violation probes. Smaller CSS viewports are explicitly reflow equivalents. Actual browser-menu 200%/400% zoom, visual legibility/clipping, pointer/touch and manual accessibility review remain required. Chromium execution alone would not establish cross-engine support.

Node/DOM and logical geometry checks do not establish native rendering, real Tab order or enforced CSP. This is a symbolic reference lab, not live AD/KDC, Keycloak, OpenSSH, CA, SSSD or security-key interoperability or cryptographic certification. Bun remains unexecuted in this environment.

## Reviewer sequence

1. Check the final HTML/source hashes and the unchanged Code3 review report. Distinguish current evidence from the preserved 1.1.2 results.
2. In both AD first sign-in and Keycloak SSO, try realm lengths 254, 255 and 2,048. On rejection, inspect the error association and unchanged playback/context, then enter `CORP.EXAMPLE` and Apply without Reset.
3. Compare unqualified SPN, an exact matching `@REALM` qualifier, and `@OTHER.EXAMPLE`. Confirm accepted service name and realm remain separate; conflicting input does not imply cross-realm success or move the account realm.
4. Compare request, ticket header, protected reply, proof and cache in the full journey and focused `adTGSReply` Send. Repeat with PKINIT/FAST. Confirm local host independence, active reapply, Reset and unchanged base fixtures.
5. Inspect the full suite and exact emitted-bundle evidence; preserve the previously verified R1/F01-F19 corrections.
6. Run native acceptance against the corrected bytes in a browser-enabled environment and finish the manual checks before final sign-off.
