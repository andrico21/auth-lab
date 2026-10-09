# HTML2 R1 correction handoff - 1.1.2

Version 1.1.2 repairs the follow-up review's remaining AD/Keycloak context inconsistency. Changing the target service now constructs a fresh fixture whose TGS request, proof, clear ticket header, protected-reply schematic and issued/cached credential all name that service. Changing the realm rebuilds their realm-dependent values together. The separate workstation host acquisition remains `host/ws01.a.example`.

The independent [HTML2 recheck](reviews/auth-lab-html2-recheck.html) confirmed all previous **F01-F19 closed** in the delivered 1.1.1 standalone. It reported **R1 (P2)** and retained **G01** as an open native-browser acceptance gate. The report is included unchanged, SHA-256 `003cf0c38e427631b01ac0c800bb0116be117b67a2f4f62f6dc100a30188fef5`.

## Reviewed input and scope

The reviewer examined the exact 1.1.1 HTML: **1,825,607 bytes**, SHA-256 `7f49ff591c7ba43ee73e7ae19ef17c1db1c155957201fc655ee499a80b0352ae`. The preceding source ZIP has SHA-256 `2fad8ed24c080994d77189fd921f092b956a25a1928fc9454f7d7e1dbdb912a6`. Its release status and source manifest are preserved as [1.1.1-release-status.json](verification/1.1.1-release-status.json) and [1.1.1-source-manifest.json](verification/1.1.1-source-manifest.json). Earlier Code1 evidence stays historical under `verification/code1-correction`.

Application changes are confined to `src/kerberos-ad-lab.js`. The correction adds an independent regression file and an emitted-bundle acceptance tool; documentation and release evidence are refreshed. No new scenarios are added: 27 AD/bridge presets, 87 added presets, 130 extended scenarios and 141 deduplicated picker choices remain available. This deliverable does not deploy the project website.

## R1: fresh construction from typed context

Previously, generic scalar projection changed the visible `Ticket.sname` and cached target but left the authored TGS proof target and `EncTGSRepPart` schematic unchanged. Both review examples still reported success with inconsistent internal values.

| Preset | Applied service principal | Required target across service acquisition |
| --- | --- | --- |
| `lab-ad-first-sign-in` | `cifs/other.corp.test` | Request `sname`, proof target, ticket `sname`, protected reply and issued/cached credential all use `cifs/other.corp.test`. The separate host credential remains `host/ws01.a.example`. |
| `lab-kc-kerberos-sso` | `HTTP/other.corp.test` | The same service-acquisition fields all use `HTTP/other.corp.test`; the credential is constructed for the Keycloak acceptor. The existing OIDC transaction and factor policy remain intact. |

All 27 AD/bridge models now expose a typed-context constructor. It validates the illustrative realm/SPN, constructs independent credential/key configuration, clones contextual definitions and actor descriptions, and generates source events and protocol state from that configuration. The shared acquisition builder creates request/proof target, clear ticket identity, protected-reply schematic including `srealm`, and credential target before any simulated issuance. AS/TGT realm values and initial cached credentials are rebuilt too. The bridge selects its actual acceptor before construction instead of rebinding an already constructed issuance.

The constructor does not patch already issued ciphertext or add a lone proof-state binding. Values remain symbolic reference examples; no actual encryption, discovery, account provisioning or network authentication is performed. Each revision creates fresh definitions/state/events. Original scenario objects and the shared attribute registry remain unchanged; Reset reconstructs the authored fixture. Existing scalar bindings still supply participant-card context and the separate OIDC display fields.

This addresses the fixture's internal consistency. It does not assert that every legitimate canonicalized service name must equal a typed alias. This lesson models no alias/canonicalization transition. [RFC 4120 §3.3.4](https://www.rfc-editor.org/rfc/rfc4120.html#section-3.3.4) specifies TGS reply processing and incorporates the reply checks in [§3.1.5](https://www.rfc-editor.org/rfc/rfc4120.html#section-3.1.5), including service/realm expectations, nonce validation and credential storage.

The optional wording polish changes the common AP-REP example to a neutral service-session label, so the HTTP bridge no longer labels its session key as CIFS.

## Acceptance evidence

Final results and exact tested bytes are recorded in [verification/html2-r1-correction](verification/html2-r1-correction) and the preserved [1.1.2-release-status.json](verification/1.1.2-release-status.json). The full suite runs before the final build because a bundle integration test can rebuild `dist`.

The final frozen-input full suite passed **775/775**, with zero failures, cancellations, skips or todo cases, in **770.021 seconds** on Node.js 24.19.0. The final standalone is **1,828,361 bytes**, SHA-256 `1a69e1ccf8abdc66296e165c1c90a136fa684d23438d3b4843c46f8a0100d58b`. Its native preflight binds these exact bytes while retaining `verified: false`.

The independent `tests/html2-context-r1.test.mjs` checks both reported SPNs, alone and with an alternate realm. It covers actual Apply handlers, full TGS reply inspection, the focused `adTGSReply` Send moment and complete source-prefix state, animated packet value, independent host acquisition, replacement of the prior focused context, Reset and unchanged base fixtures. It also checks all 27 constructors, including cached and denied paths, without allowing a context edit to turn a failure into success.

The final targeted regression run passed **31/31**, with no failures, skips or cancellations, in **31.181 seconds**. The identical final test file against the immutable 1.1.1 ZIP source failed **31/31**: four concrete Apply/reply mismatches and 27 missing typed constructors. A separate baseline capture records 15 direct field comparisons: nine already correct and six failing (proof, protected reply and focused Send in both presets). This distinguishes the substantive inconsistency from the constructor-interface assertions. Logs, captured values and hashes are retained separately from the full-suite result.

An additional read-only peer probe checked **54 contextualized models**, **210 exact ticket-target occurrences**, **32 focused Send moments** and **1,096 ledger/state prefixes**. The executed probe, actual output, source hash and limits are preserved in this evidence directory. It found no inconsistent target, stale realm or mutated base fixture. These are independent source/trace checks, not browser observations.

The portable `tools/verification/html2-r1-bundle-check.mjs` executes the actual emitted inline JavaScript with the existing deterministic DOM harness, repeats the four Apply/full/focused/Reset cases and records the exact HTML hash. All **4/4** emitted-context cases passed on the final hash above, including actual transmitted service/host requests, full and focused replies, final credential target and Reset. The broader emitted-bundle smoke and independent route sampler cover the complete catalog. Script/style CSP hash integrity is checked separately from native enforcement. Emitted catalog smoke passed **141/141** choices with exact CSP hashes. Offline geometry passed **224** collapsed/expanded scenes over **825,829** sampled points, with no intersections, overlaps or boundary failures in logical bounds.

To rerun from the repository root with Node.js:

```sh
node --test --test-concurrency=2 tests/*.test.mjs
node build.mjs
AUTH_LAB_QA_EVIDENCE_DIR=docs/verification/html2-r1-correction node tools/verification/html2-r1-bundle-check.mjs
AUTH_LAB_QA_EVIDENCE_DIR=docs/verification/html2-r1-correction node tools/verification/compiled-bundle-smoke.mjs
AUTH_LAB_QA_EVIDENCE_DIR=docs/verification/html2-r1-correction node tools/verification/independent-geometry-check.mjs
```

## G01 and evidence limits

**G01 remains open.** Current capability discovery found Playwright but no usable Chromium, Firefox or WebKit executable and no callable native-browser tool. No blocked download was repeated. The final native preflight records `verified: false`, zero native checks/screenshots and the corrected artifact hash. A blocked preflight is not an acceptance pass.

The native runner already covers the new families, collapsed/expanded components, fresh/legacy/nested help, keyboard/focus restoration, replay/seek, long runtime values, desktop/narrow/reduced-motion layouts, modular HTTP source, HTTP standalone and direct `file://`, and actual CSP violation attribution. Its smaller viewports exercise zoom-equivalent reflow; browser-menu 200%/400% zoom and manual visual/accessibility review remain required. See [verification tools](../tools/verification/README.md).

No native screenshot, actual browser text fit, Tab order or CSP enforcement is claimed here. Node/DOM geometry uses logical bounds, not real browser rectangles. Neither these checks nor the reviewer report certify live AD, Keycloak, OpenSSH, Smallstep or SSSD interoperability or real cryptographic execution. Bun was not installed; the executed build and regression commands use Node.

## Reviewer sequence

1. Verify the new artifact hash against `release-status.json` and distinguish it from the reviewed 1.1.1 bytes.
2. In `lab-ad-first-sign-in`, change only Service principal to `cifs/other.corp.test`, Apply, inspect the target-service TGS request/reply and final state. Repeat in `lab-kc-kerberos-sso` with `HTTP/other.corp.test`.
3. Focus `adTGSReply`, select its target-service Send moment and compare its exact instance value and state with the full source event. Confirm the separate workstation host acquisition still uses `host/ws01.a.example`.
4. Repeat with realm `CORP.EXAMPLE`, reapply during focused playback, then Reset. Confirm playback/context reset and the complete original fixture returns.
5. Run the full suite and emitted-context tool. Inspect cached, unknown-SPN, stale-key and required-MIC negative presets; preserve the previously verified F01-F19 corrections.
6. Execute native acceptance on these exact bytes in a browser-enabled environment, record browser/version and screenshots, and complete manual zoom/focus/containment/CSP review before final sign-off.

## Code3 follow-up

The unchanged [Code3 final review](reviews/auth-lab-code3-final-review.html) independently confirmed R1 and F01-F19 closed in 1.1.2, including a separate 775-test suite and byte-identical rebuild. It reported R2/R3 environment-contract defects; the 1.1.3 [correction handoff](code3-environment-corrections.md) covers their repairs. G01 remains open. Results above refer to the exact historical 1.1.2 bytes.
