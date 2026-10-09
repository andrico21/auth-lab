# Kerberos and SSH implementation handoff

Prepared on 9 October 2026 for independent review; updated to **1.1.3** after Code1, HTML2 and Code3 reviews. This is the implementation of the approved Kerberos/SSH research plan, based on the supplied current `auth-lab-main` source archive. The app and its teaching text are English. The delivered build is a single offline HTML file; no website deployment is part of this handoff. [The earlier handoff](code1-review-corrections.md) records F01-F19, independently confirmed closed. [The R1 handoff](html2-r1-correction.md) covers typed AD/bridge reconstruction. [The Code3 handoff](code3-environment-corrections.md) covers candidate-before-commit Apply and parsed single-realm service identities; the native gate stays open.

## Inputs and review target

| Input | Identity |
| --- | --- |
| Supplied current source archive | `auth-lab-main.zip`, SHA-256 `5385577a8c6e2b4c206130594ebf419d9a9a2a65e068bc9b59afe6cf529e8950` |
| Original standalone HTML | SHA-256 `9b2ce7821c415491f8862b353025eef7135158387f0531850f650d187cc4a1c1` |
| Approved research plan, including R1 correction | `research/auth-lab-kerberos-ssh-research-plan.html`, SHA-256 `d3180997145b262f926802c75c6ad477c1cea406f38b08b666fe3d9697a0301b` |
| Current implementation | This source tree, package version `1.1.3`, and `dist/auth-flow-studio.html` |

The two original reviewer attachments were read from the supplied local files and left unchanged. The old historical v14 working tree was not used as the implementation baseline. Historical validation files remain in the archive as history; the current evidence lives in `docs/verification`.

## What was added

Three workspace tabs use the same scenario registry, attribute index and player. The initial view remains Basic Keycloak sign-in. SSH opens a complete corporate-SSO-to-certificate journey. Kerberos opens first AD domain sign-in, with separate AD DS and Keycloak bridge families. Fixed presets keep prerequisite and failure choices out of the ordinary student path.

| New module | Presets | Coverage |
| --- | ---: | --- |
| `src/kerberos-ad-lab.js` | 27 | Password logon, workstation host ticket/PAC, credential caches, Kerberos failures, Keycloak SPNEGO, two MIC rejection profiles, continuous OIDC/PKCE and assurance/factor policy |
| `src/kerberos-crypto-lab.js` | 17 | Fresh-DH PKINIT, certificate/account/KDC trust rejection, FAST AS and TGS, armor prerequisites, fallback and protected-message failures |
| `src/kerberos-forest-lab.js` | 14 | One-way/two-way trusts, child/root referrals, three forests, nontransitivity, selective authentication, SID/PAC/ACL checks and cache paths |
| `src/ssh-access-lab.js` | 29 | OIDC certificate enrollment, independent SSH trust/proof checks, reissuance, lifetimes, Device flow, remote SSSD/PAM and SSH GSS-API |
| Total additions | **87** | Fixed, inspectable teaching fixtures |

Together with the original 43 extended web scenarios this yields **130 extended scenarios**. The global picker has **141 deduplicated choices**: 130 extended scenarios, Core lab and 12 ready presets, with SPA/BFF presets sharing two extended models. `new-scenario-inventory.md` is generated from the implemented registry and records exact IDs and source-event counts.

The original web core, SAML/JWE, named external-provider profiles, attribute help, F2, pause/speed/scrub, connection replay, names-only overlays, participant movement and page-memory environment controls remain integrated. No new application dependency was added.

## Architecture and contracts

### One registry and one player

`lab-catalog.js` merges the new scenario modules with the original registry. `workspaces.js` assigns scenarios to a workspace and maps only allowlisted IDs to routes. An unknown route returns to Basic Keycloak sign-in. Browser Back/Forward uses the existing history entry rather than adding another one. Hash routes contain fixed workspace/scenario IDs; operator-entered addresses and protocol objects are never serialized there.

Each scenario owns its participant definitions, positions, initial state, source events, protocol effects, object records and occurrence metadata. The player draws scenario-owned actors rather than assuming the original eight web actors. Visible grouping maps logical actors to a parent card when internals are folded. AS and TGS remain distinct protocol owners. Inventory rows retain their logical owner. Expanding or folding internals changes only presentation, including routes; it does not rewrite participants, state or source events. Focused attribute study can reveal the required component automatically.

`layout.js` routes connections around the visible cards and labels network versus local/IPC actions. Per-authority visual boundaries supplement individual participant cards. The new inline SVG agent and smart-card illustrations are code-native, preserving the one-file/no-external-asset contract.

### Protocol state is reconstructed from the full source prefix

`protocol-state.js` is a pure reconstruction layer. `reconstructProtocolState(model, eventIndex)` starts with the scenario's initial state and replays every preceding source event through the selected event. Attribute filtering and connection replay never drop intervening state changes. Scrubbing backwards reconstructs a previous state rather than preserving future outcomes or host knowledge.

Protocol effects use explicit `put`, `remove`, `append` and `advance` operations. The protocol clock advances only through authored protocol events. Animation speed, pause, drag, expansion and seek do not make tickets expire or accelerate a polling requirement.

`buildProtocolInstances` preserves object identity, creator, holders and allowed inspectors. Occurrences identify `instanceId`, `definitionId`, `fieldPath`, `representation`, `sourceEventId` and exact value/reference. Initial objects use the `initial` source event. A scenario/context revision adds a qualified identity scope, while local protocol references remain stable. The same instance/field/representation cannot silently change its encoded value. Wire occurrences do not borrow a generic glossary example or expose a future decoded field.

Protected fields can be explained in the glossary without pretending their plaintext travels alongside ciphertext. The object inspector's permitted inspectors are explicitly the union of the declared field inspectors; possessing an opaque object does not automatically grant inspection of every protected field.

### Runtime environment remains page-owned

The optional panel adds typed fields for the Kerberos realm, service principal, CA URL, SSH host and Unix account where applicable. Draft edits do not affect the active model until valid input is applied. Card context displays the selected concrete address or realm; the additional map context allows long values to wrap.

`scenario-context.js` uses declared scalar bindings and templates. It does not replace arbitrary substrings inside tickets, signatures, encrypted values or private keys, and it does not create future credentials in initial state. Multi-forest lessons keep distinct explicit realm contexts instead of applying a single realm input to every authority.

AD baseline and Keycloak bridge now have explicit typed-context constructors, alongside PKINIT/FAST. They construct fresh request/proof targets, realm values, clear ticket headers, protected-reply schematics, key relationships and initial/issued/cached credentials together. The local host acquisition remains independent of the requested remote service. Apply creates a new revision and resets playback; Reset returns to the original fixture. No already issued ciphertext is rewritten.

SSH has an explicit contextualizer. Changing the illustrative Unix account or issuer creates a new scenario/context revision and rebuilds its subject mapping, account policy, definitions, events, state and synthetic certificate encoding together. It does not edit an already signed object or change the base fixture. Negative branches retain their intended mismatch. This is synthetic fixture construction, not live account provisioning or cryptographic issuance.

Runtime values remain in the open page. Reset/page lifecycle cleanup discards them. There is no IdP discovery, network connection, storage, address-bearing history route or environment export. The independent code verifier, SSH private key, session identifier and protected Kerberos fields remain local to their designated owners.

## Protocol invariants requiring reviewer attention

### AD baseline and R1

- First password sign-in separates the user long-term key, realm `krbtgt` key, workstation computer key, TGT session key, local host credential and later remote-service session key. The Windows host-ticket/PAC stage occurs before the separate remote resource access.
- No credentials, TGT-only and cached-service presets have different acquisition paths. Reusing a service credential still creates a fresh authenticator.
- **Unknown SPN** is a TGS acquisition rejection; no new target service credential is installed.
- **Stale service key** follows successful TGS issuance, client reply checks and credential caching. The acceptor fails after receiving AP-REQ. The issued client credential remains cached. There is no successful service security context, AP-REP or resource access. Client knowledge changes only when the returned result reaches it.
- Skew, expiration, authenticator replay and resource ACL denial remain distinct checks. Kerberos authentication success does not imply resource authorization.

### Keycloak bridge and MFA

The bridge starts with one application authorization transaction: `client_id`, redirect, state, nonce, PKCE verifier/challenge and pending code state. HTTP Negotiate wraps the Kerberos exchange in SPNEGO. Mechanism negotiation, `mechListMIC` when required, mutual authentication, configured principal-to-user mapping and realm policy precede the OIDC result. No NTLM fallback is invented. Channel-binding status is explicit; HTTPS is not treated as proof of channel binding.

The Alternative Kerberos / Forms-only OTP lesson intentionally demonstrates an OTP bypass. Separate presets implement a stated required-factor or age-bounded assurance contract. They cover password fallback, weak/sufficient cookies, fresh factor requirements, allowed age reuse, expired age, missing enrollment, incorrect/cancelled factor, unsupported assurance and `prompt=none`. Required-UV WebAuthn distinguishes presence/touch from user verification. Kerberos is not automatically labeled MFA. Failure branches issue no successful authorization result. The original application correlation and PKCE proof continue through the factor sequence.

These are reference flow policies, not imported Keycloak realm exports. Review an actual deployment's authenticator executions, requirement levels and assurance mapper before claiming interoperability.

### PKINIT and FAST

PKINIT uses the fresh-DH branch with separate CMS/AuthPack, DH request/reply data, certificate trust, account binding, KDC trust, DH material, reply key and TGT session key. Reused-DH nonces are not inserted into a fresh-DH fixture. Windows strong-binding enforcement and Windows Server 2025 DH/RSA policy gates are documented assumptions, not measured Windows behavior.

FAST AS explicitly distinguishes the machine bootstrap, armor credential, user key and protected challenge/reply. Required FAST without armor or a suitable DC fails; optional fallback is visible. An invalid request-binding checksum is rejected before decoding the protected body. Response nonce and finished-ticket checks happen before usable credentials are installed.

The ordinary FAST TGS branch selects implicit armor and requires its authenticator subkey and strengthening material. Missing-subkey and missing-strengthener presets terminate; session/reply/armor keys remain separate objects. No generic claim that every Windows build follows one fixture is made.

### Forest trust and referrals

One-way **B trusts A** permits an A account to access a B resource under policy; the reverse preset is denied. Two-way trust has separate A-to-B and B-to-A journeys. The child-domain cross-forest journey explicitly traverses child A, root A, root B and child B, without an invented shortcut or cache. A three-forest relationship does not imply A-to-C access; a separate preset supplies the explicit C-trusts-A relationship.

Home TGTs are explicit initial credentials. Each referral/service credential has its own identity, encryption relationship, session key, validity and new authenticator. Original `cname`/`crealm` survives the referral path. KDC request-body checksums, per-authority replay caches, PAC processing, SID filtering, selective authentication and resource ACLs are separate checks. The MS-KILE reference explains Windows `transited` handling rather than treating an RFC realm list as a universal Windows trace.

### SSH is several architectures

1. **OIDC to SSH certificate:** the native CLI owns loopback callback, state and PKCE. The CA receives its configured provisioner's ID token and the public key plus requested principal policy. Its expected ID-token `aud` is `step-ssh`, independently of API audiences. There is no mandatory PKCS#10 CSR or enrollment proof-of-possession invented for this API. The normal remote SSH server receives an OpenSSH certificate and a session-bound private-key proof; it receives no OAuth token or private key. Host-key trust, user-CA trust, certificate validity, Unix principal/account policy and signature proof are independent checks.
2. **Headless enrollment:** RFC 8628 device transaction, user approval and CA enrollment happen before SSH authentication. Pending polls obey the returned/default interval, each `slow_down` adds five seconds, and timeout backoff is explicit. Cancelled transactions ignore late results; restart uses a new transaction. Smallstep live-source polling differences are disclosed as comparison evidence, not claimed literal RFC-conformant same-release behavior.
3. **Remote SSSD/PAM:** SSH transport is established first. The remote host owns the Device OAuth client. Separate NSS/IdP lookup and its confidential service-account/API permission are prerequisites. The SSH prompt carries only verification instructions and the human code; `device_code` and OAuth tokens remain remote. One ENTER response and the zero-prompt comparison respect RFC 4256 prompt counts. The approved subject/domain must match the requested identity, then local account policy must allow access. No general assumption that these tokens are cached for later login is made.
4. **SSH GSS-API:** RFC 4462 mechanism context and session-bound MIC precede account policy. This is not HTTP Negotiate/SPNEGO and does not carry HTTP headers.

The lifecycle view separates provider session, enrollment token, certificate and established SSH connection. Expiring an enrollment token or certificate does not automatically tear down an already established connection. Revocation knowledge is local and timestamped by source events; rewind cannot give a host future knowledge. Positive user-certificate reissuance requires fresh approval and new OIDC/PKCE/code/token/certificate objects, while retaining the selected key identity.

## Evidence and acceptance limits

Read `docs/verification/release-status.json` for the current final counts and standalone hash, and `docs/verification/code3-correction/node-tests.tap` for the current complete regression result. The 1.1.2 reports under `html2-r1-correction`, the 1.1.1 reports under `code1-correction` and earlier 1.1.0 reports, including `final-node-tests.tap` and `initial-integration-tests.tap`, remain historical. Targeted reruns alone are not represented as a whole-suite pass.

The supplied baseline passed **465/465 tests** before implementation with Node.js 24.19.0. Added tests include model-specific protocol checks, every-event-prefix ledger regressions, workspace navigation/context/state integration and preservation of the existing web scenarios.

The initial 1.1.0 offline geometric check covered **139 choices**, **221 scene variants** and **814,566 sampled points**. The current correction's separately rerun geometry is recorded under `docs/verification/code3-correction` and summarized in the release status. These checks use emitted SVG routes and logical card bounds; they do not measure browser font wrapping or real CSS rectangles.

The compiled smoke check parses the actual emitted IIFE, evaluates it in the DOM harness, verifies exact script/style CSP hashes and selects every registered choice. It verifies bundle assembly and hash consistency, not native CSP enforcement.

**Native-browser acceptance remains unverified.** The environment has a Playwright package but no usable browser executable, and the browser download was blocked by HTTP 403. No screenshot, keyboard-accessibility, actual text-overflow or browser-enforced CSP result is claimed. The portable runner in `tools/verification/native-browser-acceptance.mjs` supports modular source, served standalone and direct `file://` use. Its README lists setup, manual zoom/focus/resize/movement review and the limits of automation. A blocked runner writes `verified: false`.

No real Windows/AD/Keycloak/SSSD/Smallstep/OpenSSH interoperability test or cryptographic execution has been performed. Product source links, documented contracts, version gates and synthetic event fixtures are reference evidence. They must not be relabeled as observed packet traces.

## Review sequence

1. Open the standalone file; confirm the ordinary one-realm OIDC default is still clear. Use workspace tabs, local catalog and global inline search. Check browser Back/Forward and direct fixed routes.
2. Start `lab-ad-first-sign-in`, then compare cache presets, unknown SPN and stale service key. Scrub around issuance, caching, acceptor failure and returned client knowledge.
3. Compare `lab-kc-kerberos-alternative-otp-skip`, `lab-kc-kerberos-fresh-totp` and required-UV WebAuthn. Trace `client_id`, state, nonce, PKCE and factor claims across the entire application transaction.
4. Examine PKINIT, FAST checksum rejection and mandatory TGS strengthening. Select protected fields and confirm wire overlays do not reveal plaintext or unrelated key material.
5. Follow all four KDCs in `lab-ad-forest-child-domains`. Compare one-way reverse rejection, three-forest nontransitivity, selective authentication and ACL denial. Fold/expand without changing object ownership.
6. Follow `lab-ssh-cert-success`, audience/principal failures, copied certificate and wrong-connection signature. Trace each trust key and compare SSH proof with OAuth/CA enrollment.
7. Review reissuance and the four lifetime cards; seek backwards and switch to filtered field playback. Check that protocol state equals the complete corresponding source prefix.
8. Compare Device cadence/cancel/restart with remote SSSD client ownership. Check approved-Bob/domain/account failures and identity-lookup failure before Device transaction creation.
9. Apply long illustrative URLs and a custom Unix account. Check card context, message/definition/state agreement and complete synthetic certificate regeneration; reset/reload and verify no operator data persists.
10. Run native browser acceptance with a real browser. Review F2/help focus, participant movement, 200%/400% zoom, reduced motion, long context wrapping, overlay containment and actual CSP blocking. Review all support/version badges before accepting a vendor-specific statement.

## Build and deliberate deferrals

The build concatenates the dependency-free source modules in dependency order, embeds CSS and SVG art, and computes exact hashes over the emitted normalized script/style text. `dist/auth-flow-studio.html` remains the only required runtime file. `node build.mjs` and `node --test tests/*.test.mjs` were used here. Bun scripts remain available, but a Bun executable was unavailable for this edition's verification.

No separate Kerberos executable/page, backend, discovery service or dependency bundle was added. Teleport, Vault and SSH FIDO/security-key comparisons remain planned comparison work rather than full implemented vendor journeys. Existing web WebAuthn/FIDO2 lessons remain available. Real packet traces and version-specific deployment exports are also outside this implementation's evidence. These boundaries match the reference-lab scope and should remain visible during review.
