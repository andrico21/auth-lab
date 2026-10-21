# PAKE foundations protocol worksheet

The seven independently authored worksheets are in `pake-scenarios.json`. They precede the animation implementation. Workspace: Foundations. Families: `pake-spake2` and `pake-spake2plus`. These are standards-based teaching profiles, not AD DS, Keycloak or browser API features. No application authorization, KDC, TGT, OAuth token or cookie follows PAKE completion.

## Provenance and pinned profiles

Sources retrieved 2026-10-21:

- [RFC 9382](https://www.rfc-editor.org/rfc/rfc9382), September 2023, sections 3, 4, 6, 7 and Appendix B. Badge: **RFC 9382 - IRTF Informational**. [Errata lookup](https://www.rfc-editor.org/errata/rfc9382) returned no matching errata on retrieval date.
- [RFC 9383](https://www.rfc-editor.org/rfc/rfc9383), September 2023, sections 1, 3.2-3.4, 4, 6 and Appendix C. Badge: **RFC 9383 - Independent Submission / Informational**. [Errata lookup](https://www.rfc-editor.org/errata/rfc9383) returned no matching errata on retrieval date.

Crypto QA fixture IDs are `rfc9382-B-1-p256-sha256` and `rfc9383-C-1-p256-sha256`; controlled variants use suffixes `password-mismatch`, `transcript-mismatch` and `invalid-point`. Validators are authored independently under the verification-only crypto tools. Their execution is parent-owned; no successful vector validation is claimed here.

Both fixtures use P-256, cofactor 1, SHA-256, HKDF-SHA256, HMAC-SHA256, fixed RFC M/N and uncompressed SEC1 point encoding. RFC 9382's first vector assigns **A = server, B = client**, not the opposite. `pake-a` is therefore the first sender/M role, named A (server identity), and `pake-b` is the second sender/N role, named B (client identity). RFC 9383 assigns `idProver = client`, `idVerifier = server`, with exact Context `SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors`.

Runtime values are conspicuous symbolic references to individual fields of those fixtures, not plausible-looking arbitrary hex. The RFCs supply password-equivalent scalar inputs directly and omit the actual password/PBKDF/MHF mapping. The lesson does not claim an invented password, salt, iteration count or PBKDF reproduces those scalars. Synthetic password-input handles explain ownership only. Cryptographic calculation and validation stay outside the runtime app.

## Balanced versus augmented PAKE

SPAKE2 provisioned input is password-equivalent on both sides. A stolen endpoint setup secret can be used to act in that endpoint's role. A recording of the public exchange does not itself create an offline password test. Online guessing and endpoint compromise remain separate threats.

SPAKE2+ stores `(w0,L)` with `L=w1*P` at the verifier. The prover uses `w0,w1`; the verifier does not receive the password or `w1`. The selected enrollment method is a **teaching-only authenticated confidential out-of-band administrative provisioning channel**. RFC 9383 defines record computation, not this chosen transport. The enrollment arrow carries an opaque protected envelope and has separate decoded record representations. No observer can read its record by ordinary recording.

The disclosure lesson adds an explicitly named `pake-observer`. Prior to the disclosure event, it records only public shares, public confirmation tags and the opaque enrollment envelope. Afterwards it has a distinct readable copy of `(w0,L)`. Record compromise enables verifier impersonation and permits offline password guessing if the password-derivation parameters are available. Impersonation as the prover still requires password recovery/equivalent `w1` (or solving the discrete logarithm of `L`); the stored record is not a direct prover credential. A record disclosure does not grant old ephemeral session keys, confirmation MAC keys or endpoint scalars. The app runs no guess, checker, impersonation or exploit.

## Message and local-state boundaries

### SPAKE2

1. Independently expose each endpoint's legitimate setup record, persistent before the invocation.
2. A creates its local `x` and public `pA=w*M+x*P`.
3. Send `pA`; receipt does not perform B's group check.
4. B validates `pA`; only then create B's local `y` and public `pB=w*N+y*P`.
5. Send `pB`; receipt does not perform A's group check.
6. A validates `pB`. A and B separately compute `K`, secret `TT`, `Ke`, `Ka`, `KcA`, `KcB`. `K` is not the exported key. `Ke||Ka=SHA256(TT)`; `Ke` is 16 bytes. HKDF with nil salt and info `ConfirmationKeys` plus empty AAD yields 32 bytes split into 16-byte confirmation keys. Confirmation keys are not exported.
7. A sends public `cA=HMAC(KcA,TT)`. B is unconfirmed at receipt. B separately verifies it.
8. B hands public `cB=HMAC(KcB,TT)` to the transport only after verifying `cA`. Local `handoff-confirm-b` makes B usable while cB is still in flight. Subsequent `send-confirm-b` is atomic remote receipt and changes only A's received-confirmation state; A remains unconfirmed.
9. A separately verifies `cB`. Endpoint flags distinguish `candidate`, `peerConfirmed` and `usable`. This bounded teaching profile permits an endpoint to use `Ke` only after verifying the peer and handing its own required confirmation to transport, not after proving remote delivery.
10. Each endpoint disposes its own temporary scalar, group secret, secret transcript and confirmation material. Its setup record and confirmed output `Ke` remain.

`TT` is `len(A)||A||len(B)||B||len(pA)||pA||len(pB)||pB||len(K)||K||len(w)||w`, with uint64 little-endian lengths and fixed-width 32-byte big-endian `w`. Secret TT is never sent as a packet.

### SPAKE2+

1. Prover computes registration working `w0,w1,L`. Teaching-only confidential setup delivers only `(w0,L)` to the verifier, which persists that record. Registration working values are then disposed at the prover.
2. Prover creates fresh invocation `w0,w1`, local `x` and public `shareP`.
3. Send `shareP`; verifier separately validates it before generating its own local `y` and public `shareV`.
4. Send `shareV`; prover separately validates it. Both endpoints independently derive `Z,V`, secret `TT`, `K_main`, `K_confirmP`, `K_confirmV` and candidate `K_shared`.
5. Verifier sends `confirmV=HMAC(K_confirmV,shareP)` first. Prover separately verifies it before it may generate `confirmP`.
6. Prover creates `confirmP=HMAC(K_confirmP,shareV)` and hands it to transport at `handoff-confirm-a`. Prover is peer-confirmed after step 5 but this profile withholds application usability until this local handoff. It becomes usable while confirmP is in flight. `send-confirm-a` then changes only verifier receipt state; verifier remains unconfirmed until separate local verification.
7. Verifier verifies `confirmP`; only then is its `K_shared` application-usable. No application packet is included in these lessons.
8. Each endpoint discards `K_main`, confirmation keys and ephemeral computation state after its own completion. Stored verifier `(w0,L)` and prover input remain legitimate setup. Retain only the confirmed output key for this bounded lesson.

`TT` uses length-prefixed Context, idProver, idVerifier, M, N, shareP, shareV, Z, V and w0. HKDF from `K_main=SHA256(TT)` uses nil salt and distinct info `ConfirmationKeys` and `SharedKey`; confirmation output is 64 bytes split into 32-byte keys, shared output is 32 bytes. The full secret transcript is endpoint-local.

## Exact objects, readers and lifetimes

Every artifact ID is scenario-scoped and generation 1; endpoint-local copies of shared secret material are separately identified. The public exchange and public tags have public wire representations, while local inputs, scalars, secret transcripts and key schedules have endpoint-only readers. A public confirmation tag never makes its MAC key readable. The other peer never acquires a private scalar. Enrollment has an opaque wire envelope, a prover-local creation representation and verifier-local decoded/stored record. The disclosure representation grants the observer only the disclosed record fields at the named event, not access to the verifier's other representations.

Acquisitions, releases, source IDs, field paths and immutable values are explicit authoring data. Held inventory is not inferred from the attribute ledger. Whole-message receipt occurs only at event completion; local checks are separate events. Exact receipt occurrences remain inspectable historically after request copies are released. Rewind reconstructs the same canonical prefix and inventory; it does not reverse arbitrary UI state or merge endpoint knowledge.

Enrollment-copy disposal is owner-local: `registration-dispose` releases both prover-local plaintext and prover opaque-wire scratch; `dispose-b` releases the verifier's transient wire/decoded receipts but keeps `(w0,L)`. The record-boundary observer retains its independently recorded opaque envelope, public PAKE shares/tags and, only after the explicit disclosure, a separate readable record copy. Endpoint cleanup cannot erase that evidence. Retained ciphertext does not grant decoded enrollment access, password knowledge or session-key knowledge.

## Controlled negative branches

- `lab-pake-spake2-password-mismatch`: legitimate setup records persist; A's invocation uses `(w+1) mod order`. Public group checks succeed, candidates differ, B rejects A's confirmation. No cB is sent. B cleans locally; A later times out under a declared teaching wait policy and cleans its own state.
- `lab-pake-spake2-transcript-reject`: A's local B identity is `client-altered`; B retains `client`. Public points and K agree, but TT and candidates differ. B rejects cA. The mismatch cause is known by the author, not magically by the rejecting peer.
- `lab-pake-spake2plus-password-mismatch`: legitimate record is enrolled first and never overwritten; online prover uses `(w0+1,w1+1) mod order`. Prover rejects confirmV; it never creates or sends confirmP. Verifier later times out. Both remove their own temporary state.
- `lab-pake-spake2plus-transcript-reject`: prover appends ` altered` to Context; verifier keeps official Context. Z,V agree but TT differs. Prover rejects confirmV, no confirmP follows, and local cleanup preserves legitimate records.
- Invalid-point tests are additional validation cases, not catalog presets. Off-curve SEC1 `04` plus 64 zero octets and identity encoding `00` must fail the receiving endpoint's group checks before derivation or confirmation. Both protocol directions are covered by the independent worksheet. No cryptographic runtime API is introduced merely to host invalid-point tests.

No failure branch creates an application-usable key. A local abort does not delete the other endpoint's state: the peer's later timeout is a separate authored local event. No RFC-defined error packet is invented. Legitimate setup remains intact; historical public copies do not imply current secret possession.

## Acceptance and limitations

Family-specific source tests assert all seven independent worksheets, canonical before/after boundaries, exact reader/representation sets, candidate versus confirmed/usable state, no peer scalar or MAC-key leakage, failure cleanup and persistent-record preservation. Parent owns actual UI gate, exact-object replay, all three source/standalone loading modes, build and regression execution. No live interoperability, accessibility speech/comprehension, or cryptographic validation pass is inferred from source authoring. Manual G01 remains open by user choice. No push, upload or deployment before successful Astra review.

The final family exports all seven worksheet IDs, with no additional catalog presets for invalid points. Its public interfaces remain `PAKELAB_ATTRIBUTES`, the array `PAKELAB_SOURCES`, `PAKELAB_SCENARIOS`, and `buildPakeHeldObjects(args)`. The builder consumes the explicit model-owned inventory ledger rather than inferring holdings from attributes.

Parent verification commands for this family are `bun test tests/pake-lab.test.mjs tests/held-object-pake.test.mjs` and the separately installed/pinned `bun tools/verification/expansion-crypto/check-vectors.mjs`, followed by the integrated build and actual UI/native gates. The crypto runner has exact `rfc9382-B-1-p256-sha256-invalid-point` and `rfc9383-C-1-p256-sha256-invalid-point` cases plus controlled password/transcript and SPAKE2+ confirmation-direction checks. This document records those case identities, not an execution result. Synthetic control checkpoints live in `tools/verification/expansion-crypto/fixtures/synthetic.json`; runtime symbols for controlled computations are explicitly distinguished from official positive-vector references.

## Role-specific oracle correction

The two transcript controls now derive one exchange with asymmetric local bindings, not two endpoints that both changed their binding. In `synthetic.json#/rfc9382/transcriptMismatch`, A binds B=`client-altered` while B retains the official `client`. In `#/rfc9383/transcriptMismatch`, P appends ` altered` to Context while V retains the exact official Context. A/B and P/V checkpoints include secret TT, complete confirmation schedule and candidate output in addition to tags and group results. B and V checkpoints must equal the corresponding published official outputs. A's cA is the actual first sent SPAKE2 confirmation and is compared to B's cA expectation. V's unchanged confirmV is the actual first sent SPAKE2+ confirmation and is compared to P's changed-context confirmV expectation. No reciprocal tag or usable key follows rejection.

The Python oracle was regenerated locally with `python3 tools/verification/expansion-crypto/derive-synthetic.py` using cryptography 46.0.5. Its emitted JSON deliberately replaced only the synthetic fixture file, never official expected bytes. Input SHA-256 identities and the exact endpoint binding map are recorded under `derivation.inputSha256` and `derivation.transcriptBindings`. Runtime controlledRefs now identify exact family/control/role JSON pointers; no arithmetic or cryptography was added to the application. Generator and validator remain independent implementations.

PAKE attribute cleanup uses the registered `evict` operation label, while canonical held-object effects stay `op:release`. Disposal remains endpoint-local on success, receiver rejection and sender timeout. The mounted `tests/review-pake.test.mjs` exercises real scalar and public-share selection, meaningful eviction titles, role-specific model inputs and fixture pointers, and absence of usable-key effects in both transcript rejection lessons.

Parent acceptance: `bun test --isolate tests/pake-lab.test.mjs tests/held-object-pake.test.mjs tests/review-pake.test.mjs`, then `bun tools/verification/expansion-crypto/check-vectors.mjs`. No tests or validator were run by this correction worker.
