# Optional expansion cryptographic fixture QA

This directory is an isolated development/acceptance tool. Auth Flow Studio remains a non-cryptographic, offline lesson. Nothing here is imported by runtime `src`, concatenated into the standalone application, or installed by the root package. This is not production authentication, a password checker, a TLS endpoint, or live implementation interoperability evidence. The executable accepts no arguments or user-provided credentials. All inputs are fixed, public teaching fixtures.

## Reproducible setup and execution

From the repository root, with Bun 1.4.3 (the authoring setup, pinned in this package):

```sh
bun --cwd tools/verification/expansion-crypto install --frozen-lockfile --ignore-scripts
bun tools/verification/expansion-crypto/check-vectors.mjs
```

Or, from this directory, `bun install --frozen-lockfile --ignore-scripts`, then `bun check-vectors.mjs`. No Node, npm, npx, lifecycle scripts, root dependency changes, or install step in the main application are needed. Dependency acquisition is the only network-dependent setup. The installed dependency directory can subsequently be reused without network access. Do not pass passwords, URLs, input fixtures, or report paths to the checker.

`package.json` pins `@noble/curves` 2.4.0, `@noble/hashes` 2.4.0, `hash-wasm` 4.12.0 and `crypto-js` 4.2.0. `bun.lock` records exact resolution and integrity. Noble supplies P-256/Edwards25519 point/scalar operations, SHA-256/SHA-1/MD5/HMAC/HKDF/PBKDF2; hash-wasm supplies MD4; CryptoJS supplies RC4 for the published NTLM session-key exchange example. Bun's built-in `node:crypto` compatibility API supplies AES, X.509 parsing and constant-time byte equality. The legacy primitives are necessary to reproduce NTLMv2 and the selected AES-SHA1 Kerberos profile; they are not recommendations for new authentication designs. No dependency is used to generate randomness.

The checker prints one JSON report to stdout (bounded to 128 KiB) and exits nonzero on any mismatch, rejected setup, missing package, source-snapshot drift, duplicate case ID or fatal error. It records:

- actual Bun/platform/architecture/OpenSSL identity;
- runner SHA-256, all validator/generator/package/lock/fixture file hashes;
- source URL, section, revision, retrieval date, declared and actual source-snapshot hashes;
- exact installed dependency versions, licenses, file counts and content-tree hashes;
- an independent result for each of the 31 authored cases, including successful byte checkpoints or bounded failure reason;
- the exact regeneration and frozen-setup commands, plus aggregate result.

The report deliberately contains no transcript secrets or raw computed password-derived values. The public fixture files contain the published example values. Validation uses only local files and in-process primitives: no `fetch`, HTTP, DNS, subprocess, remote service, password input or live account is involved. A parent acceptance runner may capture stdout as its evidence artifact. A report is evidence of the exact executed code and fixtures, not a blanket standards-conformance certificate.

Authoring policy: installing pinned packages and deriving fixtures were permitted setup. The finished checker, tests, lint, formatters and builds were intentionally not run by this worker; the integration owner executes them after integration. No passing result is claimed here.

## Exact official-vector selection

Only the complete vectors listed below are claimed. Other Appendix B/C vectors, ciphersuites and implementation profiles are not implied.

| Fixture ID | Exact source and profile | Computations compared with independently published expected bytes |
| --- | --- | --- |
| `rfc9382-B-1-p256-sha256` | RFC 9382 Appendix B **first** vector, `A='server'`, `B='client'`; P256-SHA256-HKDF-HMAC, uncompressed SEC1 | P-256 field/order/a/b/base/cofactor and validated fixed M/N; xP+wM and yP+wN; both independently computed unmasked shared K values; complete 8-byte little-endian length-framed TT including identities and fixed-width big-endian w; Hash(TT), Ke/Ka split, HKDF KcA/KcB, both directional full-transcript HMAC confirmations at both endpoints. |
| `rfc9383-C-1-p256-sha256` | RFC 9383 Appendix C **first** vector, prover `client`, verifier `server`, exact Context `SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors` (56 ASCII bytes, no appended newline) | Full P-256 parameters/masks; registration L=w1P; shareP/shareV; both sides' Z and V, using the provisioned verifier record rather than giving the verifier w1; complete TT including Context/M/N/Z/V/w0; K_main, both full-length confirmation keys, confirmP over shareV, confirmV over shareP, and K_shared at both endpoints. |
| `rfc9588-C-aes128-edwards25519` | RFC 9588 Appendix C **aes128-cts-hmac-sha1-96 edwards25519** vector; group 1, SHA-256, enctype 17, SF-NONE; password `password`, salt `ATHENA.MIT.EDUraeburn`, RFC 3962 default 4096 iterations | Password PBKDF2-HMAC-SHA1 plus AES DK initial reply key, not a preloaded derived-key shortcut; AES PRF+/pepper, full unreduced w and little-endian reduced scalar; field/order/a/d/base/cofactor and M/N subgroup checks; x/y cofactor/range constraints, X/Y/T/S, both sides' K; independently constructed DER support/challenge/request body, both transcript updates, SHA-256 intermediate keys, AES random-to-key identity and KRB-FX-CF2; K'[0], K'[1], K'[2], K'[3] at both endpoints. |
| `ms-nlmp-4.2.4-ntlmv2` | MS-NLMP 37.0 (2026-03-30), sections 4.2.1 and 4.2.4.1-4.2.4.2, published `User` / `Domain` / `Password`, KEY_EXCH example | UTF-16LE password MD4 intermediate (also published in 4.2.2.1.2), NTOWFv2 HMAC with uppercased username but unchanged domain, explicitly assembled timestamp/challenges/AV-pair blob including terminators, NTProofStr, full NTChallengeResponse = proof plus blob, LMv2 response, SessionBaseKey, NTLMv2 KeyExchangeKey, selected ExportedSessionKey, RC4 encrypted session key and receiver recovery. |

The RFC 9382 MHF and RFC 9383 PBKDF choice are **omitted by the official vectors**. Their published w / w0 / w1 scalars are the protocol inputs, not a fabricated password derivation. RFC 9588's password-to-key computation is defined and is actually performed. RFC 9588 explicitly chooses x/y divisible by the cofactor; do not add another cofactor multiplication as if this were the standalone RFC 9382 flow.

`rfc3961-A1-nfold` additionally compares four published n-fold primitive examples, including 64-fold(`012345`), 56-fold(`password`), 168-fold(`password`) and 128-fold(`kerberos`). The AES-SHA1 PRF truncates SHA-1 to a 16-byte AES cipher block. The pinned MIT Kerberos 1.22.2 `krb5int_dk_prf` source makes that interpretation explicit; it is not truncation to the 1-byte plaintext padding unit from the AES profile table.

A synthetic SF-NONE protected-factor case extends, without relabeling, the selected RFC 9588 vector: fixed public confounder `00..0f`, DER `3005a003020101`, usage 65, K'[1], AES-CTS encryption and HMAC-SHA1-96. Expected ciphertext plus tag comes from the separate Python/OpenSSL derivation, not from the Bun implementation. The restricted helper handles exactly this 23-byte fixture and is not an exposed/general Kerberos encryption API. The official RFC 9588 vector publishes K'[0..3], not this additional ciphertext.

## Independent controlled negative cases

The positive published fixtures are immutable. The validator derives negatives separately. `fixtures/synthetic.json` was generated by `derive-synthetic.py`, which does not import any JavaScript validator or Noble code. Its P-256 and Edwards25519 arithmetic is independent Python integer arithmetic, HKDF/HMAC/hashes use Python stdlib, and DER/AES use Python cryptography/OpenSSL. Generation has no sockets, randomness, external credentials or user input. This is an independent expected-output oracle, not a helper called by validation.

| Control | Exact change | Required observation |
| --- | --- | --- |
| RFC 9382 `-password-mismatch` | Only A uses w+1; B retains official w | Each side recomputes its public mask, unmasking, K and confirmations. Independently generated K/cA/cB values match; peer K values differ and both confirmations reject. |
| RFC 9382 `-transcript-mismatch` | Only A binds B=`client-altered`; B retains official B=`client` in the same exchange | K remains unchanged. Independent A/B TT, Ke, Ka, KcA/KcB and cA/cB checkpoints match. All unchanged B outputs equal the official vector; A's actual first sent cA fails B's expected cA. |
| RFC 9383 `-password-mismatch` | Prover uses w0+1 and w1+1; verifier keeps published (w0,L) | Independent Z/V/tags/K_shared values match the oracle; both confirmation checks reject. |
| RFC 9383 `-transcript-mismatch` | Only prover P appends ` altered` to Context; verifier V retains official Context in the same exchange | Group Z/V remain unchanged. Independent P/V TT, K_main, K_confirmP/K_confirmV, tags and K_shared checkpoints match. Unchanged V outputs equal the official vector; V's actual first sent confirmV fails P's changed-context expectation. |
| RFC 9383 `-confirmation-direction` | Reflect verifier/prover proof or MAC the wrong share | Direction-specific keys and opposite-share MAC inputs reject reflection. |
| RFC 9588 `-password-mismatch` | Client password is `password!`; KDC retains published password/key | Independent recomputation of full client key/PRF+/mask/S/K/K'[0..3] and factor ciphertext matches oracle material. KDC rejects factor integrity, not just a compared label. |
| RFC 9588 `-transcript-mismatch` | Only client's request-body final enctype byte is XOR 1, 0x11 to 0x10 | Group K remains equal. Independently derived request-bound K'[0..3] and factor bytes differ and the KDC factor unwrap rejects. This is a conflicting-body negative, not a second supported enctype profile. |
| RFC 9588 `-transcript-reset` | Reuse a prior final transcript as the seed for a new exchange | Wrong seed changes transcript and strengthened reply key. |
| RFC 9588 `-directional-key-use` | Unwrap K'[1]-protected factor with K'[2] | Integrity rejects opposite-direction reflection. |
| Each PAKE `-invalid-point` | P-256 malformed/off-curve/infinity/noncanonical-field encodings; Edwards short/noncanonical/identity/low-order encodings | Actual strict point decoding/subgroup/identity validation rejects, with no keys produced from these values. |
| NTLMv2 negative controls | Wrong password, changed server challenge, incorrect domain normalization/authority context, changed client-challenge blob byte | The account validator cannot reproduce the received proof/session key. Username-only uppercasing and complete blob authentication remain observable. |

## CredSSP v6 directional binding fixtures

`ms-cssp-v6-directional-synthetic` is a **synthetic hash-binding fixture**, not a captured CredSSP handshake. MS-CSSP 21.0 (2024-04-23), section 3.1.5 version 6 processing rules define the algorithms:

```text
SHA256(ASCII("CredSSP Client-To-Server Binding Hash") || 00 || nonce32 || SubjectPublicKey)
SHA256(ASCII("CredSSP Server-To-Client Binding Hash") || 00 || nonce32 || SubjectPublicKey)
```

Nonce: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`.

The public RSA certificate is the fixed RFC 7517 Appendix B example. The independent oracle parses it and serializes its **270-byte DER RSAPublicKey**. This is the value inside the SubjectPublicKeyInfo BIT STRING, excluding the BIT STRING tag/length/unused-bit octet. It is not the **294-byte SPKI**, certificate DER, a certificate thumbprint, or a display string. The Bun case independently parses the certificate, extracts that BIT STRING value and checks both the Python-expected bytes and native PKCS1 public-key serialization before computing either digest. This fixture does not validate the example certificate's identity, validity period, chain, signature strength or suitability for a modern TLS deployment.

Independent expected digests cover the correct directions and the plausible bugs: omitted terminating NUL, one changed nonce byte, SPKI substitution, whole-certificate substitution, and SHA-256 certificate-thumbprint substitution. Additional cases reject reflected direction, changed key bytes and nonce lengths 0/31/33. No v2-v4 incremented-public-key binding is accepted as v6. The QA tool checks the binding-hash algorithm only; actual authentication-package sealing, TLS, SPNEGO, TSRequest combined-message sequencing, credential delivery/policy and Windows interoperability belong to their separate model/native acceptance checks and are not claimed here.

## Optional independent fixture regeneration

Normal validation requires **Bun only** and the committed files. Regeneration is an optional source-development task using Python 3 and `cryptography==46.0.5` (the version recorded in the generated fixture):

```sh
python3 tools/verification/expansion-crypto/derive-synthetic.py
```

The command prints the deterministic JSON; it does not overwrite files or invoke the Bun checker. Review and deliberately replace `fixtures/synthetic.json` with that output only when changing the documented controls. The generator version/source is hashed in reports. Retain independently sourced published expected bytes and their provenance; never regenerate positive expected bytes by calling the implementation under test.

The corrected transcript controls were generated with the command above and Python cryptography 46.0.5. `derivation.inputSha256` records all four fixed input-file identities; `derivation.transcriptBindings` records the role-specific deltas and sent-tag/receiver-expectation pairing. In particular `rfc9382.json` SHA-256 is `96d4d09308ee0d15e0b1992cf697c8193df2ba79046712bb67b433408f3fdbd2` and `rfc9383.json` is `43132db8b3185f0d02e5c0b0f8c051518e894cee897c808f17aaa670be1fd177`. Official-vector checks are unchanged. The JS validator independently reconstructs the same asymmetric exchange and compares unchanged-role results to published bytes, not merely to a separate altered run. Runtime controlledRef pointers use these actual A/B/P/V fixture roles. Generator execution alone is not a validator pass.

## Source and licensing policy

`sources.json` maps exact source sections/revisions and hashes the committed excerpts/snapshots. RFC 9382/9383/9588 errata lookups on 2026-10-21 returned no matching errata. The held-for-document-update RFC 3961 DES seed-length erratum does not affect this AES fixture. No correction has been silently applied to any published vector. Microsoft numeric example pages include source revision links; the encrypted-session-key example is unchanged since its 2024-04-23 page revision within the current MS-NLMP publication.

Official vector bytes remain attributed to their primary publishers, not relicensed as original project data. RFC text excerpts and supporting RFC snapshots retain IETF Trust/Internet Society notices and the applicable BCP 78/Trust Legal Provisions. Microsoft source snapshots retain their page/source metadata and Microsoft attribution. The MIT PRF reference snapshot retains its complete original notice/license. See `LICENSES.txt`. Generated synthetic values and authored verification code fall under the repository license, without modifying those third-party terms.
