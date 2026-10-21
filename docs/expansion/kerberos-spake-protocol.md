# Kerberos SPAKE protocol worksheet

Independent boundary expectations are recorded per fixed preset in kerberos-spake-scenarios.json before animation authoring.

## Pinned profiles and support

RFC 9588 (August 2024), Proposed Standard, sections 3-8 and 10.4-10.5. MIT Kerberos administration documentation inspected 2026-10-21 explicitly reports release 1.22.2: https://web.mit.edu/kerberos/krb5-latest/doc/admin/spake.html . Support began in 1.17. Client edwards25519 is enabled by default; KDC requires spake_preauth_groups configuration. MIT documents edwards25519, P-256, P-384, P-521 and spake_preauth_kdc_challenge. Client optimistic support is an RFC 9588 standards illustration, not a claim about an MIT client configuration knob.

The matching 1.22.2 krb5.conf reference was checked directly: https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html . spake_preauth_groups accepts edwards25519, P-256, P-384 and P-521. Realm disable_encrypted_timestamp=true is client policy, persists across initial-authentication client referrals, and does not stop the KDC offering timestamp. Both downgrade presets therefore keep the KDC offer intact while changing the client's fallback decision.

Baseline: edwards25519 group 1, SHA-256, aes128-cts-hmac-sha1-96 initial/reply enctype, SF-NONE, no FAST armor, required preauthentication, provisioned principal, configured KDC, known service, no initial user TGT. AES-SHA1 is a Kerberos enctype name, not a claim that raw SHA-1 is a password hash. RFC 9588 Appendix C fixtures are offline QA only; runtime values are symbolic and not official vector bytes.

## Message and trust boundaries

Advertisement is an empty PA-SPAKE inside KRB-ERROR KDC_ERR_PREAUTH_REQUIRED (25), with singular ETYPE-INFO2 and an initial opaque PA-FX-COOKIE. The next same-conversation AS-REQ echoes those exact cookie bytes with support. KDC creates private x and public T locally and replaces the initial handle with a distinct challenge-state cookie; no scalar or transcript is invented inside the initial handle. The ordinary post-support challenge uses KDC_ERR_MORE_PREAUTH_DATA_REQUIRED (91). A supported or unsupported first KDC optimistic challenge instead uses PREAUTH_REQUIRED (25); client-optimistic support still gets MORE_PREAUTH_DATA_REQUIRED (91). The model exports errorEnvelope.messageType/code/name and the Fields KRB-ERROR value, not only a prose title.

Client receives, then separately derives initial key, w, private y, public S, K, transcript and K'[1]/K'[0]. The response carries S and encrypted SF-NONE, never K or y, and echoes the exact replacement cookie. KDC separately computes K and validates the factor. Only then it strengthens the reply key and creates AS-REP. There is no final PA-SPAKE. Client receipt, reply validation and cache acquisition are separate events. RFC 4120 TGS and mutual AP exchange follow success; service-ticket receipt alone is not a session.

The cookie is opaque to its holder. Decoded cookie state and x are KDC-only. TGT ciphertext is readable as envelope bytes by the client, but its body is encrypted under the realm TGT key and readable by TGS, not the client. The AS-REP client material uses the strengthened reply key and conveys the TGT session key separately. Unrelated cached state is never cleared by failure.

## Branch policies and omissions

Wrong password fails factor decryption at KDC, then client receives PREAUTH_FAILED; no AS-REP or TGT. No-common-group fixes rejection policy although RFC 9588 permits another proposed group. Downgrade observer strips advertisement only: allowed policy uses explicitly named encrypted timestamp, losing SPAKE offline-dictionary resistance; blocked policy stops before credential issue. Supported optimistic challenge omits support negotiation. Unsupported optimistic challenge abandons generation 0 and resets transcript to generation 1 support/challenge, using fresh private scalar. Client optimistic support skips initial empty request and requires ETYPE-INFO2 in challenge. SF-NONE has no OTP exchange. FAST, PKINIT and AD DS SPAKE support are not implied.

SPAKE versus timestamp: PAKE protects passive dictionary guessing; timestamp fallback does not. SPAKE versus PKINIT: password-derived trust versus certificate-based initial authentication. SPAKE with FAST: separate armor can enclose SPAKE; this profile has none. Kerberos SPAKE is not interchangeable with standalone balanced SPAKE2 or augmented SPAKE2+ registration records.

## Cryptographic framing and independent negative checks

RFC Editor errata search for RFC 9588 was checked 2026-10-21 and returned no matching errata. The publication status was independently checked on the RFC Editor info page.

The baseline transcript is H(H(zeros || DER support || DER challenge) || S), H=SHA-256. Accepted KDC optimism omits support from the first hash input. Rejected optimism is not included in the replacement transcript. Encrypted factor data is not part of the transcript. The w input uses PRF+(initial reply key, "SPAKEsecret" || group-number-be32), converted with the group registry method. K-prime[n] hashes "SPAKEkey", signed-be32 group, signed-be32 enctype, original PRF+ output, serialized shared K, transcript hash, exact DER KDC-REQ-BODY, unsigned-be32 n and one-byte counter1. Random-to-key gives an intermediate key; KRB-FX-CF2(initial reply key, intermediate key, "SPAKE", "keyderiv") gives K-prime[n]. The shared group element is never directly used as an encryption key.

Validate T and S are group elements before shared-secret computation (section10.1). SF-NONE is type1 with omitted data, not an empty OTP. Independent negative fixture expectations: wrong password causes factor ciphertext integrity failure; changed transcript or request body causes derived-key mismatch; an invalid group point is rejected before deriving an accepted key. None of these controls establishes live MIT interoperability.

Successful histories explicitly retain separate identities for opaque TGT, TGT protected body, AS client material, issued TGT session key, strengthened reply key and realm ticket-encryption key. A decoded representation acquisition occurs at validation, never at merely visual packet arrival.

Coordinated offline negative fixture IDs are rfc9588-C-aes128-edwards25519-password-mismatch (client password "password!" differs from published KDC password/key), rfc9588-C-aes128-edwards25519-transcript-mismatch (client-only final request-body enctype byte changed 0x11 to 0x10; deliberately conflicting body, not a supported profile), and rfc9588-C-aes128-edwards25519-invalid-point (malformed, noncanonical, identity and low-order Edwards encodings). Crypto QA owns actual expected bytes and oracle provenance. The integration owner reports the full official-vector QA passed; this family worker ran no validator, build or tests and claims no live MIT interoperability.

## Authored completion and integration boundary

All eight exact IDs have authored source histories, independent expected histories and prefix/terminal assertions. Only the success representative's native UI and exact replay gate was exercised by the integration owner before authoring the remaining seven. The remaining variants still require parent verification in source HTTP, standalone HTTP and standalone file modes. Manual G01 remains open. No push, deploy or upload is authorized here.

Creator holdings begin at creation, not later use. Opaque wire bytes are readable by actual issuers/carriers; this never grants decoded body access. TGT decoded fields are KDC issuer/TGS-only, service ticket decoded fields are TGS issuer/service-only, and decoded cookies are KDC-only. Local derivation/use/verification and cache acceptance have explicit observation effects in exact histories. KDC, TGS, service, client and downgrade observer dispose only their own transient holdings at endpoint-local events; accepted client caches and service authenticated context keys persist. Unsupported optimistic generation0 holdings end at each endpoint's separate transcript reset, not at a global cleanup percentage.

## Review corrections and focused acceptance

RFC 6113 section 5.2 (https://www.rfc-editor.org/rfc/rfc6113.html#section-5.2) governs continuable-error cookies and exact next-request echo. Initial cookie fields are `kspInitialCookieCookieBytes` and `kspInitialCookieState`; the latter is KDC-only. The KDC discards its initial handle at challenge creation and the client discards its copy only upon challenge receipt. Terminal group rejection cleans these copies at each endpoint's independent cleanup. Downgrade forwarding preserves the opaque bytes and the allowed timestamp request echoes them. Client optimism starts without a previous cookie. Unsupported KDC optimism explicitly abandons its conversation at transcript-reset/kdc-transcript-reset, rather than silently treating its old cookie as a same-conversation echo.

Canonical event IDs and cursor positions are unchanged. Attribute operations now author genuine create/derive/use/decrypt/verify/store/evict moments, not generic inspect. `kspInitialKeyKey`, `kspClientSharedK` and `kspClientReplyKeyKey` derive at client-derive and evict temporary copies at session. The client reply key is used at client-validate. `kspTgtSessionKey` derives at as-create, is acquired/checked at client-validate and stored at cache; endpoint cleanup releases only temporary copies, not accepted cache holdings. Attribute evict is the existing display action; held effects remain release. A context-only policy inspect still has no lifecycle replay. No generic inspect consumer was changed.

Focused parent commands: `bun test --isolate tests/kerberos-spake-lab.test.mjs tests/held-object-spake.test.mjs tests/review-pake.test.mjs`. The new mounted assertions select real fields, retain actor-qualified values and source indices, and compare source effects; held assertions independently check cookie replacement and local lifecycle boundaries. These regressions were authored but not executed by this worker. No new conformance, native rendering or interoperability result is claimed.
