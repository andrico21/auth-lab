# New scenario inventory

Generated from the version 1.1.3 registry on 9 October 2026. These are 87 fixed synthetic/reference presets. Counts are full source-event counts, before selected-field playback splits local/transfer moments. A preset status is evidence metadata, not proof of observed vendor interoperability. Each scenario includes primary-source links and its stated prerequisites in the app.

## AD baseline and Keycloak bridge (27)

| ID | Scenario | Source events | Evidence status |
| --- | --- | ---: | --- |
| `lab-ad-first-sign-in` | AD-01 · First domain sign-in → file access | 25 | RFC / Microsoft-specified reference |
| `lab-ad-cache-none` | AD-02 · No usable credentials → acquire them | 25 | RFC / Microsoft-specified reference |
| `lab-ad-cache-tgt` | AD-02 · Cached TGT → first service access | 13 | RFC / Microsoft-specified reference |
| `lab-ad-cache-service` | AD-02 · Cached service ticket → fresh proof | 8 | RFC / Microsoft-specified reference |
| `lab-ad-unknown-spn` | AD-05 · Unknown SPN → KDC acquisition failure | 5 | RFC / Microsoft-specified reference |
| `lab-ad-stale-service-key` | AD-05 · Stale service key → acceptor failure | 10 | RFC / Microsoft-specified reference |
| `lab-ad-clock-skew` | AD-05 · Authenticator clock skew | 5 | RFC / Microsoft-specified reference |
| `lab-ad-expired-ticket` | AD-05 · Service-ticket expiry | 7 | RFC / Microsoft-specified reference |
| `lab-ad-authenticator-replay` | AD-05 · Replayed authenticator | 5 | RFC / Microsoft-specified reference |
| `lab-ad-access-denied` | AD-05 · Authenticated identity, denied resource | 7 | RFC / Microsoft-specified reference |
| `lab-kc-kerberos-sso` | KC-01 · Desktop Kerberos SSO → Keycloak → OIDC | 32 | RFC / Keycloak configured reference |
| `lab-kc-spnego-missing-acceptor-mic` | KC-01 · SPNEGO reference: missing required acceptor MIC | 23 | RFC / Keycloak configured reference |
| `lab-kc-spnego-invalid-acceptor-mic` | KC-01 · SPNEGO reference: invalid acceptor MIC | 23 | RFC / Keycloak configured reference |
| `lab-kc-kerberos-alternative-otp-skip` | KC-02 · Why Alternative Kerberos can skip Forms OTP | 33 | RFC / Keycloak configured reference |
| `lab-kc-kerberos-fresh-totp` | KC-02 · Kerberos + a fresh required TOTP | 38 | RFC / Keycloak configured reference |
| `lab-kc-password-fresh-totp` | KC-02 · Password fallback + a fresh required TOTP | 21 | RFC / Keycloak configured reference |
| `lab-kc-low-assurance-cookie` | KC-02 · Low-assurance cookie → required factor | 19 | RFC / Keycloak configured reference |
| `lab-kc-cookie-fresh-factor` | KC-02 · Sufficient cookie still needs a fresh factor | 19 | RFC / Keycloak configured reference |
| `lab-kc-cookie-age-reuse` | KC-02 · Age-bounded factor reuse → success | 14 | RFC / Keycloak configured reference |
| `lab-kc-cookie-age-expired` | KC-02 · Existing factor too old → fresh factor | 19 | RFC / Keycloak configured reference |
| `lab-kc-factor-unenrolled` | KC-02 · Required factor not enrolled → reject | 26 | RFC / Keycloak configured reference |
| `lab-kc-factor-failed` | KC-02 · Incorrect TOTP → no successful result | 32 | RFC / Keycloak configured reference |
| `lab-kc-factor-cancelled` | KC-02 · Cancelled WebAuthn factor → reject | 28 | RFC / Keycloak configured reference |
| `lab-kc-unsupported-assurance` | KC-02 · Unsupported required assurance → reject | 6 | RFC / Keycloak configured reference |
| `lab-kc-prompt-none-factor-required` | KC-02 · prompt=none with required interaction | 6 | RFC / Keycloak configured reference |
| `lab-kc-kerberos-fresh-webauthn` | KC-02 · Kerberos + required-UV WebAuthn factor | 39 | RFC / Keycloak configured reference |
| `lab-kc-webauthn-uv-policy-fail` | KC-02 · Valid signature, missing required UV | 33 | RFC / Keycloak configured reference |

## PKINIT and FAST (17)

| ID | Scenario | Source events | Evidence status |
| --- | --- | ---: | --- |
| `lab-ad-pkinit-success` | AD-03 · Smart-card PKINIT · fresh DH | 21 | reference |
| `lab-ad-pkinit-binding` | AD-03 · PKINIT · strong account binding denied | 9 | reference |
| `lab-ad-pkinit-trust` | AD-03 · PKINIT · user certificate trust denied | 9 | reference |
| `lab-ad-pkinit-kdc-trust` | AD-03 · PKINIT · KDC certificate trust denied | 11 | reference |
| `lab-ad-fast-as-success` | AD-04 · FAST AS · protected user AS | 15 | reference |
| `lab-ad-fast-as-bootstrap` | AD-04 · FAST AS · computer bootstrap exception | 5 | reference |
| `lab-ad-fast-as-required-armor` | AD-04 · FAST AS · required armor absent | 4 | reference |
| `lab-ad-fast-as-unsupported-dc` | AD-04 · FAST AS · required FAST · no suitable DC | 2 | reference |
| `lab-ad-fast-as-optional-fallback` | AD-04 · FAST AS · optional FAST · explicit password fallback | 5 | reference |
| `lab-ad-fast-as-checksum` | AD-04 · FAST AS · request binding checksum rejected | 12 | reference |
| `lab-ad-fast-as-challenge` | AD-04 · FAST AS · user encrypted challenge rejected | 13 | reference |
| `lab-ad-fast-as-missing-response` | AD-04 · FAST AS · required protected reply absent | 13 | reference |
| `lab-ad-fast-as-response-nonce` | AD-04 · FAST AS · protected reply nonce mismatch | 14 | reference |
| `lab-ad-fast-as-ticket-binding` | AD-04 · FAST AS · finished ticket binding mismatch | 14 | reference |
| `lab-ad-fast-tgs-success` | AD-04 · FAST TGS · implicit armor and mandatory strengthening | 9 | reference |
| `lab-ad-fast-tgs-missing-subkey` | AD-04 · FAST TGS · mandatory authenticator subkey absent | 2 | reference |
| `lab-ad-fast-tgs-missing-strengthen` | AD-04 · FAST TGS · mandatory strengthen-key absent | 8 | reference |

## Forest trust and referrals (14)

| ID | Scenario | Source events | Evidence status |
| --- | --- | ---: | --- |
| `lab-ad-forest-one-way` | AD-06A · One-way forest trust · A account → B resource | 19 | RFC / MS-KILE reference |
| `lab-ad-forest-one-way-reverse` | AD-06A · One-way trust · reverse direction denied | 7 | RFC / MS-KILE reference |
| `lab-ad-forest-two-way-a-b` | AD-06B · Two-way forest trust · A → B | 19 | RFC / MS-KILE reference |
| `lab-ad-forest-two-way-b-a` | AD-06B · Two-way forest trust · B → A | 19 | RFC / MS-KILE reference |
| `lab-ad-forest-child-domains` | AD-06C · Child domains across two forests | 31 | RFC / MS-KILE reference |
| `lab-ad-forest-three-denied` | AD-06D · Three forests · A → C is not implied | 7 | RFC / MS-KILE reference |
| `lab-ad-forest-three-direct` | AD-06D · Three forests · explicit C trusts A | 19 | RFC / MS-KILE reference |
| `lab-ad-forest-same-forest` | AD-06E · Same forest · child → root comparison | 19 | RFC / MS-KILE reference |
| `lab-ad-forest-selective-denied` | AD-06F · Selective authentication denied before service ticket | 13 | RFC / MS-KILE reference |
| `lab-ad-forest-sid-filtering` | AD-06F · SID filtering · foreign identity preserved | 20 | RFC / MS-KILE reference |
| `lab-ad-forest-invalid-pac` | AD-06F · Invalid PAC · validation rejection | 13 | RFC / MS-KILE reference |
| `lab-ad-forest-acl-denied` | AD-06F · Authentication succeeds; resource ACL denies | 19 | RFC / MS-KILE reference |
| `lab-ad-forest-cached-referrals` | AD-06F · Cached referral; acquire only the service ticket | 14 | RFC / MS-KILE reference |
| `lab-ad-forest-cached-service` | AD-06F · Cached service ticket; no KDC exchange | 9 | RFC / MS-KILE reference |

## SSH access (29)

| ID | Scenario | Source events | Evidence status |
| --- | --- | ---: | --- |
| `lab-ssh-cert-success` | SSH · Corporate SSO → SSH certificate | 35 | standards-only |
| `lab-ssh-cert-audience` | SSH · Enrollment rejected · wrong ID-token audience | 22 | standards-only |
| `lab-ssh-cert-principal` | SSH · Enrollment rejected · unauthorized root principal | 21 | standards-only |
| `lab-ssh-cert-host` | SSH · SSH stopped · untrusted server host key | 26 | standards-only |
| `lab-ssh-cert-userca` | SSH · SSH rejected · untrusted user CA | 34 | standards-only |
| `lab-ssh-cert-copy` | SSH · SSH rejected · certificate copied without its key | 35 | standards-only |
| `lab-ssh-cert-session` | SSH · SSH rejected · signature from another connection | 34 | standards-only |
| `lab-ssh-cert-account` | SSH · SSH rejected · existing Unix account denied | 34 | standards-only |
| `lab-ssh-cert-root` | SSH · SSH rejected · certificate alice, requested account root | 34 | standards-only |
| `lab-ssh-cert-callback` | SSH · Enrollment stopped · callback state mismatch | 12 | standards-only |
| `lab-ssh-cert-pkce` | SSH · Enrollment stopped · wrong PKCE verifier | 14 | standards-only |
| `lab-ssh-cert-reissue` | SSH · User certificate reissuance · fresh approval, existing key | 55 | standards-only |
| `lab-ssh-cert-lifecycle` | SSH · SSH credential lifecycle · four independent clocks | 48 | standards-only |
| `lab-ssh-device-cadence` | SSH · Headless enrollment · RFC polling, slow_down and backoff | 45 | standards-only |
| `lab-ssh-device-cancel` | SSH · Headless enrollment · cancel and ignore a late result | 13 | standards-only |
| `lab-ssh-device-restart` | SSH · Headless enrollment · cancelled transaction, fresh restart | 40 | standards-only |
| `lab-ssh-device-denied` | SSH · Headless enrollment · approval denied | 14 | standards-only |
| `lab-ssh-device-expired` | SSH · Headless enrollment · device transaction expired | 14 | standards-only |
| `lab-ssh-device-clienterror` | SSH · Headless enrollment · terminal client error | 14 | standards-only |
| `lab-ssh-sssd-success` | SSH · Browser approval during SSH login · remote SSSD client | 38 | reference |
| `lab-ssh-sssd-cached` | SSH · Browser approval · existing NSS identity cache | 33 | reference |
| `lab-ssh-sssd-bob` | SSH · Browser approval rejected · requested Alice, approved Bob | 35 | reference |
| `lab-ssh-sssd-domain` | SSH · Browser approval rejected · same name in another domain | 35 | reference |
| `lab-ssh-sssd-account` | SSH · Browser approval rejected · Unix account policy | 37 | reference |
| `lab-ssh-sssd-lookup` | SSH · Identity lookup unavailable · no Device transaction | 14 | reference |
| `lab-ssh-sssd-permission` | SSH · Identity lookup denied · service API permission | 14 | reference |
| `lab-ssh-sssd-zero` | SSH · Keyboard-interactive · zero-prompt information comparison | 38 | reference |
| `lab-ssh-gss-success` | SSH · Kerberos GSS-API context + session-bound MIC | 17 | standards-only |
| `lab-ssh-gss-account` | SSH · Kerberos GSS-API context accepted, account denied | 16 | standards-only |
