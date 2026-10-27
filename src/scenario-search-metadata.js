// SEARCH01: title clauses name taught concepts; operator aliases are curated from
// worker-plan section 8.1 and the frozen WP0 catalog. No evaluator imports.
export const SCENARIO_SEARCH_REGISTRY = Object.freeze({
  "lab-spa-api": {
    "searchTags": [
      "SPA",
      "API",
      "public Code + PKCE",
      "Browser app calling an API"
    ]
  },
  "lab-bff-api": {
    "searchTags": [
      "SPA + BFF",
      "API",
      "cookie / token boundary",
      "Web frontend with a secure backend"
    ]
  },
  "lab-api-introspection": {
    "searchTags": [
      "API introspection",
      "lightweight / opaque-token pattern"
    ]
  },
  "lab-api-errors": {
    "searchTags": [
      "API outcomes",
      "401 vs 403 vs 200"
    ]
  },
  "lab-jwks-rotation": {
    "searchTags": [
      "API signing-key rotation",
      "unknown kid"
    ]
  },
  "lab-refresh-rotation": {
    "searchTags": [
      "Refresh token",
      "rotation and reuse failure"
    ]
  },
  "lab-offline-access": {
    "searchTags": [
      "Offline access",
      "consent, issuance and later refresh"
    ]
  },
  "lab-token-revocation": {
    "searchTags": [
      "Token revocation",
      "valid and unknown-token responses"
    ]
  },
  "lab-rp-initiated-logout": {
    "searchTags": [
      "RP-initiated logout",
      "hint, redirect and state"
    ]
  },
  "lab-backchannel-logout": {
    "searchTags": [
      "Backchannel logout",
      "signed event and replay handling"
    ]
  },
  "lab-frontchannel-logout": {
    "searchTags": [
      "Frontchannel logout",
      "iframe delivery and browser limits"
    ]
  },
  "lab-sso-existing-session": {
    "searchTags": [
      "Existing SSO",
      "prompt=none succeeds"
    ]
  },
  "lab-sso-login-required": {
    "searchTags": [
      "Silent SSO",
      "login_required error branch"
    ]
  },
  "lab-session-expiry": {
    "searchTags": [
      "Session expiry",
      "ordinary refresh is rejected"
    ]
  },
  "lab-client-jwt": {
    "searchTags": [
      "private_key_jwt",
      "signed client authentication"
    ]
  },
  "lab-mtls": {
    "searchTags": [
      "mTLS",
      "client authentication and certificate-bound API token"
    ]
  },
  "lab-par": {
    "searchTags": [
      "PAR",
      "push authorization before opening the browser"
    ]
  },
  "lab-jar": {
    "searchTags": [
      "JAR",
      "signed authorization Request Object"
    ]
  },
  "lab-jarm": {
    "searchTags": [
      "JARM",
      "signed JWT authorization response"
    ]
  },
  "lab-dpop": {
    "searchTags": [
      "DPoP",
      "key-bound token, fresh API proof and nonce retry"
    ]
  },
  "lab-jwt-grant": {
    "searchTags": [
      "JWT authorization grant",
      "subject assertion versus client assertion"
    ]
  },
  "lab-ciba-ping": {
    "searchTags": [
      "CIBA",
      "Ping then token fetch"
    ]
  },
  "lab-ciba-push": {
    "searchTags": [
      "CIBA",
      "Push token delivery"
    ]
  },
  "lab-ciba-hint-token": {
    "searchTags": [
      "CIBA",
      "signed login_hint_token"
    ]
  },
  "lab-exchange-id-token": {
    "searchTags": [
      "Token exchange",
      "ID-token result"
    ]
  },
  "lab-exchange-refresh-token": {
    "searchTags": [
      "Token exchange",
      "policy-enabled refresh result"
    ]
  },
  "lab-exchange-delegation": {
    "searchTags": [
      "Preview",
      "consented client delegation"
    ]
  },
  "lab-exchange-external-in": {
    "searchTags": [
      "External identity",
      "Keycloak",
      "JWT grant then V2"
    ]
  },
  "lab-exchange-external-out": {
    "searchTags": [
      "Legacy",
      "Keycloak",
      "linked external token"
    ]
  },
  "lab-saml-artifact": {
    "searchTags": [
      "SAML",
      "HTTP-Artifact + SOAP resolution"
    ]
  },
  "lab-saml-sp-slo": {
    "searchTags": [
      "SAML",
      "SP-initiated browser Single Logout"
    ]
  },
  "lab-saml-idp-slo": {
    "searchTags": [
      "SAML",
      "IdP-initiated browser Single Logout"
    ]
  },
  "lab-saml-soap-slo": {
    "searchTags": [
      "SAML",
      "SOAP backchannel Single Logout"
    ]
  },
  "lab-saml-metadata": {
    "searchTags": [
      "SAML",
      "metadata registration and signing-key rollover"
    ]
  },
  "lab-saml-validation-failures": {
    "searchTags": [
      "SAML",
      "expired, replayed and denied attempts"
    ]
  },
  "lab-direct-grant": {
    "searchTags": [
      "Direct Access Grant",
      "legacy password grant"
    ]
  },
  "lab-implicit": {
    "searchTags": [
      "Implicit",
      "front-channel tokens"
    ]
  },
  "lab-hybrid": {
    "searchTags": [
      "Hybrid",
      "code and front-channel tokens"
    ]
  },
  "lab-consent-denial": {
    "searchTags": [
      "Consent",
      "approval and refusal"
    ]
  },
  "lab-broker-account-link": {
    "searchTags": [
      "First broker login",
      "verify before linking"
    ]
  },
  "lab-passkey-cancel": {
    "searchTags": [
      "Passkey cancellation",
      "configured fallback"
    ]
  },
  "lab-account-recovery": {
    "searchTags": [
      "Account recovery",
      "one-use action credential"
    ]
  },
  "lab-concurrent-sessions": {
    "searchTags": [
      "Concurrent sessions",
      "server state and JWT lifetime"
    ]
  },
  "lab-ad-first-sign-in": {
    "searchTags": [
      "AD-01",
      "First domain sign-in",
      "file access"
    ]
  },
  "lab-ad-cache-none": {
    "searchTags": [
      "AD-02",
      "No usable credentials",
      "acquire them"
    ]
  },
  "lab-ad-cache-tgt": {
    "searchTags": [
      "AD-02",
      "Cached TGT",
      "first service access"
    ]
  },
  "lab-ad-cache-service": {
    "searchTags": [
      "AD-02",
      "Cached service ticket",
      "fresh proof"
    ]
  },
  "lab-ad-unknown-spn": {
    "searchTags": [
      "AD-05",
      "Unknown SPN",
      "KDC acquisition failure"
    ]
  },
  "lab-ad-stale-service-key": {
    "searchTags": [
      "AD-05",
      "Stale service key",
      "acceptor failure"
    ]
  },
  "lab-ad-clock-skew": {
    "searchTags": [
      "AD-05",
      "Authenticator clock skew"
    ]
  },
  "lab-ad-expired-ticket": {
    "searchTags": [
      "AD-05",
      "Service-ticket expiry"
    ]
  },
  "lab-ad-authenticator-replay": {
    "searchTags": [
      "AD-05",
      "Replayed authenticator"
    ]
  },
  "lab-ad-access-denied": {
    "searchTags": [
      "AD-05",
      "Authenticated identity, denied resource"
    ]
  },
  "lab-kc-kerberos-sso": {
    "searchTags": [
      "KC-01",
      "Desktop Kerberos SSO",
      "Keycloak",
      "OIDC"
    ]
  },
  "lab-kc-spnego-missing-acceptor-mic": {
    "searchTags": [
      "KC-01",
      "SPNEGO reference: missing required acceptor MIC"
    ]
  },
  "lab-kc-spnego-invalid-acceptor-mic": {
    "searchTags": [
      "KC-01",
      "SPNEGO reference: invalid acceptor MIC"
    ]
  },
  "lab-kc-kerberos-alternative-otp-skip": {
    "searchTags": [
      "KC-02",
      "Why Alternative Kerberos can skip Forms OTP"
    ]
  },
  "lab-kc-kerberos-fresh-totp": {
    "searchTags": [
      "KC-02",
      "Kerberos + a fresh required TOTP"
    ]
  },
  "lab-kc-password-fresh-totp": {
    "searchTags": [
      "KC-02",
      "Password fallback + a fresh required TOTP"
    ]
  },
  "lab-kc-low-assurance-cookie": {
    "searchTags": [
      "KC-02",
      "Low-assurance cookie",
      "required factor"
    ]
  },
  "lab-kc-cookie-fresh-factor": {
    "searchTags": [
      "KC-02",
      "Sufficient cookie still needs a fresh factor"
    ]
  },
  "lab-kc-cookie-age-reuse": {
    "searchTags": [
      "KC-02",
      "Age-bounded factor reuse",
      "success"
    ]
  },
  "lab-kc-cookie-age-expired": {
    "searchTags": [
      "KC-02",
      "Existing factor too old",
      "fresh factor"
    ]
  },
  "lab-kc-factor-unenrolled": {
    "searchTags": [
      "KC-02",
      "Required factor not enrolled",
      "reject"
    ]
  },
  "lab-kc-factor-failed": {
    "searchTags": [
      "KC-02",
      "Incorrect TOTP",
      "no successful result"
    ]
  },
  "lab-kc-factor-cancelled": {
    "searchTags": [
      "KC-02",
      "Cancelled WebAuthn factor",
      "reject"
    ]
  },
  "lab-kc-unsupported-assurance": {
    "searchTags": [
      "KC-02",
      "Unsupported required assurance",
      "reject"
    ]
  },
  "lab-kc-prompt-none-factor-required": {
    "searchTags": [
      "KC-02",
      "prompt=none with required interaction"
    ]
  },
  "lab-kc-kerberos-fresh-webauthn": {
    "searchTags": [
      "KC-02",
      "Kerberos + required-UV WebAuthn factor"
    ]
  },
  "lab-kc-webauthn-uv-policy-fail": {
    "searchTags": [
      "KC-02",
      "Valid signature, missing required UV"
    ]
  },
  "lab-ad-pkinit-success": {
    "searchTags": [
      "AD-03",
      "Smart-card PKINIT",
      "fresh DH"
    ]
  },
  "lab-ad-pkinit-binding": {
    "searchTags": [
      "AD-03",
      "PKINIT",
      "strong account binding denied"
    ]
  },
  "lab-ad-pkinit-trust": {
    "searchTags": [
      "AD-03",
      "PKINIT",
      "user certificate trust denied"
    ]
  },
  "lab-ad-pkinit-kdc-trust": {
    "searchTags": [
      "AD-03",
      "PKINIT",
      "KDC certificate trust denied"
    ]
  },
  "lab-ad-fast-as-success": {
    "searchTags": [
      "AD-04",
      "FAST AS",
      "protected user AS"
    ]
  },
  "lab-ad-fast-as-bootstrap": {
    "searchTags": [
      "AD-04",
      "FAST AS",
      "computer bootstrap exception"
    ]
  },
  "lab-ad-fast-as-required-armor": {
    "searchTags": [
      "AD-04",
      "FAST AS",
      "required armor absent"
    ]
  },
  "lab-ad-fast-as-unsupported-dc": {
    "searchTags": [
      "AD-04",
      "FAST AS",
      "required FAST",
      "no suitable DC"
    ]
  },
  "lab-ad-fast-as-optional-fallback": {
    "searchTags": [
      "AD-04",
      "FAST AS",
      "optional FAST",
      "explicit password fallback"
    ]
  },
  "lab-ad-fast-as-checksum": {
    "searchTags": [
      "AD-04",
      "FAST AS",
      "request binding checksum rejected"
    ]
  },
  "lab-ad-fast-as-challenge": {
    "searchTags": [
      "AD-04",
      "FAST AS",
      "user encrypted challenge rejected"
    ]
  },
  "lab-ad-fast-as-missing-response": {
    "searchTags": [
      "AD-04",
      "FAST AS",
      "required protected reply absent"
    ]
  },
  "lab-ad-fast-as-response-nonce": {
    "searchTags": [
      "AD-04",
      "FAST AS",
      "protected reply nonce mismatch"
    ]
  },
  "lab-ad-fast-as-ticket-binding": {
    "searchTags": [
      "AD-04",
      "FAST AS",
      "finished ticket binding mismatch"
    ]
  },
  "lab-ad-fast-tgs-success": {
    "searchTags": [
      "AD-04",
      "FAST TGS",
      "implicit armor and mandatory strengthening"
    ]
  },
  "lab-ad-fast-tgs-missing-subkey": {
    "searchTags": [
      "AD-04",
      "FAST TGS",
      "mandatory authenticator subkey absent"
    ]
  },
  "lab-ad-fast-tgs-missing-strengthen": {
    "searchTags": [
      "AD-04",
      "FAST TGS",
      "mandatory strengthen-key absent"
    ]
  },
  "lab-ad-forest-one-way": {
    "searchTags": [
      "AD-06A",
      "One-way forest trust",
      "A account",
      "B resource"
    ]
  },
  "lab-ad-forest-one-way-reverse": {
    "searchTags": [
      "AD-06A",
      "One-way trust",
      "reverse direction denied"
    ]
  },
  "lab-ad-forest-two-way-a-b": {
    "searchTags": [
      "AD-06B",
      "Two-way forest trust"
    ]
  },
  "lab-ad-forest-two-way-b-a": {
    "searchTags": [
      "AD-06B",
      "Two-way forest trust"
    ]
  },
  "lab-ad-forest-child-domains": {
    "searchTags": [
      "AD-06C",
      "Child domains across two forests"
    ]
  },
  "lab-ad-forest-three-denied": {
    "searchTags": [
      "AD-06D",
      "Three forests",
      "C is not implied"
    ]
  },
  "lab-ad-forest-three-direct": {
    "searchTags": [
      "AD-06D",
      "Three forests",
      "explicit C trusts A"
    ]
  },
  "lab-ad-forest-same-forest": {
    "searchTags": [
      "AD-06E",
      "Same forest",
      "child",
      "root comparison"
    ]
  },
  "lab-ad-forest-selective-denied": {
    "searchTags": [
      "AD-06F",
      "Selective authentication denied before service ticket"
    ]
  },
  "lab-ad-forest-sid-filtering": {
    "searchTags": [
      "filtering",
      "SID filtering",
      "cross-forest trust",
      "AD-06F",
      "foreign identity preserved"
    ]
  },
  "lab-ad-forest-invalid-pac": {
    "searchTags": [
      "AD-06F",
      "Invalid PAC",
      "validation rejection"
    ]
  },
  "lab-ad-forest-acl-denied": {
    "searchTags": [
      "AD-06F",
      "Authentication succeeds; resource ACL denies"
    ]
  },
  "lab-ad-forest-cached-referrals": {
    "searchTags": [
      "AD-06F",
      "Cached referral; acquire only the service ticket"
    ]
  },
  "lab-ad-forest-cached-service": {
    "searchTags": [
      "AD-06F",
      "Cached service ticket; no KDC exchange"
    ]
  },
  "lab-ssh-cert-success": {
    "searchTags": [
      "SSH",
      "Corporate SSO",
      "SSH certificate"
    ]
  },
  "lab-ssh-cert-audience": {
    "searchTags": [
      "SSH",
      "Enrollment rejected",
      "wrong ID-token audience"
    ]
  },
  "lab-ssh-cert-principal": {
    "searchTags": [
      "SSH",
      "Enrollment rejected",
      "unauthorized root principal"
    ]
  },
  "lab-ssh-cert-host": {
    "searchTags": [
      "SSH",
      "SSH stopped",
      "untrusted server host key"
    ]
  },
  "lab-ssh-cert-userca": {
    "searchTags": [
      "SSH",
      "SSH rejected",
      "untrusted user CA"
    ]
  },
  "lab-ssh-cert-copy": {
    "searchTags": [
      "SSH",
      "SSH rejected",
      "certificate copied without its key"
    ]
  },
  "lab-ssh-cert-session": {
    "searchTags": [
      "SSH",
      "SSH rejected",
      "signature from another connection"
    ]
  },
  "lab-ssh-cert-account": {
    "searchTags": [
      "SSH",
      "SSH rejected",
      "existing Unix account denied"
    ]
  },
  "lab-ssh-cert-root": {
    "searchTags": [
      "SSH",
      "SSH rejected",
      "certificate alice, requested account root"
    ]
  },
  "lab-ssh-cert-callback": {
    "searchTags": [
      "SSH",
      "Enrollment stopped",
      "callback state mismatch"
    ]
  },
  "lab-ssh-cert-pkce": {
    "searchTags": [
      "SSH",
      "Enrollment stopped",
      "wrong PKCE verifier"
    ]
  },
  "lab-ssh-cert-reissue": {
    "searchTags": [
      "SSH",
      "User certificate reissuance",
      "fresh approval, existing key"
    ]
  },
  "lab-ssh-cert-lifecycle": {
    "searchTags": [
      "SSH",
      "SSH credential lifecycle",
      "four independent clocks"
    ]
  },
  "lab-ssh-device-cadence": {
    "searchTags": [
      "SSH",
      "Headless enrollment",
      "RFC polling, slow_down and backoff"
    ]
  },
  "lab-ssh-device-cancel": {
    "searchTags": [
      "SSH",
      "Headless enrollment",
      "cancel and ignore a late result"
    ]
  },
  "lab-ssh-device-restart": {
    "searchTags": [
      "SSH",
      "Headless enrollment",
      "cancelled transaction, fresh restart"
    ]
  },
  "lab-ssh-device-denied": {
    "searchTags": [
      "SSH",
      "Headless enrollment",
      "approval denied"
    ]
  },
  "lab-ssh-device-expired": {
    "searchTags": [
      "SSH",
      "Headless enrollment",
      "device transaction expired"
    ]
  },
  "lab-ssh-device-clienterror": {
    "searchTags": [
      "SSH",
      "Headless enrollment",
      "terminal client error"
    ]
  },
  "lab-ssh-sssd-success": {
    "searchTags": [
      "PAM sshd service",
      "SSH",
      "Browser approval during SSH login",
      "remote SSSD client"
    ]
  },
  "lab-ssh-sssd-cached": {
    "searchTags": [
      "SSH",
      "Browser approval",
      "existing NSS identity cache"
    ]
  },
  "lab-ssh-sssd-bob": {
    "searchTags": [
      "SSH",
      "Browser approval rejected",
      "requested Alice, approved Bob"
    ]
  },
  "lab-ssh-sssd-domain": {
    "searchTags": [
      "SSH",
      "Browser approval rejected",
      "same name in another domain"
    ]
  },
  "lab-ssh-sssd-account": {
    "searchTags": [
      "PAM account admission",
      "SSH",
      "Browser approval rejected",
      "Unix account policy"
    ]
  },
  "lab-ssh-sssd-lookup": {
    "searchTags": [
      "SSH",
      "Identity lookup unavailable",
      "no Device transaction"
    ]
  },
  "lab-ssh-sssd-permission": {
    "searchTags": [
      "SSH",
      "Identity lookup denied",
      "service API permission"
    ]
  },
  "lab-ssh-sssd-zero": {
    "searchTags": [
      "SSH",
      "Keyboard-interactive",
      "zero-prompt information comparison"
    ]
  },
  "lab-ssh-gss-success": {
    "searchTags": [
      "SSH",
      "Kerberos GSS-API context + session-bound MIC"
    ]
  },
  "lab-ssh-gss-account": {
    "searchTags": [
      "SSH",
      "Kerberos GSS-API context accepted, account denied"
    ]
  },
  "lab-win-ntlmv2-domain": {
    "searchTags": [
      "Domain NTLMv2: response, DC validation and application access"
    ]
  },
  "lab-win-ntlmv2-local": {
    "searchTags": [
      "SERVER-local NTLMv2: accepting application and local SAM authority"
    ]
  },
  "lab-win-ntlmv2-trust": {
    "searchTags": [
      "NTLMv2 across a direct RESOURCE-trusts-CORP relationship"
    ]
  },
  "lab-win-ntlmv2-trust-denied": {
    "searchTags": [
      "NTLMv2 direct trust route denied at resource DC"
    ]
  },
  "lab-win-ntlmv2-response-rejected": {
    "searchTags": [
      "NTLMv2 response rejected: DC, service and client learn at different moments"
    ]
  },
  "lab-win-negotiate-kerberos": {
    "searchTags": [
      "HTTP Negotiate selects Kerberos, then the application authorizes"
    ]
  },
  "lab-win-negotiate-ntlm-allowed": {
    "searchTags": [
      "HTTP Negotiate uses an explicitly configured NTLM-only profile"
    ]
  },
  "lab-win-negotiate-ntlm-blocked": {
    "searchTags": [
      "Incoming NTLM blocked by accepting-service policy"
    ]
  },
  "lab-win-credssp-v6-kerberos": {
    "searchTags": [
      "CredSSP v6 with Kerberos: binding before password delegation"
    ]
  },
  "lab-win-credssp-v6-ntlm": {
    "searchTags": [
      "CredSSP v6 with NTLMv2: validation, binding and delegated credentials"
    ]
  },
  "lab-win-credssp-binding-rejected": {
    "searchTags": [
      "CredSSP reverse binding rejected before authInfo export"
    ]
  },
  "lab-win-credssp-delegation-denied": {
    "searchTags": [
      "CredSSP target delegation denied before networking"
    ]
  },
  "lab-win-credssp-logon-denied": {
    "searchTags": [
      "CredSSP credentials disclosed, separate remote logon denied"
    ]
  },
  "lab-win-rdp-normal": {
    "searchTags": [
      "Ordinary RDP NLA: delegated user credentials and downstream user access"
    ]
  },
  "lab-win-rdp-restricted-admin": {
    "searchTags": [
      "RDP Restricted Admin: empty user credentials, downstream host identity"
    ]
  },
  "lab-win-rdp-remote-credential-guard": {
    "searchTags": [
      "remote credential guard",
      "remote credguard",
      "rcg",
      "rdp",
      "redirected authentication",
      "second hop",
      "Remote Credential Guard: Kerberos-only redirected operations and user SSO"
    ]
  },
  "lab-win-rdp-rcg-kerberos-unavailable": {
    "searchTags": [
      "Required Remote Credential Guard: Kerberos prerequisite unavailable"
    ]
  },
  "lab-win-rdp-required-mode-unsupported": {
    "searchTags": [
      "Required RDP credential mode unsupported: no silent downgrade"
    ]
  },
  "lab-win-winrm-second-hop-denied": {
    "searchTags": [
      "WinRM nondelegating first hop survives user second-hop denial"
    ]
  },
  "lab-win-winrm-credssp-second-hop": {
    "searchTags": [
      "WinRM HTTPS CredSSP: independent TLS layers and delegated-user second hop"
    ]
  },
  "lab-win-winrm-delegation-denied": {
    "searchTags": [
      "WinRM target export policy denied, not a password error"
    ]
  },
  "lab-win-winrm-credssp-http": {
    "searchTags": [
      "WinRM HTTP CredSSP: no outer HTTPS, inner TLS and Kerberos remain"
    ]
  },
  "lab-win-winrm-resource-denied": {
    "searchTags": [
      "WinRM user second-hop authenticated, resource ACL denied"
    ]
  },
  "lab-smb-nonjoined-ntlm": {
    "searchTags": [
      "workgroup share",
      "nonjoined SMB",
      "NTLMv2",
      "Workgroup PC",
      "domain SMB share: explicit credentials and NTLMv2"
    ]
  },
  "lab-smb-nonjoined-kerberos": {
    "searchTags": [
      "workgroup share",
      "nonjoined SMB",
      "explicit Kerberos",
      "Workgroup PC",
      "domain SMB share: configured Kerberos"
    ]
  },
  "lab-smb-nonjoined-ntlm-blocked": {
    "searchTags": [
      "SMB NTLM blocked: no authenticated session"
    ]
  },
  "lab-smb-nonjoined-bad-credential": {
    "searchTags": [
      "SMB wrong domain credential: DC rejects the response"
    ]
  },
  "lab-smb-nonjoined-dc-unavailable": {
    "searchTags": [
      "SMB domain validation unavailable"
    ]
  },
  "lab-smb-nonjoined-share-denied": {
    "searchTags": [
      "SMB authenticated user denied at the share"
    ]
  },
  "lab-smb-nonjoined-file-denied": {
    "searchTags": [
      "SMB share connected, file ACL denies read access"
    ]
  },
  "lab-smb-nonjoined-signature-rejected": {
    "searchTags": [
      "SMB3.1.1 final signature rejected"
    ]
  },
  "lab-smb-nonjoined-encryption-rejected": {
    "searchTags": [
      "SMB3.1.1 encrypted file data rejected"
    ]
  },
  "lab-smb-nonjoined-encryption-unavailable": {
    "searchTags": [
      "SMB3.1.1 required encryption unavailable"
    ]
  },
  "lab-smb-multichannel-binding-success": {
    "searchTags": [
      "SMB3.1.1 multichannel: bind and use a second connection"
    ]
  },
  "lab-smb-multichannel-binding-rejected": {
    "searchTags": [
      "SMB3.1.1 multichannel: reject a bad binding proof"
    ]
  },
  "lab-net-radius-password-accept": {
    "searchTags": [
      "RADIUS password accept"
    ]
  },
  "lab-net-radius-password-reject": {
    "searchTags": [
      "RADIUS password reject"
    ]
  },
  "lab-net-radius-password-totp": {
    "searchTags": [
      "Password plus TOTP challenge"
    ]
  },
  "lab-net-radius-challenge-rejected": {
    "searchTags": [
      "TOTP challenge rejected"
    ]
  },
  "lab-net-eap-tls13-wired": {
    "searchTags": [
      "Wired 802.1X EAP-TLS 1.3"
    ]
  },
  "lab-net-eap-server-cert-rejected": {
    "searchTags": [
      "EAP server certificate rejected"
    ]
  },
  "lab-net-eap-client-cert-rejected": {
    "searchTags": [
      "EAP client certificate rejected"
    ]
  },
  "lab-net-eap-policy-denied": {
    "searchTags": [
      "Valid certificate identity, access policy denied"
    ]
  },
  "lab-net-nps-ad-tls12": {
    "searchTags": [
      "NPS AD DS full EAP-TLS 1.2"
    ]
  },
  "lab-net-nps-mapping-rejected": {
    "searchTags": [
      "NPS strong certificate mapping rejected"
    ]
  },
  "lab-net-radius-accounting-lifecycle": {
    "searchTags": [
      "Accounting Start, Interim-Update and Stop"
    ]
  },
  "lab-net-radius-udp-radsec": {
    "searchTags": [
      "Classic UDP and RadSec - two visible EAP-TLS transactions"
    ]
  },
  "lab-net-radsec-peer-rejected": {
    "searchTags": [
      "RadSec transport peer identity rejected"
    ]
  },
  "lab-net-radius-proxy-realm": {
    "searchTags": [
      "Realm-routed EAP-TLS proxy"
    ]
  },
  "lab-net-radius-proxy-unknown-realm": {
    "searchTags": [
      "Unknown realm - configured proxy reject"
    ]
  },
  "lab-net-radius-coa-ack": {
    "searchTags": [
      "CoA changes an existing session filter"
    ]
  },
  "lab-net-radius-coa-nak": {
    "searchTags": [
      "CoA request rejected without policy change"
    ]
  },
  "lab-net-radius-disconnect-ack": {
    "searchTags": [
      "Disconnect target session then acknowledge"
    ]
  },
  "lab-net-radius-disconnect-nak": {
    "searchTags": [
      "Disconnect absent session NAK"
    ]
  },
  "lab-net-radius-udp-retransmission": {
    "searchTags": [
      "Lost UDP reply and duplicate-safe retry"
    ]
  },
  "lab-net-enterprise-wifi-eap": {
    "searchTags": [
      "Enterprise Wi-Fi - bounded EAP decision"
    ]
  },
  "lab-net-radius11": {
    "searchTags": [
      "Experimental negotiated RADIUS/1.1"
    ]
  },
  "lab-net-radius11-required-unavailable": {
    "searchTags": [
      "Required RADIUS/1.1 unavailable"
    ]
  },
  "lab-krb-spake-success": {
    "searchTags": [
      "Kerberos SPAKE: ordinary success"
    ]
  },
  "lab-krb-spake-wrong-password": {
    "searchTags": [
      "Kerberos SPAKE: wrong password rejected"
    ]
  },
  "lab-krb-spake-no-common-group": {
    "searchTags": [
      "Kerberos SPAKE: no common configured group"
    ]
  },
  "lab-krb-spake-downgrade-allowed": {
    "searchTags": [
      "Kerberos SPAKE: downgrade allowed: encrypted timestamp"
    ]
  },
  "lab-krb-spake-downgrade-blocked": {
    "searchTags": [
      "Kerberos SPAKE: downgrade blocked by client policy"
    ]
  },
  "lab-krb-spake-optimistic-accepted": {
    "searchTags": [
      "Kerberos SPAKE: KDC optimistic challenge accepted"
    ]
  },
  "lab-krb-spake-optimistic-renegotiate": {
    "searchTags": [
      "Kerberos SPAKE: optimistic group renegotiation"
    ]
  },
  "lab-krb-spake-client-optimistic": {
    "searchTags": [
      "Kerberos SPAKE: client optimistic support"
    ]
  },
  "lab-pake-spake2-success": {
    "searchTags": [
      "SPAKE2 - two independent confirmations"
    ]
  },
  "lab-pake-spake2-password-mismatch": {
    "searchTags": [
      "SPAKE2 - wrong input, failed confirmation"
    ]
  },
  "lab-pake-spake2-transcript-reject": {
    "searchTags": [
      "SPAKE2 - B identity mismatch rejected by B"
    ]
  },
  "lab-pake-spake2plus-success": {
    "searchTags": [
      "SPAKE2+ - registration and confirmed shared key"
    ]
  },
  "lab-pake-spake2plus-password-mismatch": {
    "searchTags": [
      "SPAKE2+ - wrong input, failed confirmation"
    ]
  },
  "lab-pake-spake2plus-transcript-reject": {
    "searchTags": [
      "SPAKE2+ - Context mismatch rejected by prover"
    ]
  },
  "lab-pake-spake2plus-record-boundary": {
    "searchTags": [
      "SPAKE2+ - ordinary recording versus disclosed verifier record"
    ]
  },
  "lab-nfs-v42-kerberos-read": {
    "searchTags": [
      "Modern default: authenticated private NFSv4.2 read"
    ]
  },
  "lab-nfs-gss-protection": {
    "searchTags": [
      "Compare krb5, krb5i and krb5p"
    ]
  },
  "lab-nfs-v3-auth-sys": {
    "searchTags": [
      "NFSv3: client-asserted identity and root squashing"
    ]
  },
  "lab-nfs-v3-kerberos": {
    "searchTags": [
      "NFSv3 can use Kerberos"
    ]
  },
  "lab-nfs-v40-namespace": {
    "searchTags": [
      "NFSv4.0: integrated namespace and state"
    ]
  },
  "lab-nfs-v41-machine-user": {
    "searchTags": [
      "NFSv4.1: machine state and user access"
    ]
  },
  "lab-nfs-security-discovery": {
    "searchTags": [
      "Recover from a security-policy boundary"
    ]
  },
  "lab-nfs-identity-permission": {
    "searchTags": [
      "From principal to UID/GID to access decision"
    ]
  },
  "lab-nfs-nonjoined-client": {
    "searchTags": [
      "A non-domain-joined Linux workstation uses Kerberos"
    ]
  },
  "lab-nfs-session-binding": {
    "searchTags": [
      "Add a connection without inventing a new user login"
    ]
  },
  "lab-nfs-tls-auth-sys": {
    "searchTags": [
      "RPC-with-TLS protects a transport, not a user claim"
    ]
  },
  "lab-nfs-required-tls-failure": {
    "searchTags": [
      "Required transport protection fails closed"
    ]
  },
  "lab-nfs-windows-server-v41": {
    "searchTags": [
      "Linux client to Windows Server for NFS"
    ]
  },
  "lab-wlog01": {
    "searchTags": [
      "Workgroup workstation: local password logon"
    ]
  },
  "lab-wlog02": {
    "searchTags": [
      "credential guard",
      "lsa",
      "lsass",
      "protected TGT",
      "online domain sign-in",
      "Online AD DS password sign-in to local desktop"
    ]
  },
  "lab-wlog03": {
    "searchTags": [
      "Explicit local account on a domain member: same name, different SID"
    ]
  },
  "lab-wlog04": {
    "searchTags": [
      "offline logon",
      "cached logon",
      "cached credentials",
      "Offline cached domain validation: local desktop, no fresh KDC grant"
    ],
    "variants": {
      "protected-user": [
        "protected users offline",
        "protected users",
        "offline logon",
        "cached logon denial"
      ]
    }
  },
  "lab-wlog05": {
    "searchTags": [
      "Smart-card sign-in: local PIN, PKINIT and local desktop"
    ]
  },
  "lab-wlog06": {
    "searchTags": [
      "Required FAST: computer armor, user proof and local desktop"
    ]
  },
  "lab-wlog07": {
    "searchTags": [
      "Unlock the existing local or domain Windows session"
    ]
  },
  "lab-wlog08": {
    "searchTags": [
      "workgroup share",
      "explicit domain credentials",
      "nonjoined PC",
      "Nonjoined PC: local desktop and explicit domain network identity"
    ]
  },
  "lab-welev01": {
    "searchTags": [
      "filtering",
      "token filtering",
      "deny-only",
      "administrator membership",
      "process token",
      "Administrator membership versus the process token actually used"
    ]
  },
  "lab-welev02": {
    "searchTags": [
      "run as admin",
      "run as administrator",
      "UAC consent",
      "Run as administrator: same-administrator consent"
    ]
  },
  "lab-welev03": {
    "searchTags": [
      "run as admin",
      "alternate administrator",
      "credential elevation",
      "Standard-user elevation: authenticate a separate administrator"
    ]
  },
  "lab-welev04": {
    "searchTags": [
      "runas /user: secondary logon, not guaranteed elevation"
    ]
  },
  "lab-welev05": {
    "searchTags": [
      "runas /netonly: local identity stays, outbound validation is deferred"
    ]
  },
  "lab-welev06": {
    "searchTags": [
      "Administrator protection: isolated elevation identity and profile"
    ]
  },
  "lab-llog01": {
    "searchTags": [
      "PAM login service",
      "Linux local login through configured PAM"
    ]
  },
  "lab-llog02": {
    "searchTags": [
      "PAM directory account admission",
      "Linux AD identity, Kerberos proof and host admission"
    ]
  },
  "lab-llog03": {
    "searchTags": [
      "PAM offline cache",
      "Linux offline cached directory login without a fresh TGT"
    ]
  },
  "lab-llog04": {
    "searchTags": [
      "PAM password change",
      "Linux expired authentication token and explicit password authority"
    ]
  },
  "lab-llog05": {
    "searchTags": [
      "Nonjoined Linux local desktop then explicit Kerberos"
    ]
  },
  "lab-lelev01": {
    "searchTags": [
      "PAM sudo service",
      "sudo",
      "sudoers",
      "runas policy",
      "timestamp cache",
      "sudo policy, authentication identity and target credentials"
    ]
  },
  "lab-lelev02": {
    "searchTags": [
      "PAM su service",
      "su target authentication and real-root bypass"
    ]
  },
  "lab-lelev03": {
    "searchTags": [
      "polkit authorizes one mechanism operation, not a root client"
    ]
  },
  "lab-lelev04": {
    "searchTags": [
      "Linux Security Modules can deny an already elevated process"
    ]
  },
  "lab-mlog01": {
    "searchTags": [
      "Mac local login, unlock and keychain boundaries"
    ]
  },
  "lab-mlog02": {
    "searchTags": [
      "FileVault disk unlock, secure token and ownership are different gates"
    ]
  },
  "lab-mlog03": {
    "searchTags": [
      "Mac AD online versus previously cached mobile login"
    ]
  },
  "lab-mlog04": {
    "searchTags": [
      "Local Mac account then managed Kerberos resource SSO"
    ]
  },
  "lab-mlog05": {
    "searchTags": [
      "Platform SSO registration, method-specific login policy and IdP identity"
    ]
  },
  "lab-melev01": {
    "searchTags": [
      "Scoped Mac GUI administrator authorization without a root desktop"
    ]
  },
  "lab-melev02": {
    "searchTags": [
      "Mac sudo password or explicitly configured Touch ID stack"
    ]
  },
  "lab-melev03": {
    "searchTags": [
      "Network-only Platform SSO administrator authorization with strict exclusions"
    ]
  },
  "lab-jwt01": {
    "searchTags": [
      "JWT, JWS, JWE and opaque tokens"
    ]
  },
  "lab-jwt02": {
    "searchTags": [
      "Signed JWT verification and tampering"
    ]
  },
  "lab-jwt03": {
    "searchTags": [
      "Encrypted and nested JWT acceptance"
    ]
  },
  "lab-jwt04": {
    "searchTags": [
      "Algorithm and key-type confusion rejected"
    ]
  },
  "lab-jwt05": {
    "searchTags": [
      "Issuer trust, discovery, kid and JWKS"
    ]
  },
  "lab-jwt06": {
    "searchTags": [
      "JWKS rotation and bounded refresh"
    ]
  },
  "lab-jwt07": {
    "searchTags": [
      "Issuer, audience, time and claim types"
    ]
  },
  "lab-jwt08": {
    "searchTags": [
      "ID tokens, access tokens and cross-JWT substitution"
    ]
  },
  "lab-jwt09": {
    "searchTags": [
      "Bearer possession, replay and validation lifetime"
    ]
  },
  "lab-k8s01": {
    "searchTags": [
      "Human OIDC login to kubectl API read"
    ]
  },
  "lab-k8s02": {
    "searchTags": [
      "JWT claims to Kubernetes userInfo"
    ]
  },
  "lab-k8s03": {
    "searchTags": [
      "Kubernetes JWT rejection and key rotation"
    ]
  },
  "lab-k8s09": {
    "searchTags": [
      "Projected ServiceAccount token issuance and rotation"
    ]
  },
  "lab-k8s10": {
    "searchTags": [
      "ServiceAccount identities and RBAC subjects"
    ]
  },
  "lab-k8s11": {
    "searchTags": [
      "TokenReview versus offline service-account JWT validation"
    ]
  },
  "lab-k8s12": {
    "searchTags": [
      "Audience-isolated ServiceAccount TokenRequest"
    ]
  },
  "lab-k8s13": {
    "searchTags": [
      "Missing credentials, anonymous identity and 401/403"
    ]
  },
  "lab-k8s04": {
    "searchTags": [
      "role binding",
      "RoleBinding",
      "RBAC",
      "Kubernetes authorization",
      "RoleBinding explains Alice allowed and Bob forbidden"
    ]
  },
  "lab-k8s05": {
    "searchTags": [
      "role binding scope",
      "ClusterRoleBinding",
      "namespaced RBAC",
      "Role and ClusterRole binding scope"
    ]
  },
  "lab-k8s06": {
    "searchTags": [
      "Request attributes, subresources and can-i"
    ]
  },
  "lab-k8s07": {
    "searchTags": [
      "Additive RBAC and group binding union"
    ]
  },
  "lab-k8s08": {
    "searchTags": [
      "Authorized writes, admission and persistence"
    ]
  },
  "lab-k8s14": {
    "searchTags": [
      "Impersonation permission and constrained variant"
    ]
  },
  "lab-k8s15": {
    "searchTags": [
      "Role creation, bind and escalate safeguards"
    ]
  },
  "lab-mcp01": {
    "searchTags": [
      "Remote MCP: discovery to authorized tool result"
    ]
  },
  "lab-mcp02": {
    "searchTags": [
      "Discover the correct resource and authorization server"
    ]
  },
  "lab-mcp03": {
    "searchTags": [
      "Registration choices: CIMD and existing client registration"
    ]
  },
  "lab-mcp04": {
    "searchTags": [
      "Reject a substituted authorization response"
    ]
  },
  "lab-mcp05": {
    "searchTags": [
      "A received token is not yet an accepted request"
    ]
  },
  "lab-mcp06": {
    "searchTags": [
      "Insufficient scope and bounded incremental consent"
    ]
  },
  "lab-mcp07": {
    "searchTags": [
      "Expiry, refresh rotation and reauthorization"
    ]
  },
  "lab-mcp08": {
    "searchTags": [
      "OAuth permission, tool approval and resource policy"
    ]
  },
  "lab-mcp09": {
    "searchTags": [
      "MCP proxy: a separate OAuth grant for the upstream API"
    ]
  },
  "lab-mcp10": {
    "searchTags": [
      "Proxy consent cannot be inherited by a different MCP client"
    ]
  },
  "lab-mcp11": {
    "searchTags": [
      "Reject token passthrough across the proxy boundary"
    ]
  },
  "lab-mcp12": {
    "searchTags": [
      "Untrusted discovery URLs and metadata do not trigger unsafe fetches"
    ]
  },
  "lab-mcp13": {
    "searchTags": [
      "Local stdio: process credentials and OS authority"
    ]
  },
  "lab-dnssec01": {
    "searchTags": [
      "Follow a signed lookup"
    ]
  },
  "lab-dnssec02": {
    "searchTags": [
      "From zone data to signatures"
    ]
  },
  "lab-dnssec03": {
    "searchTags": [
      "Cross a delegation boundary"
    ]
  },
  "lab-dnssec04": {
    "searchTags": [
      "Explain a validation decision"
    ]
  },
  "lab-dnssec05": {
    "searchTags": [
      "Stub validation and the AD flag"
    ]
  },
  "lab-dnssec06": {
    "searchTags": [
      "dnssec forwarder",
      "DNS forwarding",
      "DNSSEC validation",
      "forwarding resolver",
      "Who validates when DNS is forwarded?"
    ]
  },
  "lab-dnssec07": {
    "searchTags": [
      "Prove that a name or type does not exist with NSEC"
    ]
  },
  "lab-dnssec08": {
    "searchTags": [
      "NSEC3 and Opt-Out"
    ]
  },
  "lab-dnssec09": {
    "searchTags": [
      "Wildcards and aliases across zones"
    ]
  },
  "lab-dnssec10": {
    "searchTags": [
      "Reuse validated cache data"
    ]
  },
  "lab-dnssec11": {
    "searchTags": [
      "Large answers, EDNS and encrypted transport"
    ]
  },
  "lab-dnssec12": {
    "searchTags": [
      "Refresh signatures and roll a ZSK"
    ]
  },
  "lab-dnssec13": {
    "searchTags": [
      "Roll a KSK or combined signing key"
    ]
  },
  "lab-dnssec14": {
    "searchTags": [
      "Change algorithms and digest policy"
    ]
  },
  "lab-dnssec15": {
    "searchTags": [
      "Install and maintain a trust anchor"
    ]
  },
  "lab-dnssec16": {
    "searchTags": [
      "Maintain parent DS with CDS/CDNSKEY"
    ]
  },
  "lab-dnssec17": {
    "searchTags": [
      "Bootstrap DS and operate automation safely"
    ]
  },
  "lab-dnssec18": {
    "searchTags": [
      "Operate multiple signers/providers"
    ]
  },
  "lab-dnssec19": {
    "searchTags": [
      "Publish and replicate a signed zone"
    ]
  },
  "lab-dnssec20": {
    "searchTags": [
      "Diagnose failure and recovery"
    ]
  },
  "lab-dnssec21": {
    "searchTags": [
      "Compact denial of existence"
    ]
  },
  "lab-dnssec22": {
    "searchTags": [
      "private DNS",
      "conditional forwarding",
      "local trust anchor",
      "Private DNS, local anchors and conditional forwarding"
    ]
  },
  "basic-keycloak": {
    "searchTags": [
      "Basic Keycloak sign-in"
    ]
  },
  "web-mfa": {
    "searchTags": [
      "Web sign-in with MFA"
    ]
  },
  "web-passkey": {
    "searchTags": [
      "Passwordless web sign-in"
    ]
  },
  "basic-saml": {
    "searchTags": [
      "Basic SAML sign-in"
    ]
  },
  "corporate-external": {
    "searchTags": [
      "Corporate sign-in through an external IdP"
    ]
  },
  "two-realms": {
    "searchTags": [
      "Sign-in across two Keycloak realms"
    ]
  },
  "desktop-sign-in": {
    "searchTags": [
      "Desktop app sign-in"
    ]
  },
  "service-to-service": {
    "searchTags": [
      "Service-to-service access"
    ]
  },
  "device-sign-in": {
    "searchTags": [
      "Sign-in from a CLI or limited-input device"
    ]
  },
  "backend-token-exchange": {
    "searchTags": [
      "Backend access to another API"
    ]
  },
  "core": {
    "searchTags": [
      "configurable core lab",
      "authorization code",
      "PKCE",
      "SAML",
      "FIDO2",
      "MFA"
    ]
  },
  "lab-wra01": {
    "searchTags": [
      "filtering",
      "token filtering",
      "remote uac",
      "local administrator",
      "LocalAccountTokenFilterPolicy",
      "deny-only",
      "local SAM"
    ]
  },
  "lab-wra02": {
    "searchTags": [
      "filtering",
      "token filtering",
      "remote uac",
      "local administrator",
      "LocalAccountTokenFilterPolicy",
      "RID500",
      "FilterAdministratorToken"
    ]
  },
  "lab-wra03": {
    "searchTags": [
      "workgroup share",
      "domain account",
      "nonjoined PC",
      "account authority"
    ]
  },
  "lab-wra04": {
    "searchTags": [
      "logon admission",
      "share ACL",
      "file ACL",
      "management endpoint",
      "deny-only SID"
    ]
  },
  "lab-wra05": {
    "searchTags": [
      "Administrator Protection",
      "remote domain elevation",
      "remote elevation policy"
    ]
  },
  "lab-wprot01": {
    "searchTags": [
      "credential guard",
      "credguard",
      "lsa",
      "lsass",
      "lsaiso",
      "isolated lsa",
      "vbs",
      "credential isolation",
      "LsaCfgFlags"
    ]
  },
  "lab-wprot02": {
    "searchTags": [
      "lsa",
      "lsass",
      "local security authority",
      "lsa protection",
      "protected process",
      "ppl",
      "RunAsPPL",
      "run as ppl"
    ]
  },
  "lab-wprot03": {
    "searchTags": [
      "protected users",
      "Kerberos restrictions",
      "delegation restrictions"
    ],
    "variants": {
      "offline-unavailable": [
        "protected users offline",
        "offline logon",
        "cached logon denial"
      ]
    }
  },
  "lab-wprot04": {
    "searchTags": [
      "authentication policy",
      "allowed device",
      "AS issuance",
      "FAST armor"
    ]
  },
  "lab-wprot05": {
    "searchTags": [
      "authentication silos",
      "effective policy",
      "service ticket admission",
      "TGS policy"
    ]
  },
  "lab-pam01": {
    "searchTags": [
      "pam",
      "pam.d",
      "Linux-PAM",
      "soft checks",
      "hard checks",
      "configuration control flow"
    ],
    "variants": {
      "required-deferred-failure": [
        "required",
        "deferred failure"
      ],
      "requisite-immediate-failure": [
        "requisite",
        "immediate failure"
      ],
      "sufficient-early-success": [
        "sufficient",
        "early success"
      ],
      "sufficient-after-failure": [
        "sufficient",
        "remembered failure"
      ],
      "sufficient-failure-fallback": [
        "sufficient",
        "fallback"
      ],
      "optional-nondecisive": [
        "optional",
        "nondecisive"
      ],
      "optional-only-success": [
        "optional",
        "optional-only success"
      ],
      "optional-only-failure": [
        "optional",
        "optional-only failure"
      ],
      "include-termination": [
        "include",
        "include termination"
      ],
      "substack-termination": [
        "substack",
        "substack termination"
      ],
      "substack-failure": [
        "substack",
        "substack failure"
      ],
      "substack-jump-boundary": [
        "substack",
        "substack jump boundary"
      ],
      "soft-hard-limits": [
        "pam limits",
        "pam_limits",
        "limits.conf",
        "soft limit",
        "hard limit",
        "nofile"
      ]
    }
  }
});

const scenarioMetadataKey = value => String(value).normalize('NFKD').replace(/\p{M}/gu,'').toLowerCase().trim().replace(/\s+/g,' ');
const scenarioMetadataStrings = values => [...new Map(values.filter(value=>typeof value==='string'&&value.trim()).map(value=>[scenarioMetadataKey(value),value.trim()])).values()];
const scenarioMetadataProfileText = value => {
  if(typeof value==='string'||typeof value==='number'||typeof value==='boolean')return [String(value)];
  if(Array.isArray(value))return value.flatMap(scenarioMetadataProfileText);
  if(value&&typeof value==='object')return Object.entries(value).flatMap(([key,item])=>[key,...scenarioMetadataProfileText(item)]);
  return [];
};
// The only compatibility adapter for legacy keywords. Consumers index searchTags,
// not keywords in a second flattened taxonomy.
export function adaptScenarioSearchTags(searchTags=[],keywords=[]) {
  return scenarioMetadataStrings([...searchTags,...(Array.isArray(keywords)?keywords:typeof keywords==='string'?[keywords]:[])]);
}

export function createScenarioSearchMetadata(modelOrPreset,attributes={}) {
  const model=modelOrPreset, entry=SCENARIO_SEARCH_REGISTRY[model.id];
  if(!entry)throw new Error('Missing scenario search metadata: '+model.id);
  const choices=model.variantChoices||[];
  const choiceIds=new Set(choices.map(choice=>choice.id));
  if(choiceIds.size!==choices.length)throw new Error('Duplicate search variant: '+model.id);
  for(const id of Object.keys(entry.variants||{})){
    if(!choiceIds.has(id))throw new Error('Unknown search variant: '+model.id+'/'+id);
  }
  const attributeIds=model.catalogAttributeIds||model.ids||[];
  const fieldRows=Array.isArray(model.attributeNames)?model.attributeNames:attributeIds.map(id=>({id,...attributes[id]}));
  const profile=model.profile||{};
  const profileText=scenarioMetadataProfileText(profile);
  const searchIdentifiers=scenarioMetadataStrings([model.id,...fieldRows.flatMap(field=>[field.id,field.name]),...(model.searchIdentifiers||[])]);
  const searchContext=scenarioMetadataStrings([model.summary,model.category,model.status,model.protocol,model.workspace,model.family,model.lesson,model.evidenceLabel,model.learningObjective,...(model.prerequisites||[]),...profileText,...fieldRows.flatMap(field=>[field.name,field.standard]),model.config?.applicationProtocol,model.config?.oidcFlow]);
  return {
    searchTags:adaptScenarioSearchTags([...entry.searchTags,...(model.searchTags||[])],model.keywords),
    searchIdentifiers,
    searchContext,
    searchVariants:choices.map(choice=>({
      id:choice.id,
      label:choice.label||choice.id,
      searchTags:adaptScenarioSearchTags([...(entry.variants?.[choice.id]||[]),...(choice.searchTags||[])]),
      searchIdentifiers:scenarioMetadataStrings([choice.id,choice.caseId,choice.canonicalCaseId]),
      searchContext:scenarioMetadataStrings([choice.label,choice.description]),
    })),
  };
}

/** Validate identity/tag/case coverage without running steps() or withVariant(). */
export function validateScenarioSearchMetadata(entries) {
  const ids=new Set();
  for(const model of entries){
    ids.add(model.id);
    const entry=SCENARIO_SEARCH_REGISTRY[model.id];
    if(!entry||!entry.searchTags.length)throw new Error('Missing scenario search tags: '+model.id);
    if(entry.searchTags.some(tag=>!tag.trim())||new Set(entry.searchTags.map(scenarioMetadataKey)).size!==entry.searchTags.length)throw new Error('Blank or duplicate search tags: '+model.id);
    createScenarioSearchMetadata(model);
  }
  for(const id of Object.keys(SCENARIO_SEARCH_REGISTRY))if(!ids.has(id))throw new Error('Unknown registry destination: '+id);
  return {identities:ids.size,registryEntries:Object.keys(SCENARIO_SEARCH_REGISTRY).length};
}
