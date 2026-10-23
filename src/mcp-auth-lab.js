import {labAttribute,labP,labStep,labScenario} from './lab-common.js';
import {jwtValidateFixture,jwtIntrospectionDecision} from './jwt-policy.js';

export const MCPLAB_ATTRIBUTES={};
export const MCPLAB_SOURCES=[
  {
    "id": "next-mcp-url-34fabf499cb7",
    "title": "MCP authorization 2026-07-28",
    "standard": "MCP 2026-07-28",
    "url": "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization",
    "section": "Roles; Scope Selection Strategy; Authorization Response Validation; Resource Parameter Implementation; Access Token Usage; Scope Challenge Handling",
    "revision": "MCP 2026-07-28",
    "snapshotSha256": "0d445a7888aaa67108d3623fe4f55cf8dfe98951dfaf22bef50d824f3c1ff535"
  },
  {
    "id": "next-mcp-url-4e20f9bca3cb",
    "title": "User-requested tutorial",
    "standard": "MCP 2026-07-28",
    "url": "https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/authorization",
    "section": "Step-by-step introductory flow; legacy DCR/session implementation sample (not current normative baseline)",
    "revision": "MCP 2026-07-28",
    "snapshotSha256": "de6edec79cc7c0a2a4ba7f9cd6b6a4df15f056f45573f281e3104a7dfcff3ab6"
  },
  {
    "id": "next-mcp-url-2058d5663b79",
    "title": "RFC 9728 - Protected Resource Metadata",
    "standard": "RFC 9728",
    "url": "https://www.rfc-editor.org/rfc/rfc9728.html",
    "section": "Sections 2-5, 7.3-7.8: resource identity, metadata/challenge, audience, SSRF and phishing. RFC Editor initially read; later 429 was resolved using the IETF copy.",
    "revision": "RFC 9728 - Protected Resource Metadata",
    "snapshotSha256": "e395d326c517f89bd926930defb1b4bbd2ea2d5203b692ab582ae457846f700e"
  },
  {
    "id": "next-mcp-url-5cb9d8ac9518",
    "title": "RFC 8707 - Resource Indicators",
    "standard": "RFC 8707",
    "url": "https://www.rfc-editor.org/rfc/rfc8707.html",
    "section": "Section 2: target resource in grant/token requests; scopes and audiences solve different problems.",
    "revision": "RFC 8707 - Resource Indicators",
    "snapshotSha256": "d085d9b8e5665995a3c9702ffb1458ac93c51855624f1109e2c81e467f3e82dd"
  },
  {
    "id": "next-mcp-url-cb6a61add96b",
    "title": "RFC 7636 - PKCE",
    "standard": "RFC 7636",
    "url": "https://www.rfc-editor.org/rfc/rfc7636.html",
    "section": "Sections 4.1-4.6 and Appendix B: verifier, S256 challenge and redemption binding.",
    "revision": "RFC 7636 - PKCE",
    "snapshotSha256": "1dd39bd17081e0ed18c2cf304b87c79061c51e505d2ff5e12ffbd0d182fe5b20"
  },
  {
    "id": "next-mcp-url-478bbf202b68",
    "title": "RFC 6750 - Bearer use",
    "standard": "RFC 6750",
    "url": "https://www.rfc-editor.org/rfc/rfc6750.html",
    "section": "Sections 2.1, 3 and 3.1: Authorization header, challenges, invalid_token and insufficient_scope.",
    "revision": "RFC 6750 - Bearer use",
    "snapshotSha256": "c458bb43ff32efb811466120efdec411010cdde537e59948342240a32dcd5a1c"
  },
  {
    "id": "next-mcp-url-6e1c66cfb825",
    "title": "MCP Streamable HTTP 2026-07-28",
    "standard": "MCP 2026-07-28",
    "url": "https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http",
    "section": "Sending Messages; Request Metadata; Server Validation",
    "revision": "MCP 2026-07-28",
    "snapshotSha256": "cb81bac07c568c25e6844303276195834db36c6d606659d91d93a8b8fda32c84"
  },
  {
    "id": "next-mcp-url-117c3edbfcd7",
    "title": "MCP authorization-server discovery 2026-07-28",
    "standard": "MCP 2026-07-28",
    "url": "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery",
    "section": "Protected Resource Metadata Discovery Requirements; Authorization Server Metadata Discovery",
    "revision": "MCP 2026-07-28",
    "snapshotSha256": "49a047e7b94dd837d171d1efd61661022ef181543ab72f29d862007e1fa22d2e"
  },
  {
    "id": "next-mcp-url-7c80959f0ef2",
    "title": "RFC 8414 - Authorization Server Metadata",
    "standard": "RFC 8414",
    "url": "https://www.rfc-editor.org/rfc/rfc8414.html",
    "section": "Sections 2, 3.1, 3.3 and 5: endpoints/capabilities, path insertion and issuer matching.",
    "revision": "RFC 8414 - Authorization Server Metadata",
    "snapshotSha256": "05083c732395b4499316f5d030f2f86cc203f9ac8a455af7efb3f27a29b57697"
  },
  {
    "id": "next-mcp-url-85a922f6cf28",
    "title": "OpenID Connect Discovery 1.0, errata set 2",
    "standard": "OpenID Connect Discovery 1.0, errata set 2",
    "url": "https://openid.net/specs/openid-connect-discovery-1_0.html",
    "section": "Sections 4.1-4.3: provider configuration alternative; discovery does not itself turn OAuth into OIDC login.",
    "revision": "OpenID Connect Discovery 1.0, errata set 2",
    "snapshotSha256": "0401a07b35de50e914e195aa2c3c64cc4f6542464381c885d24a2623fbf75ec2"
  },
  {
    "id": "next-mcp-url-5655f61af2a0",
    "title": "MCP client registration 2026-07-28",
    "standard": "MCP 2026-07-28",
    "url": "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration",
    "section": "Implementation Requirements; Advertising CIMD Support; Dynamic Client Registration; Authorization Server Binding",
    "revision": "MCP 2026-07-28",
    "snapshotSha256": "2b65478c58e149b008b8ae6711a152e1dbbc180be426cc2e494283110ebde776"
  },
  {
    "id": "next-mcp-url-c6ba78bdbb90",
    "title": "CIMD draft cited by MCP: -00",
    "standard": "draft-ietf-oauth-client-id-metadata-document-00",
    "url": "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00",
    "section": "Exact normative draft reference in MCP 2026-07-28; preserve this baseline instead of silently mixing later drafts.",
    "revision": "draft-ietf-oauth-client-id-metadata-document-00",
    "snapshotSha256": "845d2f2b5485aaf78da6b39f805a2755150e5082e7e282867d628d77cd6eaa45"
  },
  {
    "id": "next-mcp-url-d0f5a8798d31",
    "title": "CIMD current IETF record: -02",
    "standard": "draft-ietf-oauth-client-id-metadata-document-02; updated2026-07-06",
    "url": "https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/",
    "section": "Active Internet-Draft observed 2026-10-21; updated 2026-07-06. No invented final RFC or extension version.",
    "revision": "draft-ietf-oauth-client-id-metadata-document-02; updated2026-07-06",
    "snapshotSha256": "af66629beafdfc62cff3da1af6426f111221362dfe52ec694282e93074655890"
  },
  {
    "id": "next-mcp-url-d6251e5cec01",
    "title": "RFC 7591 - Dynamic Client Registration",
    "standard": "RFC 7591",
    "url": "https://www.rfc-editor.org/rfc/rfc7591.html",
    "section": "Sections 2-3: optional compatibility branch only; deprecated by the selected MCP version, not falsely called universally required.",
    "revision": "RFC 7591 - Dynamic Client Registration",
    "snapshotSha256": "a946f977f181ea69b2c7566584fa7b6fac90a158828ef4cf8168f87be6b2c90a"
  },
  {
    "id": "next-mcp-url-4b9b953ca683",
    "title": "MCP authorization security 2026-07-28",
    "standard": "MCP 2026-07-28",
    "url": "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations",
    "section": "Token Audience Binding and Validation; Authorization Code Protection; Client ID Metadata Document Security; Confused Deputy Problem; Access Token Privilege Restriction",
    "revision": "MCP 2026-07-28",
    "snapshotSha256": "b5d44ab4222224b9c687c3c566e3666df81cdeb236f18620ad7f7dc3501f30bf"
  },
  {
    "id": "next-mcp-url-a3e5dca68e99",
    "title": "RFC 9207 - Authorization response issuer",
    "standard": "RFC 9207",
    "url": "https://www.rfc-editor.org/rfc/rfc9207.html",
    "section": "Sections 2.3-2.4: advertised issuer response support and exact issuer comparison; MCP adds a present-iss check even without advertisement.",
    "revision": "RFC 9207 - Authorization response issuer",
    "snapshotSha256": "482fca2e2591ac8b30566f952112bfb19887f186c5140251ccd4948a64a3be85"
  },
  {
    "id": "next-mcp-url-4e6d674bf887",
    "title": "RFC 9700 - OAuth security BCP",
    "standard": "RFC 9700",
    "url": "https://www.rfc-editor.org/rfc/rfc9700.html",
    "section": "Sections 2.1, 4.4, 4.7, 4.8 and 4.14: redirects, mix-up, CSRF, downgrade and refresh protection.",
    "revision": "RFC 9700 - OAuth security BCP",
    "snapshotSha256": "c00e2234fcd79581bc29669c60d693afaa42f67d9205bddee848f757ae975419"
  },
  {
    "id": "next-mcp-url-c36d79fcad94",
    "title": "RFC 9068 - JWT access-token profile",
    "standard": "RFC 9068",
    "url": "https://www.rfc-editor.org/rfc/rfc9068.html",
    "section": "Section 4: validation for the explicitly selected at+jwt profile; MCP does not require all access tokens to be JWTs.",
    "revision": "RFC 9068 - JWT access-token profile",
    "snapshotSha256": "03f9f0f2090864299fa2779dd4129824859017165a0ae99f90669d7084a1712f"
  },
  {
    "id": "next-mcp-url-80790969b697",
    "title": "RFC 7662 - Introspection",
    "standard": "RFC 7662",
    "url": "https://www.rfc-editor.org/rfc/rfc7662.html",
    "section": "Section 2: protected token-status endpoint and active response; use only for the declared opaque-token profile.",
    "revision": "RFC 7662 - Introspection",
    "snapshotSha256": "8c36ce5246215c16fac436fafda277ee0638566b7610aa5cc6673388009445d7"
  },
  {
    "id": "next-mcp-url-6de02dfd2c80",
    "title": "RFC 7009 - Token revocation",
    "standard": "RFC 7009",
    "url": "https://www.rfc-editor.org/rfc/rfc7009.html",
    "section": "Sections 2 and 3: optional revocation endpoint profile, response/propagation distinctions.",
    "revision": "RFC 7009 - Token revocation",
    "snapshotSha256": "af01723527d58beb02d56c236d4cec1e9b702da239e9a91920e9ecc839c01d8f"
  },
  {
    "id": "next-mcp-url-920caecd56af",
    "title": "MCP tools 2026-07-28",
    "standard": "MCP 2026-07-28",
    "url": "https://modelcontextprotocol.io/specification/2026-07-28/server/tools",
    "section": "Tool definitions; listing; invocation; security considerations",
    "revision": "MCP 2026-07-28",
    "snapshotSha256": "a4160085bea033598ef252dc0d52f6ca217a7c8cc201ef51f1082445bfd05246"
  },
  {
    "id": "next-mcp-url-4903497743e8",
    "title": "MCP security best practices 2026-07-28",
    "standard": "MCP 2026-07-28",
    "url": "https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices",
    "section": "Confused Deputy Problem; Token Passthrough; Server-Side Request Forgery",
    "revision": "MCP 2026-07-28",
    "snapshotSha256": "b7e168e0d69dcee5e7d0935b3cd99049132261425a19504382835110fa92211b"
  },
  {
    "id": "next-mcp-url-d615a0183fe5",
    "title": "MCP stdio 2026-07-28",
    "standard": "MCP 2026-07-28",
    "url": "https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio",
    "section": "Request Metadata; Shutdown; Unexpected Termination",
    "revision": "MCP 2026-07-28",
    "snapshotSha256": "5793ffd99cbf63d405f128393409ad473fe68dbfc9b25c59fde2133ee1ab3079"
  },
  {
    "id": "next-mcp-url-86d0ba4323f1",
    "title": "MCP local server security 2026-07-28",
    "standard": "MCP 2026-07-28",
    "url": "https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/local-server-security",
    "section": "Local process authority; credentials; sandbox deployment guidance",
    "revision": "MCP 2026-07-28",
    "snapshotSha256": "903779636240f5b51852f97bbff1093132eb38588dc39cdc9622851f0c21232d"
  },
  {
    "id": "next-mcp-url-8de706439f16",
    "title": "Optional OAuth client-credentials extension",
    "standard": "Optional OAuth client-credentials extension",
    "url": "https://modelcontextprotocol.io/extensions/auth/oauth-client-credentials",
    "section": "Independent extension io.modelcontextprotocol/oauth-client-credentials; mutable page observed 2026-10-21, implementation must retain a source snapshot/hash.",
    "revision": "Optional OAuth client-credentials extension",
    "snapshotSha256": "ffd9078cc51c61addb371aafbc1732f77d92d1b1bcb91bd3f3ab23b581054dd1"
  },
  {
    "id": "next-mcp-url-28748e610219",
    "title": "RFC 6749 - Client credentials",
    "standard": "RFC 6749",
    "url": "https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4",
    "section": "Section 4.4: confidential application grant, no user delegation; refresh tokens should not normally be included.",
    "revision": "RFC 6749 - Client credentials",
    "snapshotSha256": "535362fa3b4ca668d4734c244c6ed8c811f2ccd7ea1612a4201e5d8922a74b4e"
  },
  {
    "id": "next-mcp-url-31f263d73f91",
    "title": "RFC 7523 - Client assertion",
    "standard": "RFC 7523",
    "url": "https://www.rfc-editor.org/rfc/rfc7523.html",
    "section": "Sections 2.2 and 3: JWT client authentication distinct from the resulting resource access token.",
    "revision": "RFC 7523 - Client assertion",
    "snapshotSha256": "718fd1261b19af816ac064386f5373d63ed2b7891a0bb057ebbe29f628202f24"
  },
  {
    "id": "next-mcp-url-a739f7343f18",
    "title": "MCP 2026-07-28 changes",
    "standard": "MCP 2026-07-28",
    "url": "https://modelcontextprotocol.io/specification/2026-07-28/changelog",
    "section": "Major changes 1-4; Minor changes 4,7-9; Deprecated 4",
    "revision": "MCP 2026-07-28",
    "snapshotSha256": "865966bec9f9b2759c9ad483ffbebf31604c3bb189e6f3b7304caec847810b19"
  },
  {
    "id": "next-mcp-url-5adefa332170",
    "title": "OAuth 2.1 draft cited by MCP: -13",
    "standard": "draft-ietf-oauth-v2-1-13",
    "url": "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13",
    "section": "Exact draft cited by the selected MCP specification; not an RFC.",
    "revision": "draft-ietf-oauth-v2-1-13",
    "snapshotSha256": "a9f7fe7b28e90891fef24961894ca882bc17aeaa650495985fa84cdfa44c0436"
  },
  {
    "id": "next-mcp-url-5c3b61a554c2",
    "title": "OAuth 2.1 current IETF record: -16",
    "standard": "draft-ietf-oauth-v2-1-16; updated2026-09-02; dated2026-09-03",
    "url": "https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/",
    "section": "Active Internet-Draft observed 2026-10-21; record updated 2026-09-02, document dated 2026-09-03. Recheck at implementation freeze.",
    "revision": "draft-ietf-oauth-v2-1-16; updated2026-09-02; dated2026-09-03",
    "snapshotSha256": "c6296b5f06d0e4773789ce28fab33f5d569ebd9467a37408ed19ba9ad9200a3c"
  }
];
const mcpProfileSourceIds={"1":["next-mcp-url-4e20f9bca3cb","next-mcp-url-34fabf499cb7","next-mcp-url-2058d5663b79","next-mcp-url-5cb9d8ac9518","next-mcp-url-cb6a61add96b","next-mcp-url-478bbf202b68","next-mcp-url-6e1c66cfb825"],"2":["next-mcp-url-117c3edbfcd7","next-mcp-url-2058d5663b79","next-mcp-url-7c80959f0ef2","next-mcp-url-85a922f6cf28","next-mcp-url-5655f61af2a0"],"3":["next-mcp-url-5655f61af2a0","next-mcp-url-c6ba78bdbb90","next-mcp-url-d0f5a8798d31","next-mcp-url-d6251e5cec01","next-mcp-url-4b9b953ca683"],"4":["next-mcp-url-a3e5dca68e99","next-mcp-url-cb6a61add96b","next-mcp-url-34fabf499cb7","next-mcp-url-4e6d674bf887","next-mcp-url-4b9b953ca683"],"5":["next-mcp-url-478bbf202b68","next-mcp-url-c36d79fcad94","next-mcp-url-80790969b697","next-mcp-url-5cb9d8ac9518","next-mcp-url-4b9b953ca683"],"6":["next-mcp-url-34fabf499cb7","next-mcp-url-478bbf202b68","next-mcp-url-2058d5663b79","next-mcp-url-4e6d674bf887"],"7":["next-mcp-url-34fabf499cb7","next-mcp-url-4b9b953ca683","next-mcp-url-4e6d674bf887","next-mcp-url-6de02dfd2c80","next-mcp-url-478bbf202b68"],"8":["next-mcp-url-920caecd56af","next-mcp-url-34fabf499cb7","next-mcp-url-c36d79fcad94","next-mcp-url-4e6d674bf887"],"9":["next-mcp-url-4b9b953ca683","next-mcp-url-4903497743e8","next-mcp-url-5cb9d8ac9518","next-mcp-url-cb6a61add96b","next-mcp-url-478bbf202b68"],"10":["next-mcp-url-4903497743e8","next-mcp-url-4b9b953ca683","next-mcp-url-5655f61af2a0","next-mcp-url-4e6d674bf887"],"11":["next-mcp-url-4b9b953ca683","next-mcp-url-5cb9d8ac9518","next-mcp-url-c36d79fcad94","next-mcp-url-80790969b697"],"12":["next-mcp-url-2058d5663b79","next-mcp-url-7c80959f0ef2","next-mcp-url-4b9b953ca683","next-mcp-url-4903497743e8","next-mcp-url-c6ba78bdbb90"],"13":["next-mcp-url-d615a0183fe5","next-mcp-url-86d0ba4323f1","next-mcp-url-34fabf499cb7"]};
const mcpFieldSchema=["ACL","Accept","Accepted","Action","Actual","Addresses","Advertised","Allowed","Approved","Attempt","Authorization","Available","Body","BoundDownstream","CIMDAdvertised","CacheScope","Candidates","Challenge","ChallengeExpected","ChallengeMethod","ChangedAfterApproval","Choice","Claims","Client","ClientId","CodeRecord","Consent","Containment","Content-Type","Cookie","CredentialAuthority","CredentialSent","CurrentVersionMetadata","DCRDeprecatedCompatibility","Decision","DerivedChallenge","Detector","DisplayName","DisplayNameTrust","Document","Exp","Expected","Generation","GrantClientMatches","Granted","HTTP","Header","Headers","Identity","Incoming","Input","Issuer","IssuerDecision","IssuerMatches","IssuerPresent","MCP-Protocol-Version","Mcp-Method","Mcp-Name","MetadataScopes","Method","NewAccess","NewGeneration","NextURL","NoHTTP401","Not","Now","OldGenerationValid","Outcome","Outgoing","Policy","PreviousRequested","PreviousURL","Profile","Protected carrier","Provider","Reason","Record","Redirect","RedirectHostname","RedirectMatches","Registration","Request","RequestId","Requested","Required","Resource","Response","Result","RootsAreSandbox","Scope","Scopes","SelectedOutgoing","SelectedPointer","Stage","State","StateMatches","TTLms","Target","Token","TokenInstance","Tool","Trust","URL","UpstreamRevoked","User","Verdict","VerifierMatches","WWW-Authenticate","client_id","code","code_challenge","code_challenge_method","code_verifier","error","error_description","expires_in","grant_type","iss","redirect_uri","resource","resourceOk","response_type","scope","state","token_type"];
const mcpObjectSchema=["tls-record","grant","client-registration","trust-record","access-token","secret","introspection-response","validation-context","metadata","validated-configuration","oauth-transaction","pkce-challenge","browser-cookie","consent","authorization-code","request","tool-list","host-approval","result","refresh-token","grant-comparison","pkce-verifier","untrusted-url","process-identity","protocol-object"];
function mcpFieldId(name){return 'mcp_field_'+name.replace(/[^\w]/g,'_');}
function mcpObjectId(type){return 'mcp_object_'+type.replace(/[^\w]/g,'_');}
MCPLAB_ATTRIBUTES[mcpFieldId('redirect')]=labAttribute('redirect','Callback destination bound to one transaction, not a trusted endpoint selected by a callback.','Authorization response','Compare exact approved callback before redemption.','Instance-specific callback','MCP 2026-07-28',MCPLAB_SOURCES[0].url);
MCPLAB_ATTRIBUTES[mcpFieldId('untrustedConsentHint')]=labAttribute('untrusted consent hint','An initiating client claim about an existing browser session is not matching per-client consent.','C2 request','Reject attempts to substitute prior consent or a cookie for the exact new client transaction.','none / reuse C1 session (untrusted)','MCP 2026-07-28','https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices');
for(const name of mcpFieldSchema)MCPLAB_ATTRIBUTES[mcpFieldId(name)]=labAttribute(name,'Explicit MCP/OAuth input or decision field; exact values and trust remain occurrence-local.','Declared actor','Inspect the source-authored operation without granting authority from prose.','Instance-specific synthetic fixture','MCP 2026-07-28',MCPLAB_SOURCES[0].url);
for(const type of mcpObjectSchema)MCPLAB_ATTRIBUTES[mcpObjectId(type)]=labAttribute(type.replace(/-/g,' '),'Exact '+type+' representation with explicit creator, custody and validation boundaries.','Actual source actor','Track exact generation, local creation, receipt and use.','Instance-specific synthetic fixture','MCP 2026-07-28',MCPLAB_SOURCES[0].url);
const mcpResource='https://mcp.lab.example/team/mcp',mcpIssuer='https://login.lab.example/tenant-a',mcpUpstream='https://api.lab.example/files',mcpUpIssuer='https://upstream-login.lab.example';
const mcpRedirect='http://127.0.0.1:49152/callback';
const mcpVerifier='dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',mcpChallenge='E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
function mcpFreeze(value){if(value&&typeof value==='object'&&!Object.isFrozen(value)){Object.values(value).forEach(mcpFreeze);Object.freeze(value);}return value;}
function mcpPut(path,value){return {op:'put',path:'mcp.'+path,value};}
function mcpEncode(value){return btoa(unescape(encodeURIComponent(JSON.stringify(value)))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');}
export function mcpAuthorizationIssuerDecision({advertised,iss,expectedIssuer}){return iss===undefined?{ok:advertised!==true,reason:advertised===true?'advertised issuer missing':'issuer absence permitted'}:{ok:iss===expectedIssuer,reason:iss===expectedIssuer?'exact issuer match':'issuer mismatch'};}
export function mcpCanonicalResource(value){try{const url=new URL(value);if(url.protocol!=='https:'||url.hash||url.username||url.password)return null;return url.origin+(url.pathname==='/'?'':url.pathname)+url.search;}catch{return null;}}
export function mcpDiscoveryCandidates(resource,issuer,pointer){const r=new URL(resource),a=new URL(issuer),path=a.pathname==='/'?'':a.pathname;return {resource:pointer?[pointer]:[r.origin+'/.well-known/oauth-protected-resource'+(r.pathname==='/'?'':r.pathname),r.origin+'/.well-known/oauth-protected-resource'].filter((v,i,x)=>x.indexOf(v)===i),authorization:[a.origin+'/.well-known/oauth-authorization-server'+path,a.origin+'/.well-known/openid-configuration'+path,...path?[issuer+'/.well-known/openid-configuration']:[]]};}
export function mcpParseChallenges(header){
  const chunks=[];let start=0,quoted=false,escaped=false;
  for(let i=0;i<header.length;i++){const c=header[i];if(escaped){escaped=false;continue;}if(c==='\\'&&quoted){escaped=true;continue;}if(c==='"')quoted=!quoted;if(c===','&&!quoted){chunks.push(header.slice(start,i).trim());start=i+1;}}chunks.push(header.slice(start).trim());
  const challenges=[];let current;
  for(const chunk of chunks){const match=/^([!#$%&'*+.^_`|~\w-]+)\s+(.*)$/.exec(chunk);if(match&&!match[2].startsWith('=')){current={scheme:match[1],parameters:{}};challenges.push(current);mcpReadParameter(match[2],current.parameters);}else if(current)mcpReadParameter(chunk,current.parameters);}
  return challenges;
}
function mcpReadParameter(text,target){const m=/^([\w-]+)\s*=\s*(?:"((?:\\.|[^"\\])*)"|([^\s,]+))$/.exec(text);if(m)target[m[1].toLowerCase()]=m[2]===undefined?m[3]:m[2].replace(/\\(.)/g,'$1');}
export function mcpScopeUnion(previous,challenge){return [...new Set([...previous,...challenge])].sort();}
export function mcpRegistrationChoice({issuer,existing,cimdAdvertised,dcrAdvertised,compatibility=false}){if(existing?.issuer===issuer)return 'existing';if(cimdAdvertised)return 'cimd';if(compatibility&&dcrAdvertised)return 'deprecated-dcr';return 'configuration-required';}
export function mcpCimdDecision({url,document,redirect,advertised=true,available=true,allowedDomain=true}){
  if(!advertised)return {ok:false,reason:'CIMD not advertised'};
  if(!available)return {ok:false,reason:'CIMD unavailable'};
  let parsed,body;try{parsed=new URL(url);body=typeof document==='string'?JSON.parse(document):document;}catch{return {ok:false,reason:'Invalid CIMD URL or JSON'};}
  if(parsed.protocol!=='https:'||parsed.pathname==='/'||parsed.username||parsed.password||parsed.hash||!allowedDomain)return {ok:false,reason:'CIMD URL/trust policy'};
  if(!body||Array.isArray(body)||body.client_id!==url||typeof body.client_name!=='string'||!Array.isArray(body.redirect_uris))return {ok:false,reason:'CIMD structure or exact client_id mismatch'};
  if(!body.redirect_uris.includes(redirect))return {ok:false,reason:'Redirect absent from client metadata'};
  return {ok:true,reason:'Validated draft -00 registration metadata; no user grant',registration:{client_id:url,redirect,token_endpoint_auth_method:body.token_endpoint_auth_method||'none'}};
}
export function mcpStepUpDecision({previousRequested=[],challengeScopes,metadataScopes,initial=false,attempt=0,maxAttempts=2}){
  if(attempt>=maxAttempts)return {ok:false,reason:'Step-up retry budget exhausted',attempt};
  const required=challengeScopes===undefined?(initial?metadataScopes||[]:[]):challengeScopes;
  return {ok:true,requested:mcpScopeUnion(previousRequested,required),attempt:attempt+1};
}
export function mcpRefreshGrantDecision({refresh,client,resource,scopes,network='delivered'}){
  if(!refresh)return {ok:false,reason:'No refresh token; reauthorize',reauthorize:true};
  if(network!=='delivered')return {ok:false,reason:'Bounded transient failure; no assumed AS response',reauthorize:false};
  if(!refresh.valid||refresh.revoked===true||refresh.expired===true||(refresh.currentGeneration!==undefined&&refresh.generation!==refresh.currentGeneration)||refresh.client!==client)return {ok:false,reason:'invalid_grant',reauthorize:true};
  if(refresh.resource!==resource)return {ok:false,reason:'invalid_target',reauthorize:false};
  if(!scopes.every(scope=>refresh.scopes.includes(scope)))return {ok:false,reason:'invalid_scope',reauthorize:false};
  return {ok:true,oldGenerationValid:false,newGeneration:refresh.generation+1,scopes:[...scopes]};
}
export function mcpProxyConsentDecision({record,user,client,redirect,scopes,csrf}){
  if(!record||record.integrity!==true||record.approved!==true||record.user!==user||record.client!==client||record.redirect!==redirect||record.csrf!==csrf||!scopes.every(scope=>record.scopes.includes(scope)))return {ok:false,upstreamContactAllowed:false,downstreamCodeAllowed:false,reason:'Matching per-user/per-client consent required'};
  return {ok:true,upstreamContactAllowed:true,downstreamCodeAllowed:true,reason:'Consent matches exact initiating transaction'};
}
export function mcpDestinationDecision({url,addresses=['203.0.113.20'],tlsTrusted=true,redirects=0,bytes=1024,seen=[],allowPrivate=false}){
  let parsed;try{parsed=new URL(url);}catch{return {ok:false,reason:'invalid URL',stage:'before-send'};}
  if(parsed.protocol!=='https:'||parsed.username||parsed.password||parsed.hash)return {ok:false,reason:'HTTPS authority required; no embedded credentials or fragment',stage:'before-send'};
  const privateAddress=[parsed.hostname.replace(/^\[|\]$/g,''),...addresses].some(x=>x.toLowerCase()==='localhost'||(x.includes(':')?/^(::1$|::ffff:(127\.|10\.|192\.168\.|169\.254\.)|f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:)/i.test(x):/^[0-9.]+$/.test(x)&&/^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(x)));
  if(privateAddress&&!allowPrivate)return {ok:false,reason:'declared public-egress policy blocks private destination',stage:'before-send'};
  if(redirects>3||seen.includes(url))return {ok:false,reason:'redirect budget or cycle',stage:'before-send'};
  if(!tlsTrusted)return {ok:false,reason:'TLS identity rejected',stage:'after-transport-before-application'};
  if(bytes>65536)return {ok:false,reason:'metadata size budget',stage:'after-response'};
  return {ok:true,reason:'destination policy accepted',stage:'before-send'};
}
const mcpReadOperation=mcpFreeze({tool:'read_file',target:'demo/report.txt',arguments:{path:'demo/report.txt'},requiredScopes:['files:read']});
const mcpWriteOperation=mcpFreeze({tool:'write_file',target:'demo/report.txt',arguments:{path:'demo/report.txt',content:'Reviewed report update'},requiredScopes:['files:write']});
export function mcpRequestEnvelope(method='tools/call',token='SYM(access-token-g1)',operation=mcpReadOperation){
  return {method:'POST',path:'/team/mcp',headers:{Accept:'application/json, text/event-stream','Content-Type':'application/json','MCP-Protocol-Version':'2026-07-28','Mcp-Method':method,...method==='tools/call'?{'Mcp-Name':operation.tool}:{},...token?{Authorization:'Bearer '+token}:{}},body:{jsonrpc:'2.0',id:7,method,params:{...method==='tools/call'?{name:operation.tool,arguments:{...operation.arguments}}:{},_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{}}}}};
}
export function mcpValidateEnvelope(request){const h=request.headers||{},b=request.body||{},meta=b.params?._meta;if(request.method!=='POST'||!h['MCP-Protocol-Version']||h['MCP-Protocol-Version']!==meta?.['io.modelcontextprotocol/protocolVersion']||typeof meta?.['io.modelcontextprotocol/clientCapabilities']!=='object'||meta['io.modelcontextprotocol/clientCapabilities']===null||typeof b.method!=='string'||h['Mcp-Method']!==b.method||(b.method==='tools/call'&&(!h['Mcp-Name']||h['Mcp-Name']!==b.params.name)))return {ok:false,status:400,reason:'HeaderMismatch'};return {ok:true};}
const mcpActorSpecs={mcpC:{name:'Host / MCP client C',type:'client',position:{x:145,y:120}},mcpB:{name:'User / browser B',type:'browser',position:{x:145,y:365}},mcpR:{name:'Protected MCP resource R',type:'server',position:{x:560,y:120}},mcpA:{name:'Authorization server A',type:'server',position:{x:975,y:120}},mcpS:{name:'Upstream authorization server UAS',type:'server',position:{x:975,y:365}},mcpU:{name:'Upstream API U',type:'server',position:{x:560,y:610}},mcpO:{name:'OS launcher / policy O',type:'server',position:{x:975,y:120}}};
mcpActorSpecs.mcpX={name:'Substitute issuer X',type:'server',position:{x:975,y:365}};
mcpActorSpecs.mcpT={name:'Authorization server A2 / independent issuer',type:'server',position:{x:975,y:365}};
mcpActorSpecs.mcpM={name:'Client metadata HTTPS host M',type:'server',position:{x:145,y:610}};
const mcpLearningQuestions=Object.freeze([
  'Who issues the token, and who decides to run the tool?',
  "Which resource and issuer may receive this client's credentials?",
  'Why does client registration not grant access to a tool?',
  'What do PKCE, state and issuer checks each prevent?',
  'When does a received token become an accepted operation?',
  'How can a read-only grant be deliberately upgraded to write?',
  'What do the client and issuer know when refresh fails?',
  'Why are OAuth permission, host approval and resource policy separate?',
  'Why does a proxy need a separate grant for its upstream API?',
  "Why can't a new client inherit another client's proxy consent?",
  "Why can't a proxy pass an upstream token through as its own grant?",
  'What must be checked before following an untrusted metadata URL?',
  'Which OS process and credential boundaries control local stdio access?'
]);
function mcpAuthor(number,title,variant,actorIds=['mcpC','mcpB','mcpR','mcpA']){
  const id='lab-mcp'+String(number).padStart(2,'0'),steps=[],definitions={},inventory={artifacts:[],initial:[],events:{},bindings:[]},objects=new Map();
  let holdingSerial=0;const authoredHoldings=new Map(),holdingKey=(artifactId,actorId,store,representationId)=>[artifactId,actorId,store,representationId].join('|');
  const initialState={mcp:{variant,tokenAccepted:false,hostInvocationApproved:false,resourceAuthorized:false,operationExecuted:false,resultLearned:false,clientKnowledge:'not attempted',serverDecision:'pending',priorReadGrant:{id:'prior-read-grant',valid:true,scopes:['files:read']},historicalDisclosure:[],credentialRequests:0,upstreamRequests:0,downstreamCodes:0}};
  initialState.mcp.asConsent=null;
  const artifact=(key,label,creator,value,{initial=false,holders=[creator],type='protocol-object',representation='plain',readers=actorIds}={})=>{
    const artifactId=id+':'+key,attributeId=mcpObjectId(type);
    definitions[attributeId]={...labAttribute(label,label+' is an exact synthetic '+type+'; possession, readability and accepted authority are separate.',creator,'Track exact object identity and generation at authored operations.',value,'MCP 2026-07-28',MCPLAB_SOURCES[0].url),section:MCPLAB_SOURCES[0].section,synthetic:true};
    const def={artifactId,label,creator,type,representations:[{representationId:representation,format:representation,readableBy:readers,fields:[{attributeId,name:label,value,readableBy:readers}]}]};inventory.artifacts.push(def);objects.set(artifactId,{attributeId,value,creator,representation,label});
    if(initial){inventory.initial.push({op:'create',artifactId},...holders.map(actorId=>acquire(artifactId,actorId,'local store',representation)));}return artifactId;
  };
  const acquire=(artifactId,actorId,store='local store',representationId=objects.get(artifactId).representation,retention='retained')=>{const holdingId=id+':holding:'+ ++holdingSerial,key=holdingKey(artifactId,actorId,store,representationId);if(!authoredHoldings.has(key))authoredHoldings.set(key,[]);authoredHoldings.get(key).push(holdingId);return {op:'acquire',artifactId,actorId,store,representationId,holdingId,retention};};
  const create=(artifactId,actorId=objects.get(artifactId).creator)=>[{op:'create',artifactId},acquire(artifactId,actorId)];
  const release=(artifactId,actorId,store='local store',representationId=objects.get(artifactId).representation)=>{const key=holdingKey(artifactId,actorId,store,representationId),holdingId=authoredHoldings.get(key)?.pop();if(!holdingId)throw new TypeError('No authored MCP holding to release: '+key);return {op:'release',artifactId,actorId,store,representationId,holdingId};};
  const event=(key,title,actor,values={},effects=[],refs=[],kind='inspect')=>{
    const sourceEventId=id+':'+key,fields=[],payload=[],operations=[];
    if(Object.hasOwn(inventory.events,sourceEventId))throw new TypeError('Duplicate MCP source event: '+sourceEventId);
    for(const [name,value] of Object.entries(values)){const attributeId=mcpFieldId(name);definitions[attributeId]=labAttribute(name,title,actor,'Explain explicit '+kind+' boundary',typeof value==='string'?value:JSON.stringify(value),'MCP 2026-07-28',MCPLAB_SOURCES[0].url);fields.push(attributeId);payload.push(labP(name,typeof value==='string'?value:JSON.stringify(value),title,attributeId));operations.push({attributeId,kind,actorId:actor,instanceId:sourceEventId+':record',creator:actor,holders:[actor],inspectors:[actor],fieldPath:name,representation:'plain',value:typeof value==='string'?value:JSON.stringify(value),sourceEventId,exactValueRef:sourceEventId+':'+name});}
    for(const ref of refs){const object=objects.get(ref.artifactId||ref),artifactId=ref.artifactId||ref,refKind=ref.kind||kind,representation=ref.representation||object.representation,value=ref.value??object.value,fieldPath=ref.fieldPath||object.label;fields.push(object.attributeId);payload.push(labP(fieldPath,value,title,object.attributeId));operations.push({attributeId:object.attributeId,kind:refKind,actorId:actor,instanceId:artifactId,creator:ref.creator||object.creator,holders:[actor],inspectors:[actor],fieldPath,representation,value,sourceEventId,exactValueRef:artifactId+':'+representation+':'+fieldPath});}
    const step=labStep(sourceEventId,title,actor,actor,key,'internal',title,title,fields,payload,[],operations);step.eventType='local';step.protocolLabel='Actor-local operation';step.protocolEffects=effects;steps.push(step);inventory.events[sourceEventId]={effects:[],messages:[]};return step;
  };
  const local=(key,title,actor,values={},effects=[],refs=[],held=[],kind='verify')=>{
    const step=event(key,title,actor,values,effects,refs,kind),ledger=inventory.events[step.id];
    ledger.effects.push(...held);
    for(const ref of refs){
      const artifactId=ref.artifactId||ref,object=objects.get(artifactId),operation=ref.kind||kind;
      if(operation==='inspect'||operation==='create'||held.some(effect=>effect.op==='create'&&effect.artifactId===artifactId))continue;
      ledger.effects.push({op:'observe',artifactId,actorId:actor,representationId:ref.representation||object.representation,kind:['verify','decrypt'].includes(operation)?'verification':'knowledge',result:operation+' at '+key});
    }
    return step;
  };
  const transfer=(key,title,from,to,refs=[],values={},effects=[],transport='HTTPS / TLS 1.3')=>{
    const packet=artifact(key+'-tls-record',title+' protected carrier',from,'SYM(TLS ciphertext '+key+')',{type:'tls-record',representation:'wire'});
    local(key+'-protect','Sender-local TLS protection / '+title,from,{},[],[...refs.map(ref=>typeof ref==='string'?{artifactId:ref,kind:'encrypt'}:{...ref,kind:'encrypt'}),{artifactId:packet,kind:'derive'}],[{op:'create',artifactId:packet},acquire(packet,from,'TLS output','wire','temporary')],'derive');
    const step=event(key,title,from,{'Protected carrier':'SYM(TLS ciphertext '+key+')'},[],[], 'send');step.from=from;step.to=to;step.channel='backchannel';step.eventType='message';step.protocolLabel=transport;step.layers=[{protocol:transport,transport,from,to,protection:'Endpoint TLS confidentiality/integrity; ciphertext is not plaintext'}];
    const wire=objects.get(packet);step.attributeOperations=[{attributeId:wire.attributeId,kind:'send',actorId:from,instanceId:packet,creator:from,holders:[from],inspectors:[from,to],fieldPath:wire.label,representation:'wire',value:wire.value,sourceEventId:step.id,exactValueRef:packet+':wire'},{attributeId:wire.attributeId,kind:'receive',actorId:to,instanceId:packet,creator:from,holders:[to],inspectors:[from,to],fieldPath:wire.label,representation:'wire',value:wire.value,sourceEventId:step.id,exactValueRef:packet+':wire'}];step.fields=[wire.attributeId];step.payload=[labP(wire.label,wire.value,'Protected bytes only',wire.attributeId)];inventory.events[step.id]={effects:[release(packet,from,'TLS output','wire'),acquire(packet,to,'wire inbox','wire','temporary')],messages:[{from,to,objects:[{artifactId:packet,representationId:'wire'}],start:0,end:1}]};
    const recovered=local(key+'-recover','TLS recovery / '+title,to,values,effects,refs,refs.map(ref=>acquire(ref.artifactId||ref,to)), 'decrypt');inventory.events[recovered.id].effects.push(release(packet,to,'wire inbox','wire'));return recovered;
  };
  const stop=(key,actor,reason,status='client-stop')=>local(key,'Stop: '+reason,actor,{Detector:reason,Outcome:status},[mcpPut('clientKnowledge',actor==='mcpC'?reason:'await response')]);
  const reply=(key,status,reason,from='mcpR',to='mcpC',headers={})=>{local(key+'-decision',reason,from,{HTTP:status},[mcpPut('serverDecision',status)]);transfer(key,reason+' response',from,to,[],{HTTP:status,Headers:headers,Reason:reason},[mcpPut(to==='mcpC'?'clientKnowledge':'proxyKnowledge',reason),mcpPut(to==='mcpC'?'responseStatus':'proxyResponseStatus',status)]);};
  const resourceError=(key,status,reason,{from='mcpR',to='mcpC',error,requiredScopes=['files:read'],metadata=from==='mcpU'?mcpUpstream+'/.well-known/oauth-protected-resource':'https://mcp.lab.example/metadata/team'}={})=>{
    const challenge='Bearer '+[...error?['error="'+error+'"']:[],'resource_metadata="'+metadata+'"',...requiredScopes.length?['scope="'+requiredScopes.join(' ')+'"']:[]].join(', ');
    reply(key,status,reason,from,to,{'WWW-Authenticate':challenge});
  };
  const tokenError=(key,error)=>{local(key+'-decision','AS rejects token-endpoint request','mcpA',{HTTP:400,error},[mcpPut('serverDecision',400)]);transfer(key,'AS token-endpoint error response','mcpA','mcpC',[],{HTTP:400,Headers:{},error,Reason:error},[mcpPut('clientKnowledge',error),mcpPut('responseStatus',400)]);};
  const finish=(extra={})=>{const model=labScenario({id,title,workspace:'mcp',family:'authorization',category:'MCP authorization',protocol:number===13?'MCP stdio':'MCP HTTP / OAuth',standard:'MCP 2026-07-28',source:MCPLAB_SOURCES[0].url,summary:title,learningObjective:mcpLearningQuestions[number-1],prerequisites:['Synthetic public client; issuer-bound registration','Trusted resource/issuer policy; fixed clock1000','No live authentication, subprocess or tool execution'],supportNote:'Offline symbolic standards teaching profile. No native/live interoperability evidence. Scope names are illustrative. OAuth2.1 -13 and CIMD -00 are drafts; dated specification overrides tutorial session/DCR examples.',profile:{id:'mcp-2026-07-28-'+number,name:title,version:'2026-07-28',publicationStatus:'Dated MCP specification; OAuth/CIMD Internet-Drafts',supportStatus:'Standards illustration, not product conformance',implementation:'Deterministic offline fixture',transport:number===13?'stdio':'Self-contained Streamable HTTP POST',clientType:'public desktop',registration:'existing exact-issuer registration',authorizationIssuer:mcpIssuer,resourceUri:mcpResource,tokenFormat:'RFC9068 JWT, explicit opaque comparison',grantAssumptions:'Human-delegated authorization code with S256; optional rotating refresh',startingSummary:['Client holds a separate prior read grant; this attempt cannot erase it.','Resource trusts configured issuer/audience, not clientInfo.','Host approval and resource policy are separate decisions.'],assumptions:['TLS already established under trusted synthetic endpoint policy','Approved loopback callback distinct from HTTPS production endpoints'],transports:[number===13?'Local stdin/stdout':'HTTPS POST /team/mcp'],algorithms:['PKCE S256 Appendix B vector','Symbolic RS256 signature verdict, not runtime crypto'],cryptoDetail:'SYM/HANDLE values and bound fixture evidence are not numerical proof.',completion:'Resource decision, protected result delivery and client learning remain distinct.',sources:MCPLAB_SOURCES.filter(source=>(mcpProfileSourceIds[number]||[]).includes(source.id))},initialState,mcpInventory:inventory,variantId:variant,relatedLessons:[{id:'lab-jwt08',title:'Token purposes',summary:'Separate profile; no credential transferred.'}],...extra},definitions,steps,Object.fromEntries(actorIds.map(actor=>[actor,{...mcpActorSpecs[actor],...(actor==='mcpR'&&number>=9&&number<=11?{name:'MCP proxy P'}:{}),...(actor==='mcpR'&&number===13?{name:'Local MCP subprocess S',parentId:'mcpC'}:{})}])));model.catalogAttributeIds=Object.keys(MCPLAB_ATTRIBUTES);model.decisionBindings=[{label:'AS consent',path:'mcp.asConsent'},{label:'Resource token accepted',path:'mcp.tokenAccepted'},{label:'Resource policy',path:'mcp.resourceAuthorized'},{label:'Host invocation approval',path:'mcp.hostInvocationApproved'},{label:'Operation executed',path:'mcp.operationExecuted'},{label:'Client learned result',path:'mcp.resultLearned'}];return model;};
  artifact('prior-read-grant','Prior read grant','mcpC','SYM(prior grant files:read)',{initial:true,type:'grant',readers:['mcpC']});
  if(actorIds.includes('mcpA')&&(number!==3||variant==='existing-registration'))artifact('issuer-registration','Existing issuer-bound public client registration','mcpC',JSON.stringify({issuer:mcpIssuer,client_id:'desktop-client',redirect:mcpRedirect,token_endpoint_auth_method:'none'}),{initial:true,type:'client-registration',readers:['mcpC','mcpA']});
  if(actorIds.includes('mcpR')&&number!==13)artifact('resource-trust','Operator-configured resource validation policy','mcpR',JSON.stringify({issuer:number===11?mcpUpIssuer:mcpIssuer,audience:mcpResource,algorithms:['RS256']}),{initial:true,type:'trust-record',readers:['mcpR']});
  return {id,number,variant,actorIds,steps,definitions,inventory,initialState,objects,artifact,acquire,create,release,local,transfer,stop,reply,resourceError,tokenError,finish};
}
function mcpToken(a,key='access-g1',{issuer=mcpIssuer,audience=mcpResource,scopes=['files:read'],expired=false,purpose='access',signature=true,owner='mcpA',initial=false,holders,opaque=false,readers=a.actorIds,trustedIssuer=mcpIssuer,clientId=a.clientId||'desktop-client'}={}){
  const header={alg:'RS256',kid:'mcp-key',typ:purpose==='access'?'at+jwt':'JWT'},claims={iss:issuer,sub:'user-7',aud:audience,exp:expired?900:1500,iat:expired?800:990,jti:key,client_id:clientId,scope:scopes.join(' ')};const signingInput=mcpEncode(header)+'.'+mcpEncode(claims),compact=opaque?'HANDLE(opaque '+key+')':signingInput+'.'+mcpEncode('SYM-signature');
  const artifactId=a.artifact(key,'Access token '+key,owner,compact,{initial,holders:holders||[owner],type:'access-token',representation:opaque?'opaque':'readable-untrusted',readers});
  return {artifactId,compact,instanceId:artifactId,claims,opaque,profile:{id:'mcp-rfc9068',issuer:trustedIssuer,audience:mcpResource,algorithms:['RS256'],requiredClaims:['iss','sub','aud','exp','iat','jti','client_id'],skewSeconds:0,audienceArray:true,purpose:'rfc9068-access'},keys:[{id:'mcp-signing-key',kid:'mcp-key',issuer:trustedIssuer,kty:'RSA',alg:'RS256',use:'sig',key_ops:['verify']}],signatureEvidence:{kind:'SYM',valid:signature,tokenInstanceId:artifactId,keyId:'mcp-signing-key',signingInput,signatureSegment:compact.split('.')[2]}};
}
function mcpValidateToken(a,token,{actor='mcpR',key='token-validation',issuer=mcpIssuer,audience=mcpResource,opaque=false,inactive=false,timeout=false,asActor='mcpA'}={}){
  opaque=opaque||token.opaque;
  const response={active:!inactive,aud:token.claims.aud,exp:token.claims.exp,scope:token.claims.scope};
  if(opaque){
    const credential=a.artifact(key+'-introspection-credential','R introspection authentication handle',actor,'HANDLE(resource introspection credential)',{initial:true,type:'secret',readers:[actor,asActor]});
    a.transfer(key+'-introspect','R authenticates to configured introspection endpoint',actor,asActor,[credential,token.artifactId],{URL:issuer+'/introspect',Token:token.compact});
    if(!timeout){const doc=a.artifact(key+'-introspection-json','Untrusted introspection response',asActor,JSON.stringify(response),{type:'introspection-response',representation:'readable-untrusted',readers:[asActor,actor]});a.local(key+'-introspection-create','AS constructs token status response',asActor,{},[],[doc],a.create(doc),'create');a.transfer(key+'-introspection-response','Receive protected introspection status',asActor,actor,[doc],{Response:response});}
  }
  const verdict=opaque?(token.claims.iss===issuer?jwtIntrospectionDecision({response,authenticated:true,expectedAudience:audience,now:1000,cachedAt:1000,ttlSeconds:15,timeout}):{ok:false,stage:'trust',code:'issuer-mismatch'}):jwtValidateFixture({token,profile:{...token.profile,issuer,audience},keys:token.keys,signatureEvidence:token.signatureEvidence,now:1000});
  const parsedRefs=[{artifactId:token.artifactId,kind:'inspect'}],parsedHoldings=[];
  if(!opaque){
    const definition=a.inventory.artifacts.find(item=>item.artifactId===token.artifactId),value=JSON.stringify(token.claims),attributeId=a.objects.get(token.artifactId).attributeId;
    if(!definition.representations.some(rep=>rep.representationId==='decoded-untrusted'))definition.representations.push({representationId:'decoded-untrusted',format:'Readable parsed JWT claims, not accepted identity',readableBy:[actor],fields:[{attributeId,name:'JWT claims',value,readableBy:[actor]}]});
    parsedRefs.push({artifactId:token.artifactId,kind:'inspect',representation:'decoded-untrusted',value,fieldPath:'JWT claims'});parsedHoldings.push(a.acquire(token.artifactId,actor,'decoded claims','decoded-untrusted'));
  }
  a.local(key+'-parse',opaque?'Receive untrusted introspection status':'Parse readable-untrusted token claims',actor,{Claims:opaque?(timeout?'No response received; no active status or claims invented':response):token.claims,Trust:'untrusted'},[],parsedRefs,parsedHoldings,'derive');
  const context=verdict.ok?a.artifact(key+'-context','R-local validated authorization context',actor,JSON.stringify({issuer,audience,scopes:opaque?response.scope:token.claims.scope,token:token.instanceId}),{type:'validation-context',readers:[actor]}):null;
  a.local(key,verdict.ok?'Accept resource token profile':'Reject resource token profile',actor,{Stage:verdict.stage||'introspection',Verdict:verdict.code||String(verdict.ok)},[mcpPut(a.number===9&&actor==='mcpU'?'upstreamTokenAccepted':'tokenAccepted',verdict.ok),mcpPut('tokenValidation',verdict)],[token.artifactId,...context?[{artifactId:context,kind:'create'}]:[]],context?a.create(context):[],'verify');return verdict.ok;
}
function mcpDiscover(a,{variant='default'}={}){
  const pointer=variant==='fallback-order'?undefined:'https://mcp.lab.example/metadata/team',header=variant==='multiple-challenges'?'Basic realm="old", Bearer resource_metadata="https://mcp.lab.example/metadata/team?label=a,b", scope="files:read"':pointer?`Bearer resource_metadata="${pointer}", scope="files:read"`:'Bearer scope="files:read"';
  const parsed=mcpParseChallenges(header),selected=parsed.find(x=>x.scheme.toLowerCase()==='bearer')?.parameters.resource_metadata,candidates=mcpDiscoveryCandidates(mcpResource,mcpIssuer,selected);
  a.local('challenge-parse','Parse Bearer challenge and pointer precedence','mcpC',{Header:header,SelectedPointer:selected||'none',Candidates:candidates},[mcpPut('discoveryCandidates',candidates)],[],[],'derive');
  if(variant==='fallback-order'){a.transfer('prm-path-request','Request path-specific PRM before root fallback','mcpC','mcpR',[],{Method:'GET',URL:candidates.resource[0]});a.transfer('prm-path-miss','Path-specific metadata unavailable','mcpR','mcpC',[],{URL:candidates.resource[0],HTTP:404});}
  a.transfer('prm-request','Request challenge-selected PRM or permitted root fallback','mcpC','mcpR',[],{Method:'GET',URL:candidates.resource.at(-1)});
  const value={resource:variant==='resource-mismatch'?'https://other.lab.example/api':mcpResource,...variant==='missing-authorization-servers'?{}:{authorization_servers:[variant==='issuer-switch'?'https://login.lab.example/tenant-b':mcpIssuer]},scopes_supported:['files:read']};const doc=a.artifact('prm-json','Received protected resource metadata','mcpR',JSON.stringify(value),{type:'metadata',representation:'readable-untrusted'});a.local('prm-create','Resource publishes metadata','mcpR',{},[],[doc],a.create(doc),'create');a.transfer('prm','Fetch protected resource metadata','mcpR','mcpC',[doc],{URL:candidates.resource.at(-1),Document:value});
  const resourceOk=Boolean(mcpCanonicalResource(value.resource)===mcpCanonicalResource(mcpResource)&&value.authorization_servers?.length>0);a.local('prm-validate','Validate canonical resource identity and required issuer list','mcpC',{resourceOk,Resource:value.resource},[mcpPut('resourceMetadataValid',resourceOk)],[doc],[],'verify');if(!resourceOk){a.stop('prm-stop','mcpC','Unusable resource metadata');return false;}
  const config=a.artifact('prm-validated','Validated protected resource configuration','mcpC',JSON.stringify(value),{type:'validated-configuration',readers:['mcpC']});a.local('issuer-binding','Bind selected issuer separately from received JSON','mcpC',{Issuer:value.authorization_servers[0]},[mcpPut('selectedIssuer',value.authorization_servers[0])],[{artifactId:doc,kind:'use'},{artifactId:config,kind:'create'}],a.create(config),'derive');
  if(variant==='issuer-switch'){a.stop('issuer-isolation','mcpC','Existing tenant-a credentials not applicable to tenant-b');return false;}
  if(variant==='discovery-exhausted'){for(const [i,url] of candidates.authorization.entries()){a.transfer('as-probe-'+i,'Request permitted AS metadata endpoint','mcpC','mcpA',[],{URL:url});a.transfer('as-unavailable-'+i,'AS metadata endpoint unavailable','mcpA','mcpC',[],{URL:url,HTTP:404});}a.stop('discovery-stop','mcpC','No permitted AS metadata document; do not invent endpoints');return false;}
  if(variant==='fallback-order')for(let i=0;i<2;i++){a.transfer('as-probe-'+i,'Request next permitted AS metadata endpoint','mcpC','mcpA',[],{Method:'GET',URL:candidates.authorization[i]});a.transfer('as-miss-'+i,'Permitted AS metadata fallback','mcpA','mcpC',[],{URL:candidates.authorization[i],HTTP:404});}
  a.transfer('as-request','Request the selected OAuth/OIDC metadata endpoint','mcpC','mcpA',[],{Method:'GET',URL:candidates.authorization[variant==='fallback-order'?2:0]});
  const metadata={issuer:variant==='issuer-mismatch'?mcpIssuer+'/':mcpIssuer,authorization_endpoint:mcpIssuer+'/authorize',token_endpoint:mcpIssuer+'/token',code_challenge_methods_supported:variant==='pkce-absent'?undefined:['S256'],authorization_response_iss_parameter_supported:true,client_id_metadata_document_supported:true};const asdoc=a.artifact('as-json','Received AS metadata','mcpA',JSON.stringify(metadata),{type:'metadata',representation:'readable-untrusted'});a.local('as-create','AS publishes capabilities','mcpA',{},[],[asdoc],a.create(asdoc),'create');a.transfer('as-metadata','Obtain issuer metadata','mcpA','mcpC',[asdoc],{URL:candidates.authorization[variant==='fallback-order'?2:0],Document:metadata});
  a.local('as-validate','Validate exact AS issuer and HTTPS endpoints','mcpC',{Expected:mcpIssuer,Actual:metadata.issuer},[mcpPut('asMetadataValid',metadata.issuer===mcpIssuer)],[asdoc],[],'verify');if(metadata.issuer!==mcpIssuer){a.stop('as-stop','mcpC','AS issuer mismatch');return false;}
  if(!metadata.code_challenge_methods_supported?.includes('S256')){a.stop('pkce-stop','mcpC','S256 not advertised; do not open authorization');return false;}return true;
}
function mcpGrant(a,{variant='default',requestedScopes=['files:read'],grantedScopes=requestedScopes,key='grant',operation=mcpReadOperation,onAuthorizationReceived}={}){
  const clientId=a.clientId||'desktop-client';
  const selectedMethod=variant==='pkce-downgrade'?'plain':'S256';a.local(key+'-pkce-selection','Require advertised S256 before opening the authorization flow','mcpC',{ChallengeMethod:selectedMethod});
  if(selectedMethod!=='S256'){a.stop(key+'-downgrade','mcpC','S256 required; plain downgrade refused');return null;}
  const tx=a.artifact(key+'-transaction','OAuth transaction/state/issuer binding','mcpC',JSON.stringify({state:'SYM(state-'+key+')',issuer:mcpIssuer,redirect:mcpRedirect,client_id:clientId,operation}),{type:'oauth-transaction',readers:['mcpC']});const verifier=a.artifact(key+'-verifier','PKCE verifier','mcpC',mcpVerifier,{type:'secret',readers:['mcpC','mcpA']});const challenge=a.artifact(key+'-challenge','PKCE S256 challenge','mcpC',mcpChallenge,{type:'pkce-challenge'});a.local(key+'-prepare','Create fresh transaction and local PKCE secret','mcpC',{Attempt:key,ChallengeMethod:'S256',Tool:operation.tool,Target:operation.target},[],[tx,verifier,challenge],[...a.create(tx),...a.create(verifier),...a.create(challenge)],'create');
  const params={response_type:'code',client_id:clientId,redirect_uri:mcpRedirect,state:'SYM(state-'+key+')',code_challenge:mcpChallenge,code_challenge_method:'S256',resource:mcpResource,scope:requestedScopes.join(' ')},request=a.artifact(key+'-authorization-request','Complete authorization transaction parameters','mcpC',JSON.stringify(params),{type:'request',readers:['mcpC','mcpB','mcpA']});
  a.local(key+'-authorization-construct','Construct exact authorization request for this operation','mcpC',{Request:params},[],[request],a.create(request),'create');
  a.transfer(key+'-authorization','Browser authorization request','mcpC','mcpB',[challenge,request],params);a.transfer(key+'-browser-as','Browser reaches selected AS with complete authorization request','mcpB','mcpA',[challenge,request],params);
  if(onAuthorizationReceived&&!onAuthorizationReceived(params,request))return null;
  const cookie=a.artifact(key+'-browser-cookie','AS browser authentication cookie','mcpA','HANDLE(AS cookie user-7)',{type:'browser-cookie',readers:['mcpA','mcpB']});a.local(key+'-as-authentication','AS chosen user authentication','mcpA',{User:'user-7',Not:'MCP password exchange'},[mcpPut('asUserAuthenticated',true)],[cookie],a.create(cookie),'create');a.transfer(key+'-cookie','Browser receives AS cookie','mcpA','mcpB',[cookie],{Cookie:'HttpOnly/Secure synthetic cookie; never C/R'});
  const denied=['consent-cancel','consent-declined'].includes(variant);a.local(key+'-consent',denied?'User declines AS consent':'AS records user/client/resource consent','mcpA',{Client:clientId,Resource:mcpResource,Requested:requestedScopes,Scopes:grantedScopes,Approved:!denied,Tool:operation.tool,Target:operation.target},[mcpPut('asConsent',!denied)]);
  if(denied){a.transfer(key+'-cancel','Consent cancellation callback','mcpA','mcpC',[],{error:'access_denied',iss:mcpIssuer,state:'SYM(state-'+key+')'},[mcpPut('clientKnowledge','consent declined')]);a.local(key+'-cancel-cleanup','Dispose canceled client transaction scratch, not browser login or prior grants','mcpC',{},[],[{artifactId:verifier,kind:'dispose'},{artifactId:tx,kind:'dispose'}],[a.release(verifier,'mcpC'),a.release(tx,'mcpC')],'dispose');return null;}
  const consent=a.artifact(key+'-consent-record','Per-user per-client consent','mcpA',JSON.stringify({user:'user-7',client:clientId,resource:mcpResource,scopes:grantedScopes}),{type:'consent',readers:['mcpA']});const code=a.artifact(key+'-code','Single-use authorization code','mcpA','SYM(code-'+key+')',{type:'authorization-code',readers:['mcpA','mcpB','mcpC']});a.local(key+'-issue-code','Create consent record and one-time code','mcpA',{},[],[consent,code],[...a.create(consent),...a.create(code)],'create');
  const advertised=variant.startsWith('absent-advertisement-')?undefined:!variant.startsWith('unadvertised-'),iss=['advertised-iss-absent','unadvertised-iss-absent','absent-advertisement-iss-absent'].includes(variant)?undefined:['wrong-issuer','unadvertised-iss-wrong','absent-advertisement-iss-wrong','error-issuer-mismatch'].includes(variant)?mcpIssuer+'/':mcpIssuer;const state=variant==='wrong-state'?'SYM(other-state)':'SYM(state-'+key+')',redirect=variant==='wrong-redirect'?mcpRedirect+'/other':mcpRedirect;
  const substituted=['wrong-issuer','unadvertised-iss-wrong','absent-advertisement-iss-wrong','error-issuer-mismatch'].includes(variant),callbackSender=substituted?'mcpX':'mcpA',errorResponse=variant==='error-issuer-mismatch';
  const callbackCode=substituted&&!errorResponse?a.artifact(key+'-substituted-code','Substitute issuer authorization code','mcpX','SYM(substitute code)',{type:'authorization-code',readers:['mcpX','mcpB','mcpC']}):code;
  if(callbackCode!==code)a.local(key+'-substitute-create','Substitute issuer creates a different code, not the honest AS grant','mcpX',{},[],[callbackCode],a.create(callbackCode),'create');
  const callbackValues={state,redirect,...iss===undefined?{}:{iss},...errorResponse?{error:'access_denied',error_description:'UNTRUSTED synthetic text'}:{code:a.objects.get(callbackCode).value}},callbackMetadata=a.artifact(key+'-callback-metadata','Unaccepted authorization response parameters',callbackSender,JSON.stringify(callbackValues),{type:'protocol-object',readers:[callbackSender,'mcpB','mcpC']}),callbackObjects=[callbackMetadata,...errorResponse?[]:[callbackCode]];
  a.local(key+'-callback-create','Create response parameters without client acceptance',callbackSender,{},[],[callbackMetadata],a.create(callbackMetadata),'create');
  a.transfer(key+'-redirect','Browser receives authorization response',callbackSender,'mcpB',callbackObjects,callbackValues);
  mcpStdioTransfer(a,key+'-callback','Browser delivers unaccepted approved-loopback callback','mcpB','mcpC',callbackObjects,callbackValues,'Approved loopback HTTP callback');
  const issuerDecision=mcpAuthorizationIssuerDecision({advertised,iss,expectedIssuer:mcpIssuer}),valid=issuerDecision.ok&&state==='SYM(state-'+key+')'&&redirect===mcpRedirect;a.local(key+'-callback-validation','Validate state, issuer and registered callback before redemption','mcpC',{Advertised:advertised===undefined?{present:false,value:null}:advertised,...advertised===undefined?{Not:'Capability field absent from validated AS metadata; absence is not false'}:{},IssuerPresent:iss!==undefined,IssuerDecision:issuerDecision.reason,StateMatches:state==='SYM(state-'+key+')',RedirectMatches:redirect===mcpRedirect},[mcpPut('callbackAccepted',valid),mcpPut('trustedErrorDisplayed',false)],[tx,...callbackObjects]);if(!valid){a.stop(key+'-callback-stop','mcpC','Unaccepted callback; no token request');return null;}
  const suppliedVerifier=variant==='wrong-verifier'?'SYM(wrong verifier)':mcpVerifier,codeRecord={used:variant==='reused-code',expires:1100,resource:mcpResource,client:clientId};
  const submittedVerifier=suppliedVerifier===mcpVerifier?verifier:a.artifact(key+'-submitted-verifier','Substituted token-request verifier','mcpC',suppliedVerifier,{type:'secret',readers:['mcpC','mcpA']});
  if(submittedVerifier!==verifier)a.local(key+'-verifier-substitution','Construct changed verifier input; retain original transaction secret','mcpC',{},[],[submittedVerifier],a.create(submittedVerifier),'create');
  a.transfer(key+'-token-request','Redeem code only at recorded token endpoint','mcpC','mcpA',[code,submittedVerifier],{URL:mcpIssuer+'/token',grant_type:'authorization_code',client_id:clientId,code:'SYM(code-'+key+')',code_verifier:suppliedVerifier,resource:mcpResource,...variant==='oauth20-redirect-compat'?{redirect_uri:mcpRedirect,Profile:'Explicit OAuth2.0 token redirect compatibility'}:{}},[mcpPut('credentialRequests',1)]);
  const derivedChallenge=suppliedVerifier===mcpVerifier?mcpChallenge:'SYM(nonmatching S256 fixture evidence)',validCode=derivedChallenge===mcpChallenge&&!codeRecord.used&&codeRecord.expires>1000&&codeRecord.resource===mcpResource&&codeRecord.client===clientId;a.local(key+'-grant-validation','AS checks independently pinned S256 fixture evidence and code record','mcpA',{ChallengeExpected:mcpChallenge,DerivedChallenge:derivedChallenge,VerifierMatches:derivedChallenge===mcpChallenge,CodeRecord:codeRecord},[mcpPut('codeAccepted',validCode)],[code,submittedVerifier]);if(!validCode){a.tokenError(key+'-invalid-grant','invalid_grant');return null;}
  const token=mcpToken(a,key+'-access-g1',{scopes:grantedScopes}),scopeChanged=JSON.stringify([...requestedScopes].sort())!==JSON.stringify([...grantedScopes].sort()),tokenResponse={token_type:'Bearer',expires_in:500,...scopeChanged?{scope:grantedScopes.join(' ')}:{}};a.local(key+'-token-issue','AS issues resource-bound access token','mcpA',{Issuer:mcpIssuer,Resource:mcpResource,Requested:requestedScopes,Scopes:grantedScopes},[],[token.artifactId],a.create(token.artifactId),'create');a.transfer(key+'-token-response','Acquire token before resource acceptance','mcpA','mcpC',[token.artifactId],tokenResponse,[mcpPut('currentToken',token.instanceId)]);
  const learnedScopes=tokenResponse.scope===undefined?[...requestedScopes]:tokenResponse.scope.split(' ');a.local(key+'-scope-accept','Client records actual granted scopes from the token response','mcpC',{Requested:requestedScopes,Granted:learnedScopes,Tool:operation.tool},[mcpPut('grantedScopes',learnedScopes)],[token.artifactId]);
  a.local(key+'-client-cleanup','Dispose used client verifier and transaction scratch','mcpC',{},[mcpPut('codeConsumed',true)],[{artifactId:verifier,kind:'dispose'},{artifactId:tx,kind:'dispose'}],[a.release(verifier,'mcpC'),a.release(tx,'mcpC')],'dispose');
  a.local(key+'-as-cleanup','AS releases verifier scratch; consumed code history remains','mcpA',{},[],[{artifactId:submittedVerifier,kind:'dispose'}],[a.release(submittedVerifier,'mcpA')],'dispose');
  return token;
}
function mcpListTools(a,token){
  const request=mcpRequestEnvelope('tools/list',token.compact),object=a.artifact('list-request','Self-contained tools/list request','mcpC',JSON.stringify(request),{type:'request',readers:['mcpC','mcpR']});
  a.local('list-construct','Construct authenticated tools/list POST','mcpC',{Headers:request.headers,Body:request.body},[],[object],a.create(object),'create');
  a.transfer('list-request-wire','Retry tools/list with resource token','mcpC','mcpR',[object,token.artifactId],{Request:request});
  if(!mcpValidateToken(a,token,{key:'list-token'})){a.resourceError('list-invalid',401,'invalid_token',{error:'invalid_token'});return false;}
  a.local('list-policy','Authorize tool visibility for this request','mcpR',{Scope:'files:read'},[mcpPut('toolListAuthorized',true)],[token.artifactId]);
  const result=a.artifact('list-result','Authorization-scoped tool list','mcpR',JSON.stringify({jsonrpc:'2.0',id:7,result:{resultType:'complete',tools:[{name:'read_file',description:'Read one permitted example file',inputSchema:{type:'object',properties:{path:{type:'string'}}}}],ttlMs:30000,cacheScope:'private'}}),{type:'tool-list',readers:['mcpR','mcpC']});
  a.local('list-create','Create scoped private tool list','mcpR',{},[],[result],a.create(result),'create');
  a.transfer('list-result-wire','Deliver tool list, not an operation grant','mcpR','mcpC',[result],{CacheScope:'private',TTLms:30000});
  a.local('list-accept','Bind cached tool list to its authorization context','mcpC',{TokenInstance:token.instanceId},[mcpPut('toolListAccepted',true)],[result]);return true;
}
function mcpInvoke(a,token,{variant='default',operation=mcpReadOperation,key='operation',acl=true,host=true}={}){
  a.local(key+'-begin','Begin independent invocation decision','mcpC',{},[mcpPut('tokenAccepted',false),mcpPut('resourceAuthorized',false)]);
  const approvedArguments=operation.arguments,currentArguments=variant==='arguments-changed'?{...approvedArguments,path:'demo/other.txt'}:approvedArguments,userApproved=host&&!['host-denied','untrusted-annotations'].includes(variant),argumentsMatch=JSON.stringify(approvedArguments)===JSON.stringify(currentArguments),approved=userApproved&&argumentsMatch;
  const approval=a.artifact(key+'-approval','Host tool/target/arguments approval','mcpC',JSON.stringify({...operation,userApproved}),{type:'host-approval',readers:['mcpC']});a.local(key+'-host-approval','Host checks concrete tool/target/arguments against approval','mcpC',{Tool:operation.tool,Target:operation.target,Approved:approved,ChangedAfterApproval:!argumentsMatch,Input:variant==='untrusted-annotations'?{readOnlyHint:true,destructiveHint:false,trust:'untrusted annotations cannot waive host policy'}:currentArguments},[mcpPut('hostInvocationApproved',approved)],[approval],a.create(approval),'create');if(!approved){a.stop(key+'-host-stop','mcpC','No approved invocation; no tools/call POST');return;}
  const missing=['later-missing-token','clientinfo-only','cached-tools'].includes(variant),request=mcpRequestEnvelope('tools/call',missing?null:token.compact,operation);
  if(variant==='clientinfo-only')request.body.params._meta['io.modelcontextprotocol/clientInfo']={name:'Trusted-looking self-asserted client',version:'synthetic'};
  if(variant==='cached-tools'){const cached=a.artifact(key+'-foreign-tools','Historical tool list from another authorization context','mcpR',JSON.stringify({tokenInstance:'different-grant',tools:['read_file'],cacheScope:'private'}),{initial:true,holders:['mcpC'],type:'tool-list',readers:['mcpC','mcpR']});a.local(key+'-cache-selection','Cached visibility from another grant cannot replace this request authorization','mcpC',{TokenInstance:token.instanceId,Input:{selectedCacheGrant:'different-grant'}},[mcpPut('cacheContextMatches',false)],[cached]);}
  const requestObj=a.artifact(key+'-request','Self-contained MCP request','mcpC',JSON.stringify(request),{type:'request',readers:['mcpC','mcpR']});a.local(key+'-construct','Construct one independently authorized POST','mcpC',{Headers:request.headers,Body:request.body},[],[requestObj],a.create(requestObj),'create');a.transfer(key+'-request-wire','Send authenticated MCP request','mcpC','mcpR',[requestObj,...missing?[]:[token.artifactId]],{Method:'POST /team/mcp',CurrentVersionMetadata:true});a.local(key+'-metadata-check','Validate mirrored protocol/method/name metadata','mcpR',{Verdict:mcpValidateEnvelope(request)},[],[requestObj]);if(missing){a.resourceError(key+'-missing',401,'Bearer token required on every POST',{requiredScopes:operation.requiredScopes});return;}
  if(!mcpValidateToken(a,token,{key:key+'-token'})){a.resourceError(key+'-invalid',401,'invalid_token',{error:'invalid_token',requiredScopes:operation.requiredScopes});return;}
  const scopes=token.claims.scope.split(' '),scopeAllowed=operation.requiredScopes.every(scope=>scopes.includes(scope)),allowed=scopeAllowed&&acl;a.local(key+'-policy','Resource evaluates operation scope and object ACL','mcpR',{Tool:operation.tool,Target:operation.target,Required:operation.requiredScopes.join(' '),Granted:scopes,ACL:acl},[mcpPut('resourceAuthorized',allowed)],[token.artifactId]);if(!allowed){if(!scopeAllowed)a.resourceError(key+'-denied',403,'insufficient_scope',{error:'insufficient_scope',requiredScopes:operation.requiredScopes});else a.reply(key+'-denied',403,'Object ACL denied');return;}
  const output=operation.tool==='write_file'?'SYM(write completed for '+operation.target+')':'SYM(permitted report bytes)',result=a.artifact(key+'-result','Protected '+operation.tool+' result','mcpR',output,{type:'result',readers:['mcpR','mcpC']});a.local(key+'-execute','Execute authorized synthetic operation','mcpR',{Tool:operation.tool,Target:operation.target,Input:operation.arguments,Result:output},[mcpPut('operationExecuted',true),mcpPut('serverDecision',200)],[result],a.create(result),'create');a.transfer(key+'-result-wire','Deliver permitted result','mcpR','mcpC',[result],{HTTP:200,Body:{jsonrpc:'2.0',id:7,result:{resultType:'complete',content:[{type:'text',text:output}]}}},[mcpPut('resultReceived',true)]);a.local(key+'-result-accept','Accept correlated result and learn permitted output','mcpC',{RequestId:7,Tool:operation.tool,Target:operation.target},[mcpPut('resultLearned',true),mcpPut('clientKnowledge','accepted result'),mcpPut('responseStatus',200)],[result],[],'verify');
}
function mcpBuild01(variant){const a=mcpAuthor(1,'Remote MCP: discovery to authorized tool result',variant);a.transfer('initial-post','Unauthenticated tools/list POST','mcpC','mcpR',[],{Request:mcpRequestEnvelope('tools/list',null)});a.reply('initial-challenge',401,'Bearer challenge with resource pointer and initial scope','mcpR','mcpC',{'WWW-Authenticate':'Bearer resource_metadata="https://mcp.lab.example/metadata/team", scope="files:read"'});if(!mcpDiscover(a,{variant}))return a.finish();const token=mcpGrant(a,{variant});if(token&&mcpListTools(a,token))mcpInvoke(a,token,{variant});return a.finish();}
function mcpBuild02(variant){
  const a=mcpAuthor(2,'Discover the correct resource and authorization server',variant,['mcpC','mcpR','mcpA','mcpT']);
  const oldRefresh=a.artifact('old-issuer-refresh','Tenant-a refresh credential','mcpC','HANDLE(tenant-a refresh)',{initial:true,type:'refresh-token',readers:['mcpC','mcpA']});
  if(mcpDiscover(a,{variant}))a.local('discovery-complete','Validated metadata is configuration, not user authorization','mcpC',{CredentialSent:false},[mcpPut('clientKnowledge','resource and issuer configuration accepted')],[oldRefresh]);
  return a.finish();
}
function mcpBuild03(variant){
  const a=mcpAuthor(3,'Registration choices: CIMD and existing client registration',variant,['mcpC','mcpB','mcpR','mcpA','mcpM']),existing=variant==='existing-registration'?{issuer:mcpIssuer,client_id:'desktop-client'}:null,compatibility=variant.startsWith('dcr-'),cimdAdvertised=!compatibility&&variant!=='no-registration',choice=mcpRegistrationChoice({issuer:mcpIssuer,existing,cimdAdvertised,dcrAdvertised:compatibility,compatibility});
  const url='https://client.lab.example/oauth/metadata.json',document={client_id:variant==='cimd-id-mismatch'?url+'/wrong':url,client_name:'Untrusted Desktop name',redirect_uris:variant==='redirect-absent'?['https://client.lab.example/other']:[mcpRedirect],token_endpoint_auth_method:'none'};
  const capabilities=a.artifact('registration-capabilities','Previously validated issuer-bound registration capabilities','mcpC',JSON.stringify({issuer:mcpIssuer,client_id_metadata_document_supported:cimdAdvertised,...compatibility?{registration_endpoint:mcpIssuer+'/register'}:{}}),{initial:true,type:'validated-configuration',readers:['mcpC']});a.local('registration-capabilities','Use validated AS advertisement, never infer a registration endpoint from the resource origin','mcpC',{Issuer:mcpIssuer,Document:{client_id_metadata_document_supported:cimdAdvertised,...compatibility?{registration_endpoint:mcpIssuer+'/register'}:{}}},[],[capabilities]);
  a.local('registration-choice','Select existing exact-issuer registration before advertised CIMD','mcpC',{Issuer:mcpIssuer,Choice:choice,CIMDAdvertised:cimdAdvertised,DCRDeprecatedCompatibility:compatibility},[mcpPut('registrationMethod',choice)]);
  a.local('public-client-config','Public desktop client must not rely on a packaged secret','mcpC',{Client:'public desktop',CredentialAuthority:variant==='packaged-secret'?'distributed packaged secret relied upon':'no packaged secret; issuer-bound client ID only'});
  const recordRegistration=(verdict,registration,actor,request)=>{
    const record=verdict.ok?a.artifact('selected-registration','Validated registration separate from consent',actor,JSON.stringify({...registration,issuer:mcpIssuer}),{type:'client-registration',readers:[actor]}):null;
    a.local('registration-check','Validate selected registration and concrete redirect hostname',actor,{Accepted:verdict.ok,Reason:verdict.reason,RedirectHostname:'127.0.0.1',DisplayNameTrust:'untrusted',...request?{Request:request}:{}},[mcpPut('registrationAccepted',verdict.ok)],record?[{artifactId:record,kind:'create'}]:[],record?a.create(record):[],'verify');
  };
  if(choice==='cimd'&&variant!=='packaged-secret'){
    a.clientId=url;
    a.local('cimd-select','Select public HTTPS URL client identifier, not a registration exchange','mcpC',{client_id:url,redirect_uri:mcpRedirect});
    const doc=a.artifact('client-metadata','CIMD draft -00 document','mcpC',variant==='malformed-cimd'?'{broken':JSON.stringify(document),{type:'metadata',representation:'readable-untrusted',readers:['mcpC','mcpM','mcpA']});
    a.local('cimd-publish','Client author prepares public synthetic registration metadata','mcpC',{},[],[doc],a.create(doc),'create');a.transfer('cimd-hosting','Declared metadata host holds the public document, not client secrets','mcpC','mcpM',[doc],{URL:url});
    const token=mcpGrant(a,{variant,onAuthorizationReceived:(params,request)=>{
      a.local('cimd-request-binding','AS learns client URL and redirect from the received authorization transaction','mcpA',{client_id:params.client_id,redirect_uri:params.redirect_uri,state:params.state},[],[request]);
      if(variant!=='disallowed-domain'){
        a.transfer('cimd-request','AS requests client_id URL learned from this authorization request','mcpA','mcpM',[],{Method:'GET',URL:params.client_id});
        if(variant==='cimd-unavailable')a.transfer('cimd-unavailable','Metadata host reports missing document','mcpM','mcpA',[],{URL:params.client_id,HTTP:404});
        else a.transfer('cimd-fetch','Metadata host returns untrusted JSON to AS','mcpM','mcpA',[doc],{URL:params.client_id,HTTP:200});
      }
      const verdict=mcpCimdDecision({url:params.client_id,document:variant==='malformed-cimd'?'{broken':document,redirect:params.redirect_uri,available:variant!=='cimd-unavailable',allowedDomain:variant!=='disallowed-domain'});
      recordRegistration(verdict,verdict.registration,'mcpA',params);
      if(!verdict.ok){
        a.local('registration-reject','AS refuses the received authorization request without issuing a code or redirecting to an unvalidated URI','mcpA',{HTTP:400,error:'invalid_request',Request:params,Reason:verdict.reason});
        a.transfer('registration-error','Browser receives request-correlated authorization error at AS','mcpA','mcpB',[],{HTTP:400,error:'invalid_request',state:params.state,client_id:params.client_id,Reason:verdict.reason});
        return false;
      }
      return true;
    }});
    if(token)mcpInvoke(a,token);
  }else{
    let verdict={ok:false,reason:'No supported registration; configure issuer-bound client information'},registration=existing;
    if(choice==='existing')verdict={ok:true,reason:'Existing registration matches exact issuer'};
    if(choice==='deprecated-dcr'){
      const request={application_type:variant==='dcr-web-redirect'?'web':'native',redirect_uris:[mcpRedirect],grant_types:['authorization_code'],token_endpoint_auth_method:'none'};
      a.transfer('dcr-request','Explicit deprecated RFC7591 compatibility registration','mcpC','mcpA',[],{URL:mcpIssuer+'/register',Request:request});
      verdict={ok:request.application_type==='native'&&variant!=='dcr-failure',reason:request.application_type==='native'?'Registration endpoint verdict':'Web redirect policy incompatible with native loopback'};
      if(verdict.ok){registration={issuer:mcpIssuer,client_id:'dcr-native-client',redirect:mcpRedirect};a.transfer('dcr-response','Receive issuer-bound DCR registration, not an access grant','mcpA','mcpC',[],{HTTP:201,Registration:registration});}
      else a.transfer('dcr-error','Registration endpoint rejects deprecated compatibility request','mcpA','mcpC',[],{HTTP:400,error:'invalid_client_metadata',Reason:verdict.reason});
    }
    if(variant==='packaged-secret')verdict={ok:false,reason:'Distributed public-client secret cannot establish client authentication'};
    recordRegistration(verdict,registration,'mcpC');
    if(!verdict.ok)a.stop('registration-stop','mcpC',verdict.reason);
    else{a.clientId=registration.client_id;const token=mcpGrant(a,{variant});if(token)mcpInvoke(a,token);}
  }
  const model=a.finish();model.profile={...model.profile,registration:choice==='cimd'?'Advertised CIMD draft -00 resolved within authorization transaction':choice==='deprecated-dcr'?'Deprecated DCR compatibility':'Existing exact-issuer registration'};return model;
}
function mcpBuild04(variant){
  const a=mcpAuthor(4,'Reject a substituted authorization response',variant,['mcpC','mcpB','mcpR','mcpA','mcpX']);
  const metadata=a.artifact('validated-as-config','Previously validated AS issuer and response capabilities','mcpC',JSON.stringify({issuer:mcpIssuer,authorization_response_iss_parameter_supported:variant.startsWith('absent-advertisement-')?undefined:!variant.startsWith('unadvertised-'),code_challenge_methods_supported:['S256'],token_endpoint:mcpIssuer+'/token'}),{initial:true,type:'validated-configuration',readers:['mcpC']});
  a.local('selected-issuer','Retain validated issuer, endpoint and PKCE capability','mcpC',{},[],[metadata]);
  const token=mcpGrant(a,{variant});if(token)mcpInvoke(a,token);return a.finish();
}
function mcpFinishResult(a,key='resource',from='mcpR'){
  const result=a.artifact(key+'-result','Permitted operation result',from,'SYM(permitted result)',{type:'result',readers:[from,'mcpC']});
  a.local(key+'-execute','Execute only after independent local policy acceptance',from,{},[mcpPut('operationExecuted',true),mcpPut('serverDecision',200)],[result],a.create(result),'create');
  a.transfer(key+'-result-wire','Deliver protected result without granting early knowledge',from,'mcpC',[result],{HTTP:200,Body:{jsonrpc:'2.0',id:7,result:{resultType:'complete',content:[{type:'text',text:'SYM(permitted result)'}]}}},[mcpPut('resultReceived',true)]);
  a.local(key+'-result-accept','Accept correlated result at client','mcpC',{RequestId:7},[mcpPut('resultLearned',true),mcpPut('clientKnowledge','accepted result'),mcpPut('responseStatus',200)],[result]);
}
function mcpBuild05(variant){
  const a=mcpAuthor(5,'A received token is not yet an accepted request',variant),opaque=['opaque','inactive','introspection-unavailable'].includes(variant);
  const token=mcpToken(a,'received-access-g1',{initial:true,holders:['mcpC'],opaque,purpose:variant==='id-token'?'id':'access',audience:variant==='id-token'?'desktop-client':variant==='other-api'?'https://other.lab.example/api':mcpResource,issuer:variant==='wrong-issuer'?'https://unrelated.lab.example':mcpIssuer,expired:variant==='expired',signature:variant!=='bad-signature'});
  const request=mcpRequestEnvelope('tools/call',token.compact);a.transfer('resource-token-wire','Present credential in one self-contained request','mcpC','mcpR',[token.artifactId],{Request:request});
  if(!mcpValidateToken(a,token,{key:'resource-token',opaque,inactive:variant==='inactive',timeout:variant==='introspection-unavailable'})){a.resourceError('resource-invalid',401,'invalid_token',{error:'invalid_token'});return a.finish();}
  const acl=variant!=='acl-denied';a.local('resource-policy','Evaluate scope and independent file ACL after token validation','mcpR',{Scope:'files:read',ACL:acl},[mcpPut('resourceAuthorized',acl)],[token.artifactId]);
  if(!acl)a.reply('resource-denied',403,'Object ACL denied');else mcpFinishResult(a);
  const model=a.finish();model.profile={...model.profile,tokenFormat:opaque?'Opaque token with authenticated RFC7662 introspection':'RFC9068 JWT access token'};return model;
}
function mcpBuild06(variant){
  const a=mcpAuthor(6,'Insufficient scope and bounded incremental consent',variant),old=mcpToken(a,'read-access-g1',{initial:true,holders:['mcpC']});
  if(variant==='missing-challenge-scope'){const selection=mcpStepUpDecision({previousRequested:[],challengeScopes:undefined,metadataScopes:['files:read'],initial:true});a.local('initial-scope-selection','Starting read grant used metadata fallback only for the initial scope-less challenge','mcpC',{Header:'Initial 401 Bearer challenge omitted scope',MetadataScopes:['files:read'],Requested:selection.requested,Not:'A later scope-less step-up cannot infer unlimited or write access'},[mcpPut('initialScopeFallbackUsed',true)],[old.artifactId]);}
  const operation=mcpWriteOperation;
  a.transfer('write-request','Try write with unchanged read token','mcpC','mcpR',[old.artifactId],{Request:mcpRequestEnvelope('tools/call',old.compact,operation)});
  mcpValidateToken(a,old,{key:'read-token'});
  a.resourceError('scope-challenge',403,'insufficient_scope',{error:'insufficient_scope',requiredScopes:operation.requiredScopes});
  const attempt=variant==='repeated-challenge'?2:0,challengeScopes=['files:write'],metadataScopes=['challenge-outside-metadata','missing-challenge-scope'].includes(variant)?['files:read']:['files:read','files:write'],decision=mcpStepUpDecision({previousRequested:['files:read'],challengeScopes,metadataScopes,attempt,maxAttempts:2});
  a.local('stepup-check','Union prior requested scopes with authoritative operation challenge, bounded to two attempts','mcpC',{PreviousRequested:['files:read'],Challenge:challengeScopes||'(absent)',MetadataScopes:metadataScopes,Decision:decision},[mcpPut('stepUpAllowed',decision.ok),mcpPut('requestedScopes',decision.requested||['files:read']),mcpPut('stepUpAttempts',decision.attempt)],[{artifactId:old.artifactId,kind:'inspect'}],[],'derive');
  if(!decision.ok){a.stop('retry-stop','mcpC',decision.reason);return a.finish();}
  const approved=variant!=='consent-declined';a.local('stepup-consent','User decides additional scope consent, not file ACL','mcpA',{Requested:decision.requested,Approved:approved},[mcpPut('asConsent',approved)]);
  if(!approved){a.transfer('stepup-denied','Learn declined step-up without deleting old read grant','mcpA','mcpC',[],{error:'access_denied'},[mcpPut('clientKnowledge','step-up declined')]);return a.finish();}
  const granted=variant==='smaller-grant'?['files:read']:variant==='hierarchy-not-permission'?['files:read','files:*']:decision.requested;
  const token=mcpGrant(a,{key:'stepup-grant',requestedScopes:decision.requested,grantedScopes:granted,operation});if(token)mcpInvoke(a,token,{operation,acl:variant!=='upgrade-acl-denied'});
  return a.finish();
}
function mcpBuild07(variant){
  const a=mcpAuthor(7,'Expiry, refresh rotation and reauthorization',variant),originalScopes=variant==='offline-access-not-permission'?['offline_access']:['files:read'],old=mcpToken(a,'expired-access-g1',{initial:true,holders:['mcpC'],expired:true,scopes:originalScopes}),refresh=variant==='no-refresh'?null:a.artifact('refresh-g1','Rotating refresh generation 1','mcpA','HANDLE(refresh g1)',{initial:true,holders:['mcpC','mcpA'],type:'refresh-token',readers:['mcpC','mcpA']});
  a.local('expiry','Predict token expiry under deterministic clock without invalidating historical possession','mcpC',{Now:1000,Exp:900},[mcpPut('clock',1000),mcpPut('currentAccessExpired',true)],[old.artifactId]);
  const input={refresh:refresh?{valid:variant!=='refresh-rejected',revoked:variant==='refresh-rejected',client:'desktop-client',resource:mcpResource,scopes:originalScopes,generation:1,currentGeneration:variant==='rotated-reuse'?2:1}:null,client:'desktop-client',resource:variant==='refresh-resource-escalation'?mcpUpstream:mcpResource,scopes:variant==='refresh-scope-escalation'?['files:admin']:originalScopes,network:variant==='refresh-network-failure'?'timeout':'delivered'},decision=mcpRefreshGrantDecision(input);
  if(refresh)a.transfer('refresh-request','Send refresh only to recorded issuer token endpoint','mcpC','mcpA',[refresh],{URL:mcpIssuer+'/token',grant_type:'refresh_token',resource:input.resource,scope:input.scopes.join(' ')});
  a.local('refresh-check','Validate refresh generation or record bounded client-side delivery uncertainty',input.network==='delivered'?'mcpA':'mcpC',{Input:input.refresh?{...input.refresh,credential:'redacted symbolic handle'}:null,Resource:input.resource,Scopes:input.scopes,Decision:decision},[mcpPut('refreshAccepted',decision.ok),mcpPut('refreshAttempts',1)],refresh?[refresh]:[]);
  if(!decision.ok){
    if(['invalid_grant','invalid_scope','invalid_target'].includes(decision.reason))a.tokenError('refresh-invalid',decision.reason);else a.stop('renewal-stop','mcpC',decision.reason);
    if(decision.reauthorize){a.local('reauthorize-required','Remove unusable current selection; retain history and unrelated grants','mcpC',{Action:'Start a fresh authorization-code transaction, not repeated refresh'},[mcpPut('reauthorizationRequired',true),mcpPut('currentToken',null)],[],refresh?[a.release(refresh,'mcpC')]:[],'dispose');}
    else if(refresh&&['invalid_scope','invalid_target'].includes(decision.reason))a.local('refresh-request-rejected','Retain valid refresh generation; retry the permitted request or seek new consent for broader permission','mcpC',{Action:'Original permitted-scope refresh remains available; broader scopes require new consent',Allowed:{resource:mcpResource,scopes:originalScopes},Reason:decision.reason},[mcpPut('refreshGeneration',1),mcpPut('refreshGeneration1Valid',true),mcpPut('permittedRefreshRetryAvailable',true),mcpPut('reauthorizationRequired',false)],[refresh]);
    return a.finish();
  }
  const replacement=mcpToken(a,'renewed-access-g2',{scopes:variant==='offline-access-not-permission'?['offline_access']:['files:read']}),nextRefresh=a.artifact('refresh-g2','Rotating refresh generation 2','mcpA','HANDLE(refresh g2)',{type:'refresh-token',readers:['mcpC','mcpA']});
  a.local('refresh-rotate','AS creates replacements and invalidates prior refresh generation','mcpA',{OldGenerationValid:false,NewGeneration:2},[mcpPut('refreshGeneration1Valid',false)],[replacement.artifactId,nextRefresh],[...a.create(replacement.artifactId),...a.create(nextRefresh)],'create');
  a.transfer('refresh-response','Acquire replacement generation before updating current store','mcpA','mcpC',[replacement.artifactId,nextRefresh],{Generation:2});
  a.local('refresh-install','Install newly acquired credentials; release old current selection only','mcpC',{NewAccess:replacement.instanceId},[mcpPut('currentToken',replacement.instanceId),mcpPut('refreshGeneration',2)],[replacement.artifactId,nextRefresh],refresh?[a.release(refresh,'mcpC')]:[],'store');
  if(variant.startsWith('revocation-')){
    a.transfer('revocation-request','Explicit advertised RFC7009 revocation request','mcpC','mcpA',[replacement.artifactId],{URL:mcpIssuer+'/revoke',Not:'Disconnect'});
    a.local('issuer-revoke','AS invalidates authority; offline R knowledge is separate','mcpA',{},[mcpPut('asRevoked',true),mcpPut('resourceKnowsRevocation',variant==='revocation-propagated')],[replacement.artifactId]);
    if(variant==='revocation-propagated'){a.transfer('revoked-request','Present cryptographically intact token after declared revocation propagation','mcpC','mcpR',[replacement.artifactId],{Request:mcpRequestEnvelope('tools/call',replacement.compact)});a.local('revocation-enforce','R applies its now-known issuer revocation record before accepting the request','mcpR',{TokenInstance:replacement.instanceId,Input:{revocationKnown:true}},[mcpPut('tokenAccepted',false),mcpPut('resourceAuthorized',false)],[replacement.artifactId]);a.resourceError('revoked-resource',401,'invalid_token',{error:'invalid_token'});return a.finish();}
  }
  mcpInvoke(a,replacement);return a.finish();
}
function mcpBuild08(variant){
  const a=mcpAuthor(8,'OAuth permission, tool approval and resource policy',variant),token=mcpToken(a,'existing-access-g1',{initial:true,holders:['mcpC']});
  mcpListTools(a,token);mcpInvoke(a,token,{variant,acl:variant!=='acl-denied'});return a.finish();
}
function mcpBuild09(variant){
  const a=mcpAuthor(9,'MCP proxy: a separate OAuth grant for the upstream API',variant,['mcpC','mcpB','mcpR','mcpA','mcpS','mcpU']),incoming=mcpToken(a,'downstream-access-g1',{initial:true,holders:['mcpC'],readers:['mcpC','mcpR','mcpA']});
  const upstreamRegistration=a.artifact('upstream-registration','Proxy registration bound to UAS','mcpR',JSON.stringify({issuer:mcpUpIssuer,client_id:'proxy-client',redirect_uri:'https://proxy.lab.example/oauth/callback',token_endpoint_auth_method:'none'}),{initial:true,type:'client-registration',readers:['mcpR','mcpS']});
  a.transfer('downstream-request','Chapter 1: C authorizes one self-contained MCP POST to proxy P','mcpC','mcpR',[incoming.artifactId],{Request:mcpRequestEnvelope('tools/call',incoming.compact),Resource:mcpResource,Issuer:mcpIssuer});
  const accepted=mcpValidateToken(a,incoming,{key:'downstream-token'});a.local('downstream-validate','Keep accepted downstream context separate from upstream grant','mcpR',{Accepted:accepted},[mcpPut('downstreamTokenAccepted',accepted)],[incoming.artifactId]);
  const comparison=a.artifact('two-grant-comparison','Persistent issuer/resource/client comparison','mcpR',JSON.stringify({downstream:{token:incoming.instanceId,issuer:mcpIssuer,resource:mcpResource,client:'desktop-client'},upstream:{issuer:mcpUpIssuer,resource:mcpUpstream,client:'proxy-client'}}),{type:'grant-comparison',readers:a.actorIds});a.local('compare-grants','Chapter boundary: compare independent grants, never substitute scopes for audience','mcpR',{},[],[comparison],a.create(comparison),'create');
  const upstreamConsent=variant!=='upstream-consent-denied',grantMatches=variant!=='other-client-grant';
  const tx=a.artifact('upstream-transaction','User/client/operation-bound upstream OAuth transaction','mcpR',JSON.stringify({user:'user-7',client:variant==='other-client-grant'?'different-client':'desktop-client',operation:'read_file',issuer:mcpUpIssuer,state:'SYM(upstream state)'}),{type:'oauth-transaction',readers:['mcpR']});
  a.local('upstream-consent','Proxy checks exact initiating client and explicit upstream consent','mcpR',{Consent:upstreamConsent,GrantClientMatches:grantMatches},[mcpPut('upstreamConsent',upstreamConsent&&grantMatches)],[tx],a.create(tx),'create');
  const outgoingChoice=variant==='missing-upstream-token'?incoming.instanceId:null;a.local('upstream-credential-choice','Incoming MCP token is not an upstream credential candidate','mcpR',{Incoming:incoming.instanceId,SelectedOutgoing:outgoingChoice||'independent grant required',Allowed:outgoingChoice===null},[mcpPut('outgoingCredentialAccepted',outgoingChoice===null)],[incoming.artifactId]);
  if(!upstreamConsent||!grantMatches||outgoingChoice!==null){a.reply('upstream-stop',403,!grantMatches?'Different client grant cannot be reused':!upstreamConsent?'Upstream consent denied':'Downstream token cannot fill upstream credential slot');return mcpProxyFinish(a);}
  const verifier=a.artifact('upstream-verifier','Proxy-local upstream PKCE verifier','mcpR',mcpVerifier,{type:'pkce-verifier',readers:['mcpR','mcpS']}),challenge=a.artifact('upstream-challenge','Upstream S256 challenge','mcpR',mcpChallenge,{type:'pkce-challenge',readers:['mcpR','mcpB','mcpS']});a.local('upstream-prepare','Chapter 2: proxy is a separately registered public OAuth client','mcpR',{ClientId:'proxy-client',Issuer:mcpUpIssuer},[],[verifier,challenge,{artifactId:upstreamRegistration,kind:'use'}],[...a.create(verifier),...a.create(challenge)],'create');
  a.transfer('upstream-authorize','Browser authorizes separate upstream resource','mcpR','mcpB',[challenge],{client_id:'proxy-client',redirect_uri:'https://proxy.lab.example/oauth/callback',resource:mcpUpstream,state:'SYM(upstream state)',code_challenge_method:'S256',code_challenge:mcpChallenge});
  a.transfer('upstream-browser','Browser reaches UAS, not downstream issuer A','mcpB','mcpS',[challenge],{resource:mcpUpstream,Consent:true});
  const upstreamConsentRecord=a.artifact('upstream-as-consent','UAS user/proxy-client/resource consent','mcpS',JSON.stringify({user:'user-7',client:'proxy-client',resource:mcpUpstream,scopes:['files:read']}),{type:'consent',readers:['mcpS']});a.local('upstream-as-consent','UAS performs its chosen user authentication and consent decision','mcpS',{User:'user-7',Client:'proxy-client',Resource:mcpUpstream,Consent:true},[mcpPut('asConsent',true)],[upstreamConsentRecord],a.create(upstreamConsentRecord),'create');
  const cookie=a.artifact('upstream-browser-cookie','UAS browser session cookie, never a proxy credential','mcpS','HANDLE(UAS browser cookie)',{type:'browser-cookie',readers:['mcpS','mcpB']});a.local('upstream-cookie-create','UAS creates its own browser session artifact','mcpS',{},[],[cookie],a.create(cookie),'create');a.transfer('upstream-browser-cookie','Only browser acquires the UAS cookie','mcpS','mcpB',[cookie],{Cookie:'Issuer-bound browser cookie; no P/C possession'});
  const code=a.artifact('upstream-code','Upstream authorization code','mcpS','SYM(upstream code)',{type:'authorization-code',readers:['mcpS','mcpR','mcpB']});a.local('upstream-code-create','UAS issues bound single-use code','mcpS',{},[],[code],a.create(code),'create');a.transfer('upstream-redirect','Browser receives UAS authorization response','mcpS','mcpB',[code],{iss:mcpUpIssuer,state:'SYM(upstream state)'});a.transfer('upstream-callback','Browser delivers proxy HTTPS callback','mcpB','mcpR',[code],{iss:mcpUpIssuer,state:'SYM(upstream state)',redirect:'https://proxy.lab.example/oauth/callback'});
  a.local('upstream-callback-check','Proxy validates upstream state, issuer and registered redirect before redemption','mcpR',{IssuerMatches:true,StateMatches:true,RedirectMatches:true},[],[tx,code,{artifactId:upstreamRegistration,kind:'use'}]);
  a.transfer('upstream-redeem','Proxy redeems its own code and verifier at UAS','mcpR','mcpS',[code,verifier],{client_id:'proxy-client',resource:mcpUpstream,grant_type:'authorization_code'});
  a.local('upstream-grant-check','UAS validates its code/client/resource and pinned S256 binding before issuing a token','mcpS',{ClientId:'proxy-client',Resource:mcpUpstream,ChallengeExpected:mcpChallenge,VerifierMatches:mcpVerifier==='dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'},[mcpPut('upstreamGrantAccepted',true)],[code,verifier]);
  const token=mcpToken(a,'upstream-access-g1',{issuer:mcpUpIssuer,trustedIssuer:mcpUpIssuer,audience:variant==='upstream-wrong-audience'?mcpResource:mcpUpstream,expired:variant==='upstream-expired',owner:'mcpS',clientId:'proxy-client',readers:['mcpR','mcpS','mcpU']});
  a.local('upstream-issue','UAS issues a different token for U','mcpS',{},[],[token.artifactId],a.create(token.artifactId),'create');a.transfer('upstream-token-receipt','Proxy stores upstream credential privately','mcpS','mcpR',[token.artifactId],{Resource:token.claims.aud});
  a.transfer('upstream-api','Use only upstream token at U','mcpR','mcpU',[token.artifactId],{Resource:mcpUpstream},[mcpPut('upstreamRequests',1)]);
  if(!mcpValidateToken(a,token,{actor:'mcpU',key:'upstream-validation',issuer:mcpUpIssuer,audience:mcpUpstream})){
    a.resourceError('upstream-reject',401,'invalid_token',{from:'mcpU',to:'mcpR',error:'invalid_token'});
    a.local('proxy-upstream-mapping','Map upstream authorization failure to an MCP tool execution error, not a downstream Bearer challenge','mcpR',{HTTP:200,Action:'Proxy renews its proxy-client grant at https://upstream-login.lab.example for https://api.lab.example/files; C retains its valid proxy token'},[mcpPut('upstreamRenewalRequired',true)]);
    a.transfer('proxy-upstream-error','Proxy returns bounded tool execution failure without credentials','mcpR','mcpC',[],{HTTP:200,Headers:{},Body:{jsonrpc:'2.0',id:7,result:{resultType:'complete',isError:true,content:[{type:'text',text:'Upstream authorization failed. The proxy must renew its upstream API grant; your MCP proxy token remains accepted.'}]}}},[mcpPut('responseStatus',200),mcpPut('clientKnowledge','upstream grant renewal required; downstream token accepted')]);return mcpProxyFinish(a);
  }
  const allowed=variant!=='upstream-acl-denied';a.local('upstream-policy','U independently evaluates target ACL','mcpU',{ACL:allowed},[mcpPut('upstreamAuthorized',allowed)]);if(!allowed){a.reply('upstream-denied',403,'Upstream object ACL denied','mcpU','mcpR');a.transfer('proxy-policy-error','Proxy returns policy denial without upstream token','mcpR','mcpC',[],{HTTP:403},[mcpPut('responseStatus',403),mcpPut('clientKnowledge','upstream policy denied')]);return mcpProxyFinish(a);}
  const result=a.artifact('upstream-result','Upstream protected result','mcpU','SYM(upstream permitted bytes)',{type:'result',readers:['mcpU','mcpR']});a.local('upstream-execute','U performs authorized operation','mcpU',{},[],[result],a.create(result),'create');a.transfer('upstream-result-wire','Proxy receives unaccepted U result','mcpU','mcpR',[result],{Result:'no credentials'});a.local('upstream-result-accept','Proxy interprets correlated permitted U result','mcpR',{},[mcpPut('upstreamResultAccepted',true)],[result]);a.local('proxy-policy','Proxy filters permitted MCP output','mcpR',{},[mcpPut('resourceAuthorized',true)]);mcpFinishResult(a,'proxy');return mcpProxyFinish(a);
}
function mcpProxyFinish(a){
  const boundary=a.steps.findIndex(step=>step.id===a.id+':upstream-consent'),cut=boundary<0?a.steps.length:boundary;
  a.initialState.mcp.upstreamTokenAccepted=null;
  const model=a.finish({chapters:[{id:'downstream',label:'1. Client to protected MCP proxy',actorIds:['mcpC','mcpB','mcpR','mcpA'],stepIds:a.steps.slice(0,cut).map(step=>step.id)},{id:'upstream',label:'2. Proxy to independent upstream service',actorIds:['mcpB','mcpC','mcpR','mcpS','mcpU'],stepIds:a.steps.slice(cut).map(step=>step.id)}],chapterComparison:[{label:'Downstream MCP access token',artifactId:a.id+':downstream-access-g1',issuer:mcpIssuer,resource:mcpResource},{label:'Separate upstream API token',artifactId:a.id+':upstream-access-g1',issuer:mcpUpIssuer,resource:mcpUpstream}]});model.profile={...model.profile,upstreamClientType:'Separately registered public proxy-client with S256; no packaged secret',upstreamIssuer:mcpUpIssuer,upstreamResource:mcpUpstream};model.decisionBindings=model.decisionBindings.filter(binding=>binding.path!=='mcp.tokenAccepted');model.decisionBindings.splice(1,0,{label:'Downstream C->P token accepted',path:'mcp.downstreamTokenAccepted'},{label:'Upstream P->U token accepted',path:'mcp.upstreamTokenAccepted'});return model;
}
function mcpBuild10(variant){
  const a=mcpAuthor(10,'Proxy consent cannot be inherited by a different MCP client',variant,['mcpC','mcpB','mcpR','mcpS']);
  const prior=a.artifact('c1-consent','Existing C1-specific proxy consent','mcpR',JSON.stringify({user:'user-7',client:'C1',approved:true}),{initial:true,type:'consent',readers:['mcpR']}),cookie=a.artifact('upstream-cookie','Existing upstream browser sign-in/consent cookie','mcpS','HANDLE(UAS cookie)',{initial:true,holders:['mcpB','mcpS'],type:'browser-cookie',readers:['mcpB','mcpS']});
  const expected={user:'user-7',client:'C2',redirect:'https://c2.lab.example/callback',scopes:['files:read'],csrf:'SYM(C2 consent CSRF)'},record=variant==='explicit-c2-approval'?{...expected,approved:true,integrity:true}:variant==='global-consent'?{user:'user-7',approved:true}:variant==='redirect-mismatch'?{...expected,approved:true,integrity:true,redirect:'https://different.lab.example/callback'}:variant==='csrf-mismatch'?{...expected,approved:true,integrity:true,csrf:'SYM(other CSRF)'}:variant==='tampered-consent'?{...expected,approved:true,integrity:false}:{...expected,client:'C1',approved:true,integrity:true};
  const requestValue={client_id:'C2',redirect_uri:expected.redirect,resource:mcpResource,scope:expected.scopes.join(' '),state:expected.csrf,untrustedConsentHint:variant==='c1-cookie-replay'?'reuse C1 upstream browser session':'none'},request=a.artifact('c2-request','C2-bound proxy authorization request','mcpC',JSON.stringify(requestValue),{type:'oauth-transaction',readers:['mcpC','mcpR']});a.local('request-c2','New C2 requests access; similar display name is not identity','mcpC',{Client:'C2',DisplayName:variant==='lookalike-name'?'C1 trusted client':'New client',Redirect:expected.redirect,Input:requestValue},[],[request],a.create(request),'create');a.transfer('c2-request','Proxy receives exact C2 authorization context before consent checking','mcpC','mcpR',[request],requestValue);
  const decision=mcpProxyConsentDecision({...expected,record});a.local('consent-check','Check per-user/per-client consent before contacting UAS','mcpR',{Record:record,Decision:decision},[mcpPut('proxyConsentAccepted',decision.ok)],[prior]);
  if(!decision.ok){a.transfer('consent-denial','Explain exact C2 approval required without upstream authorization','mcpR','mcpC',[],{Reason:decision.reason},[mcpPut('clientKnowledge','C2 approval required')]);return a.finish();}
  const consent=a.artifact('c2-consent','Explicit integrity-protected C2 consent record','mcpR',JSON.stringify(record),{type:'consent',readers:['mcpR']});a.local('consent-create','Create C2 consent independently of upstream cookie','mcpR',{},[],[consent],a.create(consent),'create');a.transfer('approved-upstream','Start only approved C2-bound upstream browser transaction','mcpR','mcpB',[],{Client:'proxy-client',BoundDownstream:'C2',State:expected.csrf});a.transfer('approved-browser','Only browser sends its issuer-bound upstream cookie to UAS','mcpB','mcpS',[cookie],{Client:'proxy-client',State:expected.csrf},[mcpPut('upstreamRequests',1)]);
  a.transfer('approved-callback','Accept upstream callback bound to approved C2','mcpS','mcpR',[],{State:expected.csrf,Issuer:mcpUpIssuer});const code=a.artifact('c2-code','C2-bound downstream authorization code','mcpR','SYM(C2 code)',{type:'authorization-code',readers:['mcpR','mcpC']});a.local('release-c2-code','Release downstream code only after exact consent/callback binding','mcpR',{},[mcpPut('downstreamCodes',1)],[code],a.create(code),'create');a.transfer('c2-code-delivery','Client learns only its newly bound code','mcpR','mcpC',[code],{Client:'C2'},[mcpPut('clientKnowledge','C2 code received; no tool invoked')]);return a.finish();
}
function mcpBuild11(variant){
  const a=mcpAuthor(11,'Reject token passthrough across the proxy boundary',variant,['mcpC','mcpR','mcpS','mcpU']),corrected=['corrected-two-grants','forward-p-token'].includes(variant),opaque=['opaque-wrong-audience','unrecognized-token'].includes(variant);
  a.artifact('shared-as-registration','Client registration at the declared shared issuer','mcpC',JSON.stringify({issuer:mcpUpIssuer,client_id:'desktop-client',redirect:mcpRedirect}),{initial:true,type:'client-registration',readers:['mcpC','mcpS']});
  const incoming=mcpToken(a,'incoming-token-g1',{initial:true,holders:['mcpC'],owner:'mcpS',audience:corrected?mcpResource:mcpUpstream,issuer:variant==='unrelated-issuer'?'https://unrelated.lab.example':mcpUpIssuer,trustedIssuer:mcpUpIssuer,opaque});a.transfer('incoming-wire','Present incoming token in a self-contained MCP POST to proxy','mcpC','mcpR',[incoming.artifactId],{Request:mcpRequestEnvelope('tools/call',incoming.compact),Resource:mcpResource,Scopes:'files:read'});
  if(!mcpValidateToken(a,incoming,{key:'incoming-token',issuer:mcpUpIssuer,asActor:'mcpS',opaque,timeout:variant==='unrecognized-token'})){a.resourceError('incoming-rejected',401,'invalid_token',{error:'invalid_token'});return mcpPassthroughFinish(a);}
  if(variant==='forward-p-token'){a.local('outgoing-gate','Reject unchanged incoming token as upstream credential','mcpR',{Incoming:incoming.instanceId,SelectedOutgoing:incoming.instanceId,Allowed:false},[mcpPut('outgoingCredentialAccepted',false)],[incoming.artifactId]);a.reply('passthrough-stop',403,'Incoming P token cannot be forwarded unchanged to U');return mcpPassthroughFinish(a);}
  const upstream=mcpToken(a,'separate-upstream-g1',{issuer:mcpUpIssuer,trustedIssuer:mcpUpIssuer,audience:mcpUpstream,initial:true,holders:['mcpR'],owner:'mcpS',clientId:'proxy-client',readers:['mcpR','mcpS','mcpU']});a.local('outgoing-gate','Select separately issued U token with different exact identity','mcpR',{Incoming:incoming.instanceId,Outgoing:upstream.instanceId,Allowed:upstream.instanceId!==incoming.instanceId},[mcpPut('outgoingCredentialAccepted',true)],[upstream.artifactId]);a.transfer('upstream-request','Send only independently issued U credential','mcpR','mcpU',[upstream.artifactId],{Resource:mcpUpstream},[mcpPut('upstreamRequests',1)]);
  if(mcpValidateToken(a,upstream,{actor:'mcpU',key:'upstream-token',issuer:mcpUpIssuer,audience:mcpUpstream})){
    a.local('upstream-policy','U permits the separately granted read operation under its local policy','mcpU',{Required:'files:read',Granted:['files:read'],ACL:true},[mcpPut('upstreamAuthorized',true)],[upstream.artifactId]);
    const result=a.artifact('upstream-result','U operation result for the separate upstream request','mcpU','SYM(permitted upstream bytes)',{type:'result',readers:['mcpU','mcpR']});
    a.local('upstream-execute','U executes the authorized synthetic operation','mcpU',{},[],[result],a.create(result),'create');
    a.transfer('upstream-result-wire','Proxy receives protected upstream output, not another credential','mcpU','mcpR',[result],{RequestId:7,Result:'SYM(permitted upstream bytes)'});
    a.local('upstream-result-accept','Proxy accepts the correlated upstream result before constructing client output','mcpR',{RequestId:7},[mcpPut('upstreamResultAccepted',true)],[result]);
    a.local('proxy-authorize','Keep both accepted validation contexts separate','mcpR',{},[mcpPut('resourceAuthorized',true)]);
    mcpFinishResult(a,'corrected-proxy');
  }
  return mcpPassthroughFinish(a);
}
function mcpPassthroughFinish(a){const model=a.finish();model.profile={...model.profile,authorizationIssuer:mcpUpIssuer,registration:'Existing issuer-bound public-client registration',grantAssumptions:'Shared AS for P and U deliberately isolates audience checks; C and proxy-client still require independent resource/client grants.'};model.relatedLessons=[{id:'lab-mcp09',title:'Two grants with separate issuers',summary:'MCP09 declares a separate upstream AS; no token transfers between lessons.'},{id:'lab-jwt08',title:'Token purpose and recipient',summary:'Same scope text is not a resource grant.'}];return model;}
function mcpBuild12(variant){
  const a=mcpAuthor(12,'Untrusted discovery URLs and metadata do not trigger unsafe fetches',variant,['mcpC','mcpR','mcpA']);
  const url=variant==='javascript-url'?'javascript:alert(1)':variant==='data-url'?'data:text/plain,fixture':variant==='file-url'?'file:///synthetic':variant==='poisoned-token-endpoint'?'https://token.lab.example/private':variant==='loopback-redirect'?'https://127.0.0.1/private':variant==='link-local-redirect'?'https://169.254.169.254/metadata':'https://metadata.lab.example/document',addresses=variant==='loopback-redirect'?['127.0.0.1']:variant==='link-local-redirect'?['169.254.169.254']:variant==='dns-rebinding'?['10.0.0.7']:variant==='poisoned-token-endpoint'?['192.168.1.7']:['203.0.113.20'];
  const input=a.artifact('untrusted-url','Untrusted metadata/authorization destination','mcpC',url,{initial:true,type:'untrusted-url',readers:['mcpC']});a.local('url-input','Receive URL as data, never launch it','mcpC',{URL:url,Input:variant==='poisoned-token-endpoint'?{token_endpoint:url}:'Untrusted metadata or navigation URL'},[],[input]);
  if(['loopback-redirect','link-local-redirect','dns-rebinding','redirect-cycle'].includes(variant))a.local('redirect-input','Validate every redirected destination and changed DNS answer','mcpC',{PreviousURL:'https://metadata.lab.example/first',NextURL:url,Addresses:addresses,Input:{previousDNS:['203.0.113.20'],nextDNS:addresses},Not:'No credential-bearing request has been sent'},[],[input]);
  const preliminary=mcpDestinationDecision({url,addresses,seen:variant==='redirect-cycle'?[url]:[],tlsTrusted:true});
  a.local('egress-check','Apply declared public-egress URL and resolved-address policy before send','mcpC',{URL:url,Addresses:addresses,Decision:preliminary,Policy:'Private enterprise destinations require explicit operator allowlist, not a universal MCP prohibition'},[mcpPut('destinationAllowed',preliminary.ok)],[input]);
  if(!preliminary.ok){a.stop('egress-stop','mcpC',preliminary.reason);return a.finish();}
  const transport=mcpDestinationDecision({url,addresses,tlsTrusted:variant!=='invalid-tls',bytes:variant==='oversized-metadata'?65537:1024});
  if(!transport.ok){a.local('response-bounds','Reject TLS identity/response size before using metadata or sending credentials','mcpC',{Decision:transport},[mcpPut('metadataAccepted',false)],[input]);a.stop('response-stop','mcpC',transport.reason);return a.finish();}
  const document={resource:variant==='wrong-resource'?'https://different.lab.example/api':mcpResource,issuer:variant==='issuer-path-switch'?'https://login.lab.example/tenant-b':mcpIssuer,client_id:variant==='cimd-mismatch'?'https://client.lab.example/wrong':'https://client.lab.example/metadata.json'};
  const doc=a.artifact('untrusted-document','Received bounded metadata JSON','mcpR',JSON.stringify(document),{type:'metadata',representation:'readable-untrusted',readers:['mcpR','mcpC']});a.local('metadata-create','Synthetic source creates response fixture','mcpR',{},[],[doc],a.create(doc),'create');a.transfer('metadata-response','Receive safe-destination JSON without trusting its identities','mcpR','mcpC',[doc],{Document:document});
  const accepted=mcpCanonicalResource(document.resource)===mcpResource&&document.issuer===mcpIssuer&&document.client_id==='https://client.lab.example/metadata.json';a.local('metadata-check','Validate resource, exact issuer and CIMD identity independently','mcpC',{Document:document,Accepted:accepted},[mcpPut('metadataAccepted',accepted)],[doc]);if(!accepted)a.stop('metadata-stop','mcpC','Metadata identity or issuer credential binding rejected');else a.local('safe-config-only','Accepted configuration grants no OAuth or tool authority','mcpC',{},[mcpPut('clientKnowledge','configuration only; no credentials sent')],[doc]);return a.finish();
}
function mcpStdioTransfer(a,key,title,from,to,object,values={},transport='Local process pipes'){
  const refs=Array.isArray(object)?object:[object],step=a.local(key,title,from,values,[],refs,[],'send');step.to=to;step.channel='internal';step.eventType='message';step.protocolLabel=transport;step.layers=[{protocol:transport==='Local process pipes'?'MCP newline-delimited JSON-RPC':transport==='Approved loopback HTTP callback'?'OAuth callback':'Declared local IPC',transport,from,to,protection:transport==='Approved loopback HTTP callback'?'Explicit approved loopback callback exception; no TLS confidentiality asserted':'OS process/pipe/provider permissions; no TLS or HTTP OAuth authority implied'}];
  const carried=[];for(const artifactId of refs){const source=a.objects.get(artifactId);step.attributeOperations.push({attributeId:source.attributeId,instanceId:artifactId,creator:source.creator,kind:'receive',actorId:to,holders:[to],inspectors:[from,to],fieldPath:source.label,representation:source.representation,value:source.value,sourceEventId:step.id,exactValueRef:artifactId+':'+source.representation+':'+source.label});a.inventory.events[step.id].effects.push(a.acquire(artifactId,to));carried.push({artifactId,representationId:source.representation});}
  a.inventory.events[step.id].messages.push({from,to,objects:carried,start:0,end:1});return step;
}
function mcpBuild13(variant){
  const a=mcpAuthor(13,'Local stdio: process credentials and OS authority',variant,['mcpC','mcpR','mcpO','mcpU']);Object.assign(a.initialState.mcp,{httpOAuthStarted:false,localIdentity:null,credentialAvailable:null,osAuthorized:null,processTerminated:false});
  const launch=a.artifact('launch-request','Host request for restricted subprocess launch','mcpC',JSON.stringify({identity:'synthetic-1001',environment:'per-server allowlist'}),{type:'request',readers:['mcpC','mcpO']});a.local('launch-create','Host selects declared restricted launcher profile','mcpC',{},[],[launch],a.create(launch),'create');mcpStdioTransfer(a,'launch-ipc','Host invokes local OS launcher','mcpC','mcpO',launch,{},'Declared OS launcher IPC');
  const identity=a.artifact('process-identity','Restricted local subprocess identity','mcpO',JSON.stringify({uid:'synthetic-1001',groups:['mcp-restricted'],environment:'per-server allowlist'}),{initial:true,type:'process-identity',readers:['mcpO','mcpC','mcpR']});a.local('process-launch','OS applies selected identity and restricted environment','mcpO',{Identity:'synthetic-1001',Containment:'Explicit OS policy, not MCP roots'},[mcpPut('localIdentity','synthetic-1001')],[identity],[a.acquire(identity,'mcpR')]);
  const available=variant!=='missing-secret';a.local('provider-check','Secret provider supplies only declared per-server credential','mcpO',{Available:available},[mcpPut('credentialAvailable',available)],[identity]);if(!available){mcpStdioDenial(a,'provider-error','Missing configured credential',{from:'mcpO',transport:'Declared OS launcher IPC'});mcpStdioCleanup(a);return mcpStdioFinish(a);}
  const overbroad=variant==='global-inheritance';a.local('launcher-policy','Reject broad global inherited credentials in restricted launcher profile','mcpO',{CredentialAuthority:overbroad?'global overbroad':'per-server',Allowed:!overbroad},[mcpPut('launcherAccepted',!overbroad)],[identity]);if(overbroad){mcpStdioDenial(a,'launcher-error','Overbroad global inheritance rejected',{from:'mcpO',transport:'Declared OS launcher IPC'});mcpStdioCleanup(a);return mcpStdioFinish(a);}
  if(variant==='http-proxy-unprotected'){a.stop('proxy-boundary-stop','mcpC','Remote HTTP proxy requires its own declared authorization boundary');mcpStdioCleanup(a);return mcpStdioFinish(a);}
  const credential=a.artifact('server-credential','Per-server provider credential','mcpO','HANDLE(per-server credential)',{type:'secret',readers:['mcpO','mcpR']});a.local('provider-create','Provider selects credential without logging its value','mcpO',{},[],[credential],a.create(credential),'create');mcpStdioTransfer(a,'provider-delivery','Local provider supplies credential outside MCP tool arguments and stdout','mcpO','mcpR',credential,{Provider:'Declared local secret-provider IPC'},'Declared secret-provider IPC');
  const request=a.artifact('stdio-request','Newline-delimited stdio request','mcpC',JSON.stringify(mcpRequestEnvelope().body)+'\n',{type:'request',readers:['mcpC','mcpR']});a.local('stdio-create','Create one versioned JSON-RPC line, no HTTP headers','mcpC',{},[],[request],a.create(request),'create');mcpStdioTransfer(a,'stdio-call','Host writes tools/call to subprocess stdin','mcpC','mcpR',request,{Method:'tools/call',NoHTTP401:true});
  const osAllowed=!['os-denied','roots-not-sandbox'].includes(variant);a.local('os-policy','OS evaluates local file authority independently of roots and host approval','mcpO',{Identity:'synthetic-1001',Allowed:osAllowed,RootsAreSandbox:false},[mcpPut('osAuthorized',osAllowed)],[identity]);
  if(variant==='missing-upstream-scope'){
    const upstream=a.artifact('upstream-credential','Separately provisioned upstream API credential','mcpU','HANDLE(upstream API credential)',{initial:true,holders:['mcpR'],type:'access-token',representation:'opaque',readers:['mcpR','mcpU']});
    a.transfer('upstream-request','Subprocess presents only its separately configured upstream credential','mcpR','mcpU',[upstream],{Resource:mcpUpstream},[mcpPut('upstreamRequests',1)]);
    a.local('upstream-scope','Upstream checks its authoritative credential record, which lacks read scope','mcpU',{Required:'files:read',Granted:[]},[mcpPut('upstreamAuthorized',false)],[upstream]);
    a.reply('upstream-denied',403,'Upstream scope denied','mcpU','mcpR');mcpStdioDenial(a,'stdio-denial','Upstream permission denied',{status:403});mcpStdioCleanup(a,credential,[upstream]);return mcpStdioFinish(a);
  }
  if(!osAllowed){mcpStdioDenial(a,'os-denial','Local OS access denied');mcpStdioCleanup(a,credential);return mcpStdioFinish(a);}
  const result=a.artifact('stdio-result','Local subprocess operation result','mcpR',JSON.stringify({jsonrpc:'2.0',id:7,result:{resultType:'complete',content:[{type:'text',text:'SYM(permitted local bytes)'}]}})+'\n',{type:'result',readers:['mcpR','mcpC']});a.local('local-execute','Perform modeled operation under OS authority','mcpR',{},[mcpPut('resourceAuthorized',true),mcpPut('operationExecuted',true)],[result],a.create(result),'create');mcpStdioTransfer(a,'stdio-result','Subprocess writes correlated result to stdout','mcpR','mcpC',result);a.local('stdio-accept','Host accepts result, not a new OS or OAuth grant','mcpC',{},[mcpPut('resultLearned',true),mcpPut('clientKnowledge','accepted local result')],[result]);mcpStdioCleanup(a,credential);return mcpStdioFinish(a);
}
function mcpStdioDenial(a,key,reason,{from='mcpR',status,transport='Local process pipes'}={}){
  const value=JSON.stringify({jsonrpc:'2.0',id:7,error:{code:-32000,message:reason,...status?{data:{upstreamHttpStatus:status}}:{}}})+'\n',response=a.artifact(key+'-response','Local denial response without protected output',from,value,{type:'protocol-object',readers:[from,'mcpC']});a.local(key+'-create','Create bounded local failure response',from,{},[],[response],a.create(response),'create');mcpStdioTransfer(a,key+'-delivery','Host receives local failure over declared IPC',from,'mcpC',response,{},transport);a.local(key+'-accept','Host learns denied outcome only after local response delivery','mcpC',{},[mcpPut('clientKnowledge',reason),...status?[mcpPut('responseStatus',status)]:[]],[response]);
}
function mcpStdioCleanup(a,credential,extra=[]){const refs=[a.id+':process-identity',...credential?[credential]:[],...extra];a.local('process-cleanup','On termination release subprocess copies, not upstream validity','mcpR',{UpstreamRevoked:false},[mcpPut('processTerminated',true)],refs.map(artifactId=>({artifactId,kind:'dispose'})),refs.map(artifactId=>a.release(artifactId,'mcpR')),'dispose');}
function mcpStdioFinish(a){
  const model=a.finish();model.profile={...model.profile,clientType:'Local host/subprocess',registration:'Not HTTP OAuth registration',authorizationIssuer:'No HTTP MCP OAuth issuer',resourceUri:'Local process pipes and selected OS resource',tokenFormat:'Declared provider handle; no inferred ID token',grantAssumptions:'OS identity and local deployment policy',algorithms:['No MCP HTTP OAuth exchange; selected OS/provider policy'],cryptoDetail:'Synthetic process identities and provider handles; no production cryptography or native OS containment evidence.',startingSummary:['Host launches a restricted synthetic subprocess.','Credential provider supplies only that server credential.','MCP roots/approval do not create OS containment.']};
  model.prerequisites=['Declared restricted OS launcher/account and local resource policy','Per-server credential-provider contract; optional separate upstream API credential','No actual subprocess, OS secret, browser grant or network execution'];
  model.decisionBindings=[{label:'HTTP MCP OAuth started',path:'mcp.httpOAuthStarted'},{label:'Local process identity',path:'mcp.localIdentity'},{label:'Provider credential available',path:'mcp.credentialAvailable'},{label:'OS resource policy',path:'mcp.osAuthorized'},{label:'Operation executed',path:'mcp.operationExecuted'},{label:'Host learned result',path:'mcp.resultLearned'},{label:'Subprocess terminated',path:'mcp.processTerminated'}];
  model.relatedLessons=[{id:'lab-llog01',title:'Linux local identity and PAM',summary:'Separate workstation lesson, no credentials transferred.'}];return model;
}
const mcpVariantCatalog=mcpFreeze({"lab-mcp01":[{"id":"default","label":"Declared default profile","description":"Independently authored MCP01 default profile"},{"id":"consent-cancel","label":"consent-cancel","description":"consent=false"},{"id":"later-missing-token","label":"later-missing-token","description":"later Authorization absent"},{"id":"pkce-absent","label":"pkce-absent","description":"code_challenge_methods_supported absent"}],"lab-mcp02":[{"id":"default","label":"Declared default profile","description":"Independently authored MCP02 default profile"},{"id":"fallback-order","label":"fallback-order","description":"challenge pointer absent; first PRM endpoint404; first two AS endpoints404"},{"id":"multiple-challenges","label":"multiple-challenges","description":"Basic realm plus quoted Bearer pointer containing comma"},{"id":"resource-mismatch","label":"resource-mismatch","description":"PRM resource identifies other API"},{"id":"issuer-mismatch","label":"issuer-mismatch","description":"AS metadata issuer differs"},{"id":"discovery-exhausted","label":"discovery-exhausted","description":"all metadata endpoints404"},{"id":"missing-authorization-servers","label":"missing-authorization-servers","description":"PRM authorization_servers absent"},{"id":"issuer-switch","label":"issuer-switch","description":"selected issuer tenant-b; existing grant tenant-a"}],"lab-mcp03":[{"id":"default","label":"Declared default profile","description":"Independently authored MCP03 default profile"},{"id":"existing-registration","label":"existing-registration","description":"usable exact-issuer registration"},{"id":"cimd-id-mismatch","label":"cimd-id-mismatch","description":"document client_id differs from fetched URL"},{"id":"redirect-absent","label":"redirect-absent","description":"redirect_uris excludes callback"},{"id":"malformed-cimd","label":"malformed-cimd","description":"document is malformed JSON"},{"id":"cimd-unavailable","label":"cimd-unavailable","description":"document fetch404"},{"id":"disallowed-domain","label":"disallowed-domain","description":"CIMD URL outside declared allowlist"},{"id":"packaged-secret","label":"packaged-secret","description":"public client relies on distributed secret"},{"id":"dcr-compatibility","label":"dcr-compatibility","description":"CIMD unadvertised; DCR explicitly chosen; native application_type"},{"id":"dcr-web-redirect","label":"dcr-web-redirect","description":"web application_type with native loopback redirect"},{"id":"dcr-failure","label":"dcr-failure","description":"advertised registration endpoint rejects"},{"id":"no-registration","label":"no-registration","description":"no existing or advertised CIMD/DCR mechanism"}],"lab-mcp04":[{"id":"default","label":"Declared default profile","description":"Independently authored MCP04 default profile"},{"id":"wrong-state","label":"wrong-state","description":"callback state changed"},{"id":"wrong-issuer","label":"wrong-issuer","description":"callback iss tenant-b"},{"id":"advertised-iss-absent","label":"advertised-iss-absent","description":"advertisement true; iss absent"},{"id":"unadvertised-iss-match","label":"unadvertised-iss-match","description":"advertisement false; matching iss present"},{"id":"unadvertised-iss-wrong","label":"unadvertised-iss-wrong","description":"advertisement false; wrong iss present"},{"id":"unadvertised-iss-absent","label":"unadvertised-iss-absent","description":"advertisement false; iss absent"},{"id":"wrong-redirect","label":"wrong-redirect","description":"callback destination differs"},{"id":"error-issuer-mismatch","label":"error-issuer-mismatch","description":"wrong iss and attacker error text"},{"id":"wrong-verifier","label":"wrong-verifier","description":"token request verifier changed"},{"id":"reused-code","label":"reused-code","description":"authorization code already consumed"},{"id":"pkce-downgrade","label":"pkce-downgrade","description":"authorization method plain instead of S256"},{"id":"oauth20-redirect-compat","label":"oauth20-redirect-compat","description":"explicit compatibility adds token redirect_uri"}],"lab-mcp05":[{"id":"default","label":"Declared default profile","description":"Independently authored MCP05 default profile"},{"id":"opaque","label":"opaque","description":"opaque token; authenticated active introspection"},{"id":"id-token","label":"id-token","description":"typ JWT and wrong token purpose"},{"id":"other-api","label":"other-api","description":"aud other API"},{"id":"wrong-issuer","label":"wrong-issuer","description":"iss unrelated"},{"id":"bad-signature","label":"bad-signature","description":"bound signature evidence valid=false"},{"id":"expired","label":"expired","description":"exp before fixed now"},{"id":"inactive","label":"inactive","description":"opaque active=false"},{"id":"introspection-unavailable","label":"introspection-unavailable","description":"timeout=true"},{"id":"acl-denied","label":"acl-denied","description":"valid token; object ACL denies"}],"lab-mcp06":[{"id":"default","label":"Declared default profile","description":"Independently authored MCP06 default profile"},{"id":"challenge-outside-metadata","label":"challenge-outside-metadata","description":"write challenge not in PRM scopes_supported"},{"id":"missing-challenge-scope","label":"missing-challenge-scope","description":"initial scope absent; metadata files:read"},{"id":"consent-declined","label":"consent-declined","description":"step-up consent=false"},{"id":"smaller-grant","label":"smaller-grant","description":"AS grants only files:read"},{"id":"repeated-challenge","label":"repeated-challenge","description":"same403 repeated twice"},{"id":"hierarchy-not-permission","label":"hierarchy-not-permission","description":"files:* granted but exact policy requires files:write"},{"id":"upgrade-acl-denied","label":"upgrade-acl-denied","description":"write scope granted; ACL denies"}],"lab-mcp07":[{"id":"default","label":"Declared default profile","description":"Independently authored MCP07 default profile"},{"id":"no-refresh","label":"no-refresh","description":"refresh omitted by AS"},{"id":"rotated-reuse","label":"rotated-reuse","description":"refresh generation1 already invalidated"},{"id":"refresh-scope-escalation","label":"refresh-scope-escalation","description":"refresh asks files:admin"},{"id":"refresh-resource-escalation","label":"refresh-resource-escalation","description":"refresh asks other resource"},{"id":"refresh-rejected","label":"refresh-rejected","description":"refresh invalid_grant"},{"id":"refresh-network-failure","label":"refresh-network-failure","description":"refresh delivery times out"},{"id":"offline-access-not-permission","label":"offline-access-not-permission","description":"offline_access present; resource permission absent"},{"id":"revocation-lag","label":"revocation-lag","description":"A revoked self-contained token; R local snapshot not updated"},{"id":"revocation-propagated","label":"revocation-propagated","description":"A revocation known at R"}],"lab-mcp08":[{"id":"default","label":"Declared default profile","description":"Independently authored MCP08 default profile"},{"id":"host-denied","label":"host-denied","description":"host approval=false"},{"id":"acl-denied","label":"acl-denied","description":"host approved; ACL false"},{"id":"untrusted-annotations","label":"untrusted-annotations","description":"tool claims harmless; host still requires approval"},{"id":"arguments-changed","label":"arguments-changed","description":"target changed after approval"},{"id":"clientinfo-only","label":"clientinfo-only","description":"no bearer; clientInfo self-asserted"},{"id":"cached-tools","label":"cached-tools","description":"cached list from another grant; current token absent"}],"lab-mcp09":[{"id":"default","label":"Declared default profile","description":"Independently authored MCP09 default profile"},{"id":"upstream-consent-denied","label":"upstream-consent-denied","description":"upstream consent=false"},{"id":"upstream-expired","label":"upstream-expired","description":"upstream exp before now"},{"id":"upstream-wrong-audience","label":"upstream-wrong-audience","description":"upstream aud P"},{"id":"upstream-acl-denied","label":"upstream-acl-denied","description":"U ACL=false"},{"id":"missing-upstream-token","label":"missing-upstream-token","description":"attempt select downstream token for U"},{"id":"other-client-grant","label":"other-client-grant","description":"grant client differs from initiating client"}],"lab-mcp10":[{"id":"default","label":"Safe denial: C2 consent absent","description":"Independently authored MCP10 default profile"},{"id":"explicit-c2-approval","label":"explicit-c2-approval","description":"user explicitly approves C2 exact transaction"},{"id":"global-consent","label":"global-consent","description":"only global user-has-consented flag"},{"id":"c1-cookie-replay","label":"c1-cookie-replay","description":"C1 consent/cookie supplied for C2"},{"id":"redirect-mismatch","label":"redirect-mismatch","description":"consent redirect differs"},{"id":"csrf-mismatch","label":"csrf-mismatch","description":"consent CSRF differs"},{"id":"tampered-consent","label":"tampered-consent","description":"record integrity verdict false"},{"id":"lookalike-name","label":"lookalike-name","description":"C2 name resembles C1; IDs differ"}],"lab-mcp11":[{"id":"default","label":"Reject wrong-recipient upstream token","description":"Independently authored MCP11 default profile"},{"id":"opaque-wrong-audience","label":"opaque-wrong-audience","description":"introspection audience U"},{"id":"unrelated-issuer","label":"unrelated-issuer","description":"incoming issuer unrelated"},{"id":"forward-p-token","label":"forward-p-token","description":"valid P token selected unchanged for U"},{"id":"unrecognized-token","label":"unrecognized-token","description":"opaque response unavailable; no parser fallback"},{"id":"corrected-two-grants","label":"corrected-two-grants","description":"different valid P/U tokens and grants"}],"lab-mcp12":[{"id":"default","label":"Declared default profile","description":"Independently authored MCP12 default profile"},{"id":"javascript-url","label":"javascript-url","description":"scheme javascript"},{"id":"data-url","label":"data-url","description":"scheme data"},{"id":"file-url","label":"file-url","description":"scheme file"},{"id":"loopback-redirect","label":"loopback-redirect","description":"redirect resolves127.0.0.1"},{"id":"link-local-redirect","label":"link-local-redirect","description":"redirect resolves169.254.169.254"},{"id":"dns-rebinding","label":"dns-rebinding","description":"second DNS answer private"},{"id":"invalid-tls","label":"invalid-tls","description":"TLS identity verdict false"},{"id":"poisoned-token-endpoint","label":"poisoned-token-endpoint","description":"token endpoint private"},{"id":"wrong-resource","label":"wrong-resource","description":"metadata resource differs"},{"id":"cimd-mismatch","label":"cimd-mismatch","description":"client_id document mismatch"},{"id":"issuer-path-switch","label":"issuer-path-switch","description":"same host tenant-b; credential bound tenant-a"},{"id":"oversized-metadata","label":"oversized-metadata","description":"response exceeds65536 bytes"},{"id":"redirect-cycle","label":"redirect-cycle","description":"redirect chain repeats URL"}],"lab-mcp13":[{"id":"default","label":"Declared default profile","description":"Independently authored MCP13 default profile"},{"id":"missing-secret","label":"missing-secret","description":"provider returns no value"},{"id":"os-denied","label":"os-denied","description":"OS file policy=false"},{"id":"missing-upstream-scope","label":"missing-upstream-scope","description":"credential lacks required upstream scope"},{"id":"global-inheritance","label":"global-inheritance","description":"inherited credential authority exceeds per-server profile"},{"id":"http-proxy-unprotected","label":"http-proxy-unprotected","description":"remote proxy lacks declared authentication"},{"id":"roots-not-sandbox","label":"roots-not-sandbox","description":"roots restrict UI but OS policy denies"}]});
const mcpAbsentIssuerChoices=mcpFreeze([...mcpVariantCatalog['lab-mcp04'],{id:'absent-advertisement-iss-match',label:'Advertisement absent, matching iss present',description:'Missing advertisement does not disable exact issuer comparison.'},{id:'absent-advertisement-iss-wrong',label:'Advertisement absent, mismatching iss present',description:'Present iss still must match recorded issuer before redemption.'},{id:'absent-advertisement-iss-absent',label:'Advertisement and iss both absent',description:'Issuer absence may proceed under remaining transaction checks.'}]);
function mcpChoicesFor(id){return id==='lab-mcp04'?mcpAbsentIssuerChoices:mcpVariantCatalog[id];}
const mcpBuilders=[mcpBuild01,mcpBuild02,mcpBuild03,mcpBuild04,mcpBuild05,mcpBuild06,mcpBuild07,mcpBuild08,mcpBuild09,mcpBuild10,mcpBuild11,mcpBuild12,mcpBuild13];
export function buildMCPScenarioFixture(id,{variant='default'}={}){
  const choices=mcpChoicesFor(id);if(!choices)throw new RangeError('Unknown MCP fixture '+id);if(!choices.some(choice=>choice.id===variant))throw new RangeError('Unknown MCP variant '+variant);
  const model=mcpBuilders[Number(id.slice(-2))-1](variant);model.variantChoices=choices;model.withVariant=variantId=>buildMCPScenarioFixture(id,{variant:variantId});return mcpFreeze(model);
}
export const MCPLAB_SCENARIOS=Object.keys(mcpVariantCatalog).map(id=>buildMCPScenarioFixture(id));
export const MCPLAB_CASE_BUILDERS=mcpFreeze(Object.fromEntries(Object.keys(mcpVariantCatalog).map(id=>[id,Object.fromEntries(mcpChoicesFor(id).map(choice=>[choice.id,()=>buildMCPScenarioFixture(id,{variant:choice.id})]))])));
