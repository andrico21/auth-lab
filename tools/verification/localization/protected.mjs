import {createHash} from 'node:crypto';

export const sha256=value=>createHash('sha256').update(value).digest('hex');
export const stableJson=value=>JSON.stringify(value,(_,item)=>item&&typeof item==='object'&&!Array.isArray(item)?Object.fromEntries(Object.entries(item).sort(([a],[b])=>a<b?-1:a>b?1:0)):item);
const PARAMETER_AUDIT_FIELDS=new Set(['sourcePath','reference','typeContract','structuredReferenceRequired']);
export const semanticParameters=parameters=>Object.fromEntries(Object.entries(parameters||{}).map(([name,definition])=>[name,Object.fromEntries(Object.entries(definition).filter(([field])=>!PARAMETER_AUDIT_FIELDS.has(field)))]));

// These roles describe canonical values, never a second English prose catalog.
export const PROTECTED_FIELDS=new Set(['id','name','role','example','examples','standard','source','sources','attributeId','attributeIds','artifactId','representationId','holdingId','instanceId','exactValueRef','value','values','code','reasonCode','status','securityStatus','failureStage','firstDetector','verificationKind','stoppedAction','path','fieldPath','fieldPaths','statePaths','startPath','deadlinePath','statusPath','messageId','from','to','channel','phase','kind','type','format','store','stores','categories','publicationStatus','supportStatus','algorithms','transports','version','protocol','transport','keyRef','certificateRole','valueTemplate']);
export const SOURCE_CITATION_FIELDS=new Set(['id','name','label','title','url','standard','section','revision','retrieved','version','quote','quotation','officialQuote']);
const TECHNICAL=/https?:\/\/[^\s<>"']+|\burn:[A-Za-z0-9][A-Za-z0-9:._/-]*|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|\/(?:etc|usr|var|run|proc|home|tmp)\/[A-Za-z0-9._/-]+|[A-Za-z]:\\[^\s"'<>]+|\b(?:S-\d+(?:-\d+)+|[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|RFC\s*\d+(?:\s*(?:§|section)\s*[\d.]+)?|MS-[A-Z0-9-]+|(?:AES|SHA|HMAC|HKDF|RSA|ECDSA|ECDH|PBKDF2|Argon2|scrypt|Ed25519|Ed448)\d*(?:[-_/+.][A-Za-z0-9]+)*|[A-Za-z][A-Za-z0-9-]*(?:[._][A-Za-z0-9_-]+)+|[A-Za-z]+_\w+|[A-Za-z]+\d+[A-Za-z0-9]*|\d+[A-Za-z][A-Za-z0-9]*|(?:0x)[0-9a-fA-F]+|\d+(?:[.:/-]\d+)*(?:ms|s|h|d)?)\b/g;
const structuredName=value=>/[_.:/=\\{}^]|\b[A-Z]{2,}\b|[a-z][A-Z]|[A-Za-z]\d/.test(value)||value.length===1&&!['a','A','I'].includes(value)&&/^[A-Za-z\u0370-\u03ff]$/.test(value);
const FORMAL_TECHNICAL_NAMES=['Active Directory','Microsoft Entra ID','OpenID Connect','OAuth','OAuth 2.0','Kerberos','Keycloak','Windows','WebAuthn','FIDO2','OpenSSH','PowerShell','Netlogon','CredSSP','SPNEGO','GSS-API','PKINIT','FAST','DNSSEC','SAML','OIDC','NTLM','NTLMv2','TLS','TLS1.3','HTTP','HTTPS','LDAP','LDAPS','RADIUS','RadSec','EAP-TLS','Kubernetes','macOS','Linux','PAM','sudo','JWT','JWE','JWS','NFS','MCP','SPAKE2+','SPAKE2','PKCS#11','AS','TGS','TGT','KDC','AP','DC','AD DS','RP','IdP','SP','JSON','XML','DER','PEM','ASN.1','AES','RSA','SHA256','SHA512','HMAC','HKDF','PBKDF2','PKCE','S256','SSO','SLO','MFA','TOTP','OTP','PIN','SID','PAC','ACL','DACL','SACL','SAM','LSA','LSASS','CIFS','SMB','SMB3.1.1','TCP','UDP','IP','IPv4','IPv6','DNS','DS','RRSIG','DNSKEY','NSEC','NSEC3','CDS','CDNSKEY','KSK','ZSK','TTL','RRset'];
const FORMAL_REFERENCES=FORMAL_TECHNICAL_NAMES.filter(value=>value!=='AS').concat(['RFC','IETF','NIST','Microsoft','Apple','Google','Cisco','MIT','MIT Kerberos','Kerberos V5','KerberosV5','Entra','Entra ID','Okta','Amazon Cognito','Cognito','AWS IAM Identity Center','IAM Identity Center','AWS','Conditional Access','YubiKey','Windows Hello','Windows Hello for Business','Google Workspace','Touch ID','Secure Enclave','OpenSSL','Protected Users','Credential Guard','Remote Credential Guard','Restricted Admin','LSA protection','UAC','SSPI','CNG','DPAPI','API','BFF','CIBA','CORS','CTAP','CTAP2','F2','FIDO','HTTP-POST','HTTP-Redirect','ID','IEEE','IPC','JWKS','OASIS','OIDC/SAML','PAKE','POST','SPA','V2','W3C','DPoP']).map(value=>({value,formal:true,kind:'protocol-product-or-command-name',sourcePath:'formal-technical-name:'+value}));
const HUMAN_UI_UPPERCASE=new Set(['ATTRIBUTE','CANONICAL','CHECKS','CONNECTION','CREATION','DEVICE','ENGLISH','EXACT','EXCHANGE','EXCHANGES','EXPLORE','FOLLOW','HISTORY','IDENTITY','INSPECTOR','INTERACTIVE','JOURNEY','LAB','LEARNING','LOCAL','NAMES','OBJECT','ON','ONE','ORDERED','PLAIN','READY','SERVICES','THE','THIS','TO','TRANSFER','YOUR','OPTION','NOT','USED','PATH','FOLLOWING','REPLAYING','DEMO','RUNNING','PAUSED','COMPLETE','PARTICIPANT','LIFECYCLE','FIELD','GUIDE','STEP','OF','CURRENT','MOMENT']);
const boundary=(text,start,end)=>!/[\p{L}\p{N}_]/u.test(text[start-1]||'')&&!/[\p{L}\p{N}_]/u.test(text[end]||'');
const SOURCE_CONFIRMED_TECHNICAL_NAMES=['EAP','NAS','SSH','CA','CLI','AEAD','MSK','RPC','SSSD','GSS','EMSK','AAA','DH','NT','URL','MAC','SPN','EKU','AD','EAPOL','PC','ASCII','NPS','KILE','URI','PRF','OS','SPAKE','RDP','NTP','ACK','LM','NUL','RBAC','ZONEMD','AV','CEK','EDNS','UI','CMS','UID','UPN','SOA','KDF','SPKI','RDATA','ACS','ECDHE','IV','TSIG','DNAME','NAK','JWK','JARM','ALPN','NSS','QR','OP','GET','RCG','PAR','FQDN','HTTP/TERMSRV','PA-TGS-REQ','PA-FX-ERROR','AS-REQ','TGS-REQ','AP-REQ','AP-REP','KDC-REQ-BODY','KRB-ERROR','KRB-FX-CF2','PA-ENCRYPTED-CHALLENGE','SF-NONE','PA-SPAKE','PA-ENC-TIMESTAMP','METHOD-DATA','PA-DATA'].map(value=>({value,formal:true,kind:'source-confirmed-technical-name',sourcePath:'source-confirmed-technical-name:'+value}));
const globallyStructuredName=value=>/[_.:/=\\{}^()-]|[a-z][A-Z]|[A-Za-z]\d|[A-Z]{2,}-/.test(value);
const AUDITED_TECHNICAL_NAMES=['CBOR','HOTP','UTF-8','UTF8','UTF','JOSE','REST','IANA','CSRF','HTML','GUI','PKI','MIME','PBKDF','MTU','HSM','DEFLATE','CSP','BCP','PDF','DOCX','SMS','CRUD','MACsec','PKAuthenticator','KDCDHKeyInfo','TSRequest','TSCredentials','TSPasswordCreds','TSRemoteGuardCreds','SPAKESupport','SPAKEChallenge','SPAKECookie','SPAKEResponse','SPAKESecondFactor','SPAKEsecret','SAMLRequest','SAMLart','SMBSigningKey'].map(value=>({value,formal:true,kind:'source-audited-technical-name',sourcePath:'source-audit:protocol-data+kerberos-crypto+windows-auth+kerberos-spake+saml-data+smb-multichannel-lab'}));
const HUMAN_PROSE_UPPERCASE=new Set(['MUST','SHOULD','AND','NOT','UNTRUSTED','TV']);

// Canonical narrative can embed literal JSON, object constructors and identifier
// sets. Keep those exact source spans out of the named-placeholder grammar.
function literalStructuredExamples(english){
  const spans=[];
  for(let start=0;start<english.length;start++){
    if(english[start]!=='{')continue;
    let depth=1,quote='',escaped=false,end=start+1;
    for(;end<english.length&&depth;end++){
      const character=english[end];
      if(quote){
        if(escaped)escaped=false;
        else if(character==='\\')escaped=true;
        else if(character===quote)quote='';
      }else if(character==='"'||character==="'")quote=character;
      else if(character==='{')depth++;
      else if(character==='}')depth--;
    }
    if(depth)continue;
    const inner=english.slice(start+1,end-1),constructor=english.slice(0,start).match(/\b[A-Za-z_$][A-Za-z0-9_$.-]*$/);
    if(constructor||/[:,=]/.test(inner)||/^[A-Za-z0-9_.:/-]+$/.test(inner)&&/[_.:/-]/.test(inner))spans.push({start:constructor?start-constructor[0].length:start,end});
    start=end-1;
  }
  return spans;
}

// These are operands of the DNS producers below, not a terminal-word rule.
// The root, wildcard prefix and absolute-name dot belong to the same identity.
const DNS_ABSOLUTE_OWNER='(?:\\*\\.)?(?:[A-Za-z0-9_][A-Za-z0-9_-]*\\.)+|\\.';
const DNS_RR_TYPE='(?:RRSIG\\([A-Z0-9]+\\)|[A-Z][A-Z0-9]*)';
const DNS_OWNER_FIELDS=new Set(['label','trace.title','title','summary','detail','payload.description','chapters.label']);
const dnsOwnerContract=(prefix,suffix,evidence)=>({pattern:new RegExp('^('+prefix+')('+DNS_ABSOLUTE_OWNER+')'+suffix+'$'),evidence});
const DNS_OWNER_CONTRACTS=[
  dnsOwnerContract('(?:Published(?: RRset| exact| client[AB])?|Previously published g0 /|Received(?: RRset| occurrence(?: /)?)?|Earlier cached|Earlier received(?: cached RRset| client[AB])?|Fresh received|Prepared per-query|Authority catalog only /|Selected response occurrence /|Validation evidence /|Reference-bound chain evidence /|Available public) ',' '+DNS_RR_TYPE,'src/dnssec-lookup.js:51,56,89,98,153; src/dnssec-resolution-cases.js:39,46; src/dnssec-denial-cases.js:54-55,75; src/dnssec-network-cases.js:109-111,117,133,143,194,532,535; src/dnssec-zone-publication-cases.js:163; canonical RRset owner operand'),
  dnsOwnerContract('(?:Query|Request) ',' '+DNS_RR_TYPE,'src/dnssec-lookup.js:152; src/dnssec-resolution-cases.js:85; src/dnssec-denial-cases.js:118; src/dnssec-network-cases.js:159,506; src/dnssec-signing-cases.js:128; canonical question.qname operand'),
  dnsOwnerContract('Receive ',' '+DNS_RR_TYPE+' before trust','src/dnssec-lookup.js:167; canonical received RRset owner operand'),
  dnsOwnerContract('Receive (?:NOERROR|SERVFAIL|NXDOMAIN|REFUSED|FORMERR|NOTAUTH) / ','','src/dnssec-network-cases.js:185,513; response question.qname operand'),
  dnsOwnerContract('Retrieve ',' '+DNS_RR_TYPE+'(?: at [A-Fa-f0-9:.]+)?','src/dnssec-parent-cases.js:77; retrieved RRset owner operand'),
  dnsOwnerContract('Evaluate ',' '+DNS_RR_TYPE+' under authenticated prerequisites','src/dnssec-resolution-cases.js:113; checked RRset owner operand'),
  dnsOwnerContract('Check (?:parent-ds-signature|dnskey-rrset-signature|answer-signature|ds-policy) for ','','src/dnssec-signing-cases.js:196; validation check.zone operand'),
  dnsOwnerContract('DNSKEY ',' / [A-Za-z0-9_.-]+','src/dnssec-lookup.js:45; canonical public key.owner operand'),
  dnsOwnerContract('(?:Unsigned delegation routing NS|Unsigned routing glue|Explicit trust anchor) ','','src/dnssec-lookup.js:72,158-159; canonical zone/target/anchor owner operand'),
  dnsOwnerContract('(?:g\\d+|signed-g\\d+|received-g\\d+|zonemd-candidate) ',' '+DNS_RR_TYPE,'src/dnssec-zone-publication-cases.js:196,199; canonical generation RRset/signature owner operand'),
  dnsOwnerContract('',' '+DNS_RR_TYPE+' / exact zone generation','src/dnssec-parent-cases.js:70; canonical exact-generation RRset owner operand'),
  dnsOwnerContract('(?:Request the selected immutable zone transfer|Receive authenticated transfer message \\d+|Receive UPDATE before authentication|Return the correlated management response) / ',' '+DNS_RR_TYPE,'src/dnssec-zone-publication-cases.js:140,237,247,273,285; decoded wire record.owner operand'),
  dnsOwnerContract('Private shared transaction capability ','','src/dnssec-zone-publication-cases.js:131; canonical TSIG key.keyName operand'),
  dnsOwnerContract('Authenticate ',' DS under the root, not the referral glue','src/dnssec-lookup.js:186; source-declared parent DS owner'),
  dnsOwnerContract('Match parent DS, then authenticate the entire ',' DNSKEY RRset','src/dnssec-lookup.js:187; source-declared parent DNSKEY owner')
];
function dnsOwnerSpans(english,context){
  if(!/^(?:artifact|step|lesson):lab-dnssec\d+(?::|$)/.test(context.ownerId||'')||!/^src\/dnssec-[a-z-]+\.js$/.test(context.sourceModule||'')||!DNS_OWNER_FIELDS.has(context.fieldPath))return [];
  // Authoring wraps the same send title in a construction step, packet/carrier
  // caption and trace operation suffix. None of those wrappers is a DNS value.
  const separator=context.fieldPath==='trace.title'?english.lastIndexOf(': '):-1;
  let caption=separator<0?english:english.slice(0,separator);
  caption=caption.replace(/ \/ (?:DNS message|opaque TLS carrier)$/,'');
  const offset=caption.startsWith('Construct ')?'Construct '.length:0;
  caption=caption.slice(offset);
  for(const {pattern,evidence} of DNS_OWNER_CONTRACTS){
    const match=caption.match(pattern);if(!match)continue;
    const start=offset+match[1].length;
    return [{start,end:start+match[2].length,evidence}];
  }
  return [];
}

// PAM producers embed configuration operands in teaching prose. These exact
// constructor fragments are code; ordinary required/optional prose is not.
function pamControlSpans(english,context){
  const owner=context.ownerId||'',module=context.sourceModule||'',spans=[];
  if(!/^(?:lesson|step|artifact):lab-(?:pam01|llog01|lelev02)(?::|$)|^field:unixws_lab_(?:pam01|llog01|lelev02)_/.test(owner)||!/^src\/(?:pam-(?:foundations-lab|stack-evaluator)|linux-(?:logon|elevation)-lab)\.js$/.test(module))return spans;
  const add=(start,end,evidence)=>spans.push({start,end,evidence});
  const operand=english.match(/^((?:Evaluate|Skip) )(\/etc\/pam\.d\/[A-Za-z0-9_.-]+:[1-9]\d* (?:\[[^\]\r\n]+\]|required|requisite|sufficient|optional|include|substack) [A-Za-z0-9_./-]+)$/);
  if(operand)add(operand[1].length,english.length,'src/pam-foundations-lab.js:85-95; exact row.file:line + row.control + row.module constructor; src/pam-stack-evaluator.js:28-33');
  const diff=english.match(/^(Configuration diff, line \d+ only: )(required -> requisite)(; compare )(sufficient-after-failure)$/);
  if(diff){
    add(diff[1].length,diff[1].length+diff[2].length,'src/pam-foundations-lab.js:55; actual control flag configuration diff');
    add(english.length-diff[4].length,english.length,'src/pam-foundations-lab.js:55; exact comparison case ID');
  }
  if(english==='Change only required to requisite'){
    for(const control of ['required','requisite']){
      const start=english.indexOf(control);
      add(start,start+control.length,'src/pam-foundations-lab.js:154; actual '+control+' control operand');
    }
  }
  if(/^numeric jump skips \d+ current-scope item\(s\); substack counts as one$/.test(english)){
    const start=english.indexOf('substack');
    add(start,start+8,'src/pam-stack-evaluator.js:99; actual substack control keyword in numeric-jump scope rule');
  }
  const declared=english.match(/^(Declared )(sufficient pam_rootok(?:\.so)?)( bypasses password comparison for real UID0)$/);
  if(declared)add(declared[1].length,declared[1].length+declared[2].length,'src/linux-elevation-lab.js:77; configured sufficient control + module operand');
  const summary=english.startsWith('Synthetic afs-login service:')||english.startsWith('su-l stack:');
  if(summary){
    const service=english.match(/^(?:Synthetic )?(afs-login|su-l)(?: service:| stack:)/),start=english.startsWith('Synthetic ')?10:0;
    if(service)add(start,start+service[1].length,'src/linux-logon-lab.js:183; src/linux-elevation-lab.js:68; exact authored PAM service ID');
    const line=/\b(?:auth(?:\/account\/password)?|account|password|session) (?:required|requisite|sufficient|optional) pam_[A-Za-z0-9_]+(?:\.so)?(?: \+ pam_[A-Za-z0-9_]+(?:\.so)?)*/g;
    for(const match of english.matchAll(line))add(match.index,match.index+match[0].length,'src/linux-logon-lab.js:183; src/linux-elevation-lab.js:68; authored configuration type/control/module fragment');
    for(const match of english.matchAll(/\boptional pam_[A-Za-z0-9_]+(?:\.so)?/g))add(match.index,match.index+match[0].length,'src/linux-logon-lab.js:183; configured optional module fragment');
    const nullok=english.indexOf('No nullok baseline.');
    if(nullok>=0)add(nullok+3,nullok+9,'src/linux-logon-lab.js:183; exact PAM module option');
  }
  if(english.includes('--login environment baseline;')){
    for(const match of english.matchAll(/(?<![A-Za-z0-9_-])(?:--login|runuser|setuid|su)(?![A-Za-z0-9_-])/g))add(match.index,match.index+match[0].length,'src/linux-elevation-lab.js:68; actual command, flag and identity-mechanism references');
  }
  return spans;
}

// Semantic occurrences require declared protocol context or explicit protocol
// evidence in the sentence. Contrasts/absence still name actual members, while
// session, account, freshness and local encryption state remain ordinary prose.
function semanticOccurrenceSpans(english,context,local){
  const spans=[],scope=[context.standard,context.protocol,context.ownerId,context.sourceModule,...context.semanticSourceModules||[]].filter(Boolean).join(' ');
  const add=(pattern,evidence)=>{for(const match of english.matchAll(pattern))spans.push({start:match.index,end:match.index+match[0].length,evidence});};
  const oauth=/OAuth|OIDC|OpenID|MCP|CIBA|DPoP|(?:src\/|:)(?:protocol-data|architecture-variants|web-api|single-realm|attribute-usage|branching|lifecycle|protection|service-account|mcp-auth|ciba|device-flow|extended-grants|kubernetes)/i.test(scope)||/\b(?:OAuth|OIDC|OpenID|DPoP)\b|\bID[- ]tokens?\b/i.test(english);
  if(oauth){
    add(/\b(?:resource server|authorization server)\b/gi,'RFC 6749 §1.1; src/protection-lab.js:protRealm/protApi; src/mcp-auth-lab.js:mcpActorSpecs');
    // nonce is an opaque OIDC/DPoP member, including explicit absent/prohibited
    // claims. Do not extend this to conceptual nonces in unrelated protocols.
    for(const match of english.matchAll(/\bnonces?\b/g)){
      const before=english.slice(Math.max(0,match.index-60),match.index),after=english.slice(match.index+match[0].length,match.index+match[0].length+60);
      const member=/\b(?:OIDC|ID[- ]tokens?|JWT|DPoP|claim|proof|state|issuer|audience|signature|authorization[- ]server|resource server)\b/i.test(english)||/\b(?:request|request’s|request's|broker|app|resource-specific|resource|returned|received|expected|original|authorization[- ]server|resource server)(?:’s|'s)?\s*$/.test(before)||/^\s*(?:=|claim\b|matches\b|prohibited\b)/.test(after);
      const conceptual=/\b(?:encryption|cipher|GCM|TLS|transport|conceptual|ordinary|generic|local encryption)\s*$/.test(before)||/^\s+for\s+(?:local encryption|the cipher|encryption|TLS)\b/.test(after);
      // The wire name is nonce; an English plural suffix remains human prose.
      if(member&&!conceptual)spans.push({start:match.index,end:match.index+5,evidence:'src/protocol-data.js:ATTRIBUTES.nonceApp/nonceBroker; src/protection-lab.js:DPoP nonce; OIDC Core §3.1.2.1'});
    }
    for(const match of english.matchAll(/\bstate\b/g)){
      const before=english.slice(Math.max(0,match.index-65),match.index),after=english.slice(match.index+5,match.index+85);
      const listed=/\b(?:code|scope|client_id|redirect_uri|response_type|PKCE)\s*(?:,|and)\s*(?:(?:the|original|application)\s+)*$/.test(before)||/^\s*[,/]\s*nonce\b/.test(after);
      const named=listed||/\b(?:OAuth|OIDC|returned|received|original|expected|fresh|new|request|request’s|broker|app|callback|logout|upstream|independent|pending|transaction)\s*$/.test(before)||/^\s*(?:=|\/nonce\b)/.test(after)||/^\s+(?:parameter|matches? callbacks|match|validation|ties|with the original|with its|before (?:accepting|redeeming)|and (?:nonce|expected callback|registered callback|stop the denied|a new pending transaction))\b/.test(after)||/\b(?:compares?|validates?|checks?|generate|generates|retains?|return|returns|includes?)\s+(?:the\s+)?$/.test(before);
      const conceptual=/\b(?:session|browser|account|authority|authority-local|protocol|current|configured|effective|observed|decoded|shared-secret\/transcript|local session|signed-in|replay|authentication-context|credential|private|public JavaScript|issuer|revocation|freshness|local RP|account\/consent\/request|pending-request|pending server-side transaction)\s*$/.test(before)||/^\s+(?:stays|uses|from|is authority|operation|remains|to show|even when)/.test(after);
      if(named&&!conceptual)spans.push({start:match.index,end:match.index+5,evidence:'src/protocol-data.js:ATTRIBUTES.stateApp/stateBroker; src/web-api-lab.js:webState; RFC 6749 §4.1.1'});
    }
  }
  if(/\bRealm [AB]\b/.test(english)&&(oauth||/Realm|Keycloak|OAuth|OIDC|CIBA|protocol-data|architecture-variants|web-api|service-account|branching|lifecycle|extended-grants|device-flow|ciba|protection|held-object-web/i.test(scope)||local.some(ref=>/^actor:realm[AB]$/.test(ref.owner||''))))add(/\b(?:Realm A|Realm B)\b/g,'src/protocol-data.js:ACTORS.realmA/realmB; authored actor-name suffix');
  // The historical reclassification filter dropped unreferenced actor records.
  // These are the actual kspActors IDs (plus the authored downgrade observer),
  // not a hyphenated-word heuristic or a translated actor caption.
  if(/kerberos-spake|lab-krb-spake|field:ksp/.test(scope))add(/\bspake-(?:client|kdc|tgs|service|observer)\b/g,'src/kerberos-spake-lab.js:kspActors and kspBuild observer declaration');
  if(/dnssec/i.test(scope)){
    // Case and checkpoint captions are constructed by replacing ID hyphens with
    // spaces. Their lowercase spelling remains the authored case vocabulary.
    if(/^(?:cname (?:secure|insecure|bogus) target|dname synthesized cname|(?:udp truncated )?tcp (?:retry|blocked)|tcp failure not cryptographic bogus|correlated tcp response completes proof input(?: after receipt)?)$/.test(english))add(/\b(?:cname|dname|tcp|udp|secure|insecure|bogus)\b/g,'src/dnssec-denial-cases.js:dnssec09 case keys; src/dnssec-network-cases.js:checkpoint keys');
    if(/^Explicit fixed (?:cname-(?:secure|insecure|bogus)-target|dname-synthesized-cname|udp-truncated-tcp-retry|tcp-blocked) input profile$/.test(english))add(/\b(?:cname-(?:secure|insecure|bogus)-target|dname-synthesized-cname|udp-truncated-tcp-retry|tcp-blocked)\b/g,'src/dnssec-lab.js:variantChoices.description; exact declared case ID');
    if(/\bconcrete cname object\b/.test(english))add(/\bcname\b/g,'src/dnssec-fields.js:concrete cname object identity');
    if(/^(?:secure|insecure|bogus|indeterminate|non-bogus)$/.test(english))add(/^(?:secure|insecure|bogus|indeterminate|non-bogus)$/g,'RFC 9499 §10; exact source-scoped DNSSEC result label');
    if(english==='Accept non-bogus data or withhold a bogus answer'||english==='accept non-bogus unverified answers')add(/\b(?:non-bogus|bogus)\b/g,'src/dnssec-resolution-cases.js:accepted-use-and-cache-boundary; accepted=status!==bogus, independent application policy follows');
    // Result names in explicit verdict/delegation descriptions, not an ordinary
    // adjective such as "an insecure connection" or "secure storage".
    for(const match of english.matchAll(/\b(?:non-bogus|secure|insecure|bogus|indeterminate)\b/g)){
      const before=english.slice(Math.max(0,match.index-45),match.index),after=english.slice(match.index+match[0].length,match.index+match[0].length+45);
      if(/\b(?:securityStatus|verdict|classification|classified|status)\s*(?:is|was|=|:|as)?\s*$/i.test(before)||/^\s*(?:[,/]|or\b)/.test(after)||/\b(?:or|not|as|remain|remains)\s*$/.test(before)||/^\s+(?:delegation|answer|data|cache|target|operator bypass|path)\b/.test(after))spans.push({start:match.index,end:match.index+match[0].length,evidence:'src/dnssec-validation.js:securityStatus; RFC 9499 §10; source-scoped DNSSEC result occurrence'});
    }
  }
  // cname/crealm are Kerberos principal members, not just DNS record names.
  if(/Kerberos|MS-KILE|RFC\s*4120|kerberos|krb|forest|ksp/.test(scope))add(/\b(?:cname|crealm)\b/g,'src/kerberos-ad-lab.js:original cname/crealm; RFC 4120 §5.3');
  if(/NFS|nfs-access|RPCSEC/.test(scope))add(/\b(?:stateid|sessionid|clientid|sequenceid|cachethis|gss_proc)\b/g,'src/nfs-access-lab.js:initialState.nfs, open/close results and nfsRead arguments; RFC 8881 wire members');
  return spans;
}

function sourceIdentitySpans(english,context){
  const owner=context.ownerId||'',field=context.fieldPath||'',spans=[...dnsOwnerSpans(english,context),...pamControlSpans(english,context)];
  const add=(start,end,evidence)=>spans.push({start,end,evidence});
  const separator=field==='trace.title'?english.lastIndexOf(': '):-1,end=separator<0?english.length:separator,label=english.slice(0,end);
  if(/^artifact:/.test(owner)&&['label','trace.title'].includes(field)){
    // The default artifact caption is its exact canonical ID, not a human alias.
    if(label===owner.slice('artifact:'.length))add(0,end,'src/held-object-web.js:121-122; canonical artifactId equals displayed label');
    if(/^artifact:lab-dnssec\d+:/.test(owner)){
      // Actual record-kind / ID and generation / owner / RR-type constructors.
      const record=label.match(/(?:^| )((?:RRSIG(?:\([A-Z0-9]+\))?|RRSET|DNSKEY|DS|NSEC3?|ZONEMD)(?: \/ | )([A-Za-z0-9_.:/-]+))$/);
      if(record&&/[_.:/-]|\d/.test(record[2])){const start=record.index+record[0].indexOf(record[1]);add(start,end,'src/dnssec-signing-cases.js:56-57; src/dnssec-parent-cases.js:69-73; src/dnssec-network-cases.js:118-120');}
      if(/^DNSKEY (?:\*\.)?[A-Za-z0-9_.-]+ \/ [A-Za-z0-9_.-]+$/.test(label))add(0,end,'src/dnssec-lookup.js:45; canonical DNSKEY owner + key ID');
      if(/^(?:g\d+|signed-g\d+|received-g\d+|zonemd-candidate) (?:\*\.)?[A-Za-z0-9_.-]+ (?:[A-Z][A-Z0-9]*|RRSIG\([A-Z0-9]+\))$/.test(label))add(0,end,'src/dnssec-zone-publication-cases.js:193-201; generation key + canonical owner + RR type');
    }
    if(/^TDO-key-[A-Z0-9.-]+-to-[A-Z0-9.-]+$/.test(label))add(0,end,'src/held-object-kerberos.js:395-403; configured account/resource realm key identity');
    if(label==='OIDC nonce')add(0,end,'src/held-object-web.js:nonce artifact; exact OIDC claim reference, not conceptual nonce prose');
  }
  if(context.sourceModule==='src/network-access-lab.js'&&['label','trace.title','title'].includes(field)&&/^(?:(?:RadSec|UDP|RADIUS\/1\.1) \/ |RADIUS\/1\.1 )?(?:Access-(?:Request|Accept|Challenge|Reject)|Accounting-(?:Request|Response)(?: (?:Start|Stop|Interim-Update)| \[(?:Start|Stop|Interim-Update)\])?|Disconnect-(?:Request|ACK|NAK)|CoA-(?:Request|ACK|NAK))$/.test(label))add(0,end,'src/network-access-lab.js:139-177,237-242,583,604-608; RADIUS Code and Acct-Status-Type literals');
  if(/^environment-field:[ab](?:Authorization|Token|Jwks)URL$/.test(owner)&&field==='label'&&/^[AB] (?:authorization_endpoint|token_endpoint|jwks_uri)$/.test(english))add(0,english.length,'src/runtime-environment.js:21-25; formal actor prefix + opaque OIDC metadata member');
  if(/^[A-Za-z_][A-Za-z0-9_]*=(?:true|false)$|^U ACL=(?:true|false)$/.test(english))add(0,english.length,'Canonical source expression: exact property/ACL key, assignment operator and Boolean literal');
  if(context.sourceModule==='src/network-access-lab.js'&&field==='detail'&&['wrong-transport-peer','unauthorized-group'].includes(english))add(0,english.length,'src/network-access-lab.js; exact modeled observation reason code');
  if(/protocolTimeline\.entries\..*\.label$/.test(field)&&context.sourceModule==='src/dnssec-lab.js'&&/^client[AB] \/ public-v\d+$/.test(english))add(0,english.length,'src/dnssec-network-cases.js:602; canonical context name + input view ID');
  if(['subfixtureChoices.label','searchVariants.label','variantChoices.label'].includes(field)){
    if(context.sourceModule==='src/windows-protection-lab.js'&&['rbcd','kcd'].includes(english))add(0,english.length,'src/windows-protection-lab.js:510-511; exact delegationMode enum');
    if(context.sourceModule==='src/dnssec-lab.js'&&english==='nxdomain')add(0,english.length,'src/dnssec-lab.js:33; exact DNS denial-case identifier');
  }
  return spans;
}

export class ProtectedRegistry {
  constructor({locate,onEntry}={}){this.entries=new Map();this.locate=locate;this.onEntry=onEntry;this.typedNames=new Map();this.typedNameIdentities=new Set();}
  add(kind,value,owner,fieldPath,source={}){
    if(typeof value!=='string'||!value)return null;
    const identity={kind,semanticId:owner,fieldPath,value};
    const id='protected:'+sha256(stableJson(identity)).slice(0,32);
    if(!this.entries.has(id)){
      if(!source.module&&this.locate)source={...source,...this.locate(value,owner)};
      this.entries.set(id,{id,...identity,sourceSha256:sha256(value),source});
      this.onEntry?.(this.entries.get(id));
    }
    return id;
  }
  registerTypedName(value,source={}){
    if(typeof value!=='string'||!globallyStructuredName(value))return;
    const first=value.match(/[\p{L}\p{N}_]+/u)?.[0];if(!first)return;
    const identity=stableJson({value,...source});if(this.typedNameIdentities.has(identity))return;this.typedNameIdentities.add(identity);
    const records=this.typedNames.get(first)||[];records.push({value,formal:true,kind:'structured-field-name',...source});this.typedNames.set(first,records);
    const canonical=value.replace(/\s*\([^)]*\)/g,'').trim();
    if(canonical!==value)this.registerTypedName(canonical,{...source,sourcePath:(source.sourcePath||'name')+':labCanonicalName'});
  }
  record(record,owner,source={}){
    if(!record||typeof record!=='object')return;
    if(owner.startsWith('actor:')){
      const id=owner.slice(6);
      this.add('actor-identifier',id,owner,'id',source);
      this.registerTypedName(id,{owner,sourcePath:owner+'.id',kind:'actor-identifier'});
      if(record.name)this.registerTypedName(record.name,{owner,sourcePath:owner+'.name',kind:'actor-name'});
    }
    for(const [field,value] of Object.entries(record)){
      if(!PROTECTED_FIELDS.has(field)&&!/(?:Ids?|Refs?|Paths?)$/.test(field))continue;
      if(field==='name'&&!/^(?:field|actor|payload):/.test(owner)&&source.fieldRole!=='profile'&&!source.fieldRole?.startsWith('payload')&&!source.fieldRole?.includes('representation.fields'))continue;
      if(typeof value==='string')this.add(field==='name'?'formal-name':field==='role'?'formal-role':field,value,owner,field,source);
      else if(Array.isArray(value)){
        for(const item of value){
          if(typeof item==='string')this.add(field,item,owner,field,source);
          else if(item&&typeof item==='object'&&field==='sources')for(const [part,exact] of Object.entries(item))if(typeof exact==='string'&&SOURCE_CITATION_FIELDS.has(part))this.add('official-citation',exact,owner,field+'.'+part,source);
        }
      }else if(value&&typeof value==='object'&&['source','sources'].includes(field)){
        for(const [part,exact] of Object.entries(value))if(typeof exact==='string'&&SOURCE_CITATION_FIELDS.has(part))this.add('official-citation',exact,owner,field+'.'+part,source);
      }
    }
  }
  // Ordinary definition names are NOT global match rules. Only typed local
  // references, structured field names and formal actor names enter this list.
  references(english,local=[],context={}){
    let occurrenceSha=null;
    const keyInstruction=context.keyInstruction||/\bEnter to (?:choose|select)\b|\bTab (?:explores|moves|cycles)\b|\bEscape (?:returns|closes|cancels)\b|\b(?:Press|press) (?:Enter|Tab|Escape)\b/.test(english);
    const typed=[];
    for(const token of new Set(english.match(/[\p{L}\p{N}_]+/gu)||[]))typed.push(...this.typedNames.get(token)||[]);
    local=local.concat(typed,SOURCE_CONFIRMED_TECHNICAL_NAMES);
    const standard=context.standard||'',protocol=context.protocol||'';
    local=local.concat(AUDITED_TECHNICAL_NAMES);
    const domain=[standard,protocol,context.ownerId||'',context.sourceModule||'',english].join(' ');
    const scoped=(test,values,kind,sourcePath)=>{if(new RegExp(test.source,'i').test(domain))local.push(...values.map(value=>({value,formal:true,kind,sourcePath})));};
    if(/(?:^|\.)(?:keywords|searchTags)$/.test(context.fieldPath||'')){
      scoped(/PAM|sudo|lelev|linux-elevation|pam-foundations|ssh-sssd/,['nofile','substack','required','sudoers','requisite','sufficient','optional','pam','include'],'source-search-technical-token','src/pam-configurations.js:95-149; src/pam-stack-evaluator.js:28-49');
      scoped(/Windows|wprot|wlog|welev|wra|win-|windows-|LSA/,['vbs','Negotiate','credguard','rdp','rcg','lsa','ppl','lsaiso','lsass','deny-only'],'source-search-technical-token','src/scenario-search-metadata.js; Windows security mechanism/flag identifiers');
      scoped(/network-access|RADIUS|EAP/,['totp','pap'],'source-search-technical-token','src/network-access-lab.js; exact authentication profile IDs');
      scoped(/NFS|nfs-access/,['mount'],'source-search-technical-token','src/nfs-access-lab.js; Unix mount command');
      scoped(/Kubernetes|kubernetes/,['kubectl'],'source-search-technical-token','src/kubernetes-auth-lab.js; kubectl command');
      if(context.sourceModule==='src/pake-lab.js'&&/^rfc938[23]-[BC]-\d+-p256-sha256$/.test(english))local.push({value:english,formal:true,kind:'source-vector-identifier',sourcePath:'src/pake-lab.js:35-37'});
    }
    scoped(/WebAuthn|CTAP|FIDO|flagsU[PV]|pinUv/,'UP UV AAGUID'.split(' '),'webauthn-flag-or-structure','src/protocol-data.js:WebAuthn+src/fido-direct.js');
    scoped(/JWE|JOSE|PAKE|RFC\s*751[6789]|field:jwe/,'AAD GCM ENC SIGN'.split(' '),'jose-crypto-name','src/jwe-data.js:jweDefinitions');
    scoped(/SAML|XML Encryption|field:saml/,'MGF MGF1'.split(' '),'xml-encryption-parameter','src/saml-data.js:SAML_ATTRIBUTES');
    scoped(/SMB|MS-SMB2/,'GCM'.split(' '),'smb-encryption-mode','src/smb-access-lab.js');
    scoped(/CIBA|Keycloak.*(?:result|status)|field:ciba/,'SUCCEED UNAUTHORIZED CANCELLED'.split(' '),'ciba-result-enum','src/ciba-data.js');
    scoped(/DNS|dnssec/,'CO FORMERR NXDOMAIN NOERROR NOTAUTH REFUSED'.split(' '),'dns-flag-or-result','src/dnssec-lookup.js+dnssec-denial-cases.js');
    scoped(/TLS|PKINIT|SPAKE|PAKE|ECDSA|field:(?:pake|ksp)/,['P256','P-256'],'ec-curve-name','src/pake-lab.js+kerberos-spake-lab.js+network-access-lab.js');
    scoped(/field:(?:jwt|net|nfs)|(?:symbolic|fixture|SYM)/,['SYM'],'fixture-symbolic-value-marker','src/jwt-validation-lab.js+network-access-lab.js+nfs-access-lab.js');
    scoped(/Kerberos|GSS|SPNEGO|NTLM|SMB|CredSSP|Windows|MS-KILE|RFC\s*(?:4120|4178|9588)|(?:topic:topic-|lesson:|field:)(?:lab-)?(?:ad-|kc-|forest-|win|wlog|wprot|ksp|krb)/,['MIC','AS','ETYPE-INFO2','PA-FX-COOKIE','PA-ENC-TS-ENC','KDC-REQ','AD-IF-RELEVANT','TDO','BADKEYVER','TRANSITED-POLICY-CHECKED'],'kerberos-or-windows-protocol-name','src/kerberos-ad-lab.js+kerberos-crypto-lab.js+windows-auth-lab.js');
    scoped(/Windows|Kerberos|CredSSP|NTLM|WinRM|RDP|MS-NRPC|MS-WSMV|MS-CSSP|ADMX_CredSsp|CORP|HOST\$|WORKSTATION\$|SERVER\\/,['CORP','HOST$','WORKSTATION$','ADMIN$','HOST','WORKSTATION','SERVER','SERVER-local','RESOURCE','HYBRID','HYBRID_EX','WS-Management','WSMan','WSMAN','TERMSRV','KXKEY','NLMP','RDPEAR','GX','NLA','PDU','DR'],'windows-protocol-or-fixture-identity','src/windows-auth-lab.js+windows-logon-lab.js+windows-remote-administration-lab.js');
    scoped(/DNS|dnssec/,'UPDATE NOTIFY NS AXFR IXFR SEP EDE DSYNC CSYNC REVOKE AA NXNAME AAAA CNAME RR CSK DLV'.split(' '),'dns-record-operation-or-flag','src/dnssec-fields.js+dnssec-lookup.js');
    scoped(/Linux|macOS|POSIX|NFS|UID/,'GID'.split(' '),'posix-identity-name','src/linux-logon-lab.js+src/nfs-access-lab.js');
    scoped(/SAML/,'SOAP'.split(' '),'saml-artifact-transport','src/held-object-web.js');
    scoped(/TLS|PKINIT|certificate|cert\b|X\.509/,'SAN'.split(' '),'certificate-extension-name','src/ssh-access-lab.js');
    scoped(/Keycloak|FGAP/,'FGAP'.split(' '),'keycloak-permission-feature','src/extended-grants-lab.js');
    scoped(/OAuth|OIDC|MCP|CIMD|JARM/,'CIMD JAR'.split(' '),'oauth-extension-name','src/protection-lab.js+src/held-object-mcp.js');
    scoped(/NFS|RPCSEC/,'MOUNT SECINFO SETCLIENTID CONFIRM WRONGSEC'.split(' '),'nfs-operation-or-error','src/nfs-access-lab.js');
    scoped(/PAKE|SPAKE/,'TT'.split(' '),'pake-transcript-name','src/pake-lab.js');
    scoped(/SSH|ssh/,'FALSE SIMPLE'.split(' '),'ssh-protocol-value','src/ssh-access-lab.js');
    for(const match of english.matchAll(/\bKC-\d{2}\b/g))local.push({value:match[0],formal:true,kind:'canonical-lesson-code',sourcePath:'src/kerberos-ad-lab.js:lesson-code'});
    scoped(/DNS|dnssec|ZONEMD|RFC\s*(?:2308|5625|9824|8914|9975|8945|9859)/,'SIMPLE DO CO FORMERR NXDOMAIN NOERROR NOTAUTH REFUSED UPDATE NOTIFY NS AXFR IXFR SEP EDE DSYNC CSYNC REVOKE AA NXNAME AAAA CNAME RR CSK DLV'.split(' ').concat(['DNSSEC OK']),'dns-record-operation-or-flag','src/dnssec-fields.js+dnssec-lookup.js');
    scoped(/SMB|smb/,'CREATE READ NEGOTIATE GCM'.split(' '),'smb-operation-or-encryption-mode','src/smb-access-lab.js');
    scoped(/NFS|nfs/,'READ CREATE LOOKUP OPEN CLOSE SEQUENCE INIT NULL DESTROY GETFH PUTFH PUTROOTFH'.split(' '),'nfs-operation-name','src/nfs-access-lab.js');
    scoped(/WebAuthn|webauthn|CTAP|FIDO/,'UP UV'.split(' '),'webauthn-flag-name','src/protocol-data.js');
    if(context.ownerId==='field:sshsssd_success_response')local.push(...['Enter','ENTER'].map(value=>({value,formal:true,kind:'keyboard-key-literal',sourcePath:'src/ssh-access-lab.js:keyboard-interactive-empty-response'})));
    scoped(/NFS|RPC|SSH|GSS|NTLM|Kerberos|linux|macos|KDC/,'MIC AS'.split(' '),'authentication-protocol-name','src/nfs-access-lab.js+kerberos-ad-lab.js+linux-logon-lab.js');
    scoped(/Windows|win-|smb|SMB|MS-NLMP/,'AUTHENTICATE CHALLENGE NEGOTIATE ESS UPPER NULL CB CBT INVALID WORKGROUPPC FILES PREAUTH ENCRYPTION SIGNING DISK ENCRYPTED ERROR CIPHER BIND ACCESS TRUE NTLMSSP NTSTATUS'.split(' '),'windows-wire-enum-or-fixture-identity','src/windows-auth-lab.js+smb-access-lab.js+smb-multichannel-lab.js');
    scoped(/nfs|NFS|RPC|RADIUS|radius|network-access/,'SYM HANDLE XDR BIND DESTROY COMPOUND QOP ACCESS FH GETATTR WRITE MNT COPY PAP CCS MHF'.split(' '),'network-protocol-encoding-operation-or-symbol','src/nfs-access-lab.js+network-access-lab.js');
    scoped(/TLS|tls|network-access/,'EE STARTTLS OCSP'.split(' '),'tls-handshake-name','src/network-access-lab.js');
    scoped(/DNS|dnssec/,'RRSET MX TXT NODATA'.split(' ').concat(['Compact Answers OK']),'dns-record-or-result-name','src/dnssec-fields.js+dnssec-resolution-cases.js');
    scoped(/SSH|ssh/,'KRL TRUE'.split(' '),'ssh-boolean-or-revocation-name','src/ssh-access-lab.js');
    scoped(/polkit|lelev|linux-elevation/,['KEEP'],'polkit-authorization-result','src/linux-elevation-lab.js');
    scoped(/OAuth|OIDC|MCP|mcp|UAS|artifact:|token/,'AT AT-D AT-front AT-back RT UAS KC'.split(' '),'authorization-actor-or-artifact-symbol','src/held-object-web.js+held-object-mcp.js');
    local.push(...['XDR','UTC','QA','NTFS','USB','CSR','RHEL','SSL','DFS','RDMA','QUIC','IOCTL','RSS','ACE','POSIX','OID','RTT','VBS','ETW','RID','LUID','KCM','GPO','LSM','SELinux','APFS','FileVault','MDM','OSS','CEL','DCR','PRM','URN','OPTIONS'].map(value=>({value,formal:true,kind:'source-audited-technical-name',sourcePath:'source-audit:realized-protocol-presenters'})));
    if(/^field:sshsssd_.*_response$/.test(context.ownerId||''))local.push(...['Enter','ENTER'].map(value=>({value,formal:true,kind:'keyboard-key-literal',sourcePath:'src/ssh-access-lab.js:keyboard-interactive-empty-response'})));
    scoped(/OAuth|OIDC|MCP|mcp-auth|CIBA|device-flow|extended-grants|protection-lab|held-object-web/,'AS AT RT KC JAR'.split(' '),'authorization-server-or-token-symbol','src/mcp-auth-lab.js+extended-grants-lab.js+held-object-web.js');
    scoped(/kerberos|KDC|PKINIT/,'AS-REP PA-PAC-REQUEST PA-PK-AS-REQ MS'.split(' '),'kerberos-message-or-reference','src/kerberos-ad-lab.js+kerberos-crypto-lab.js');
    scoped(/passkey|credentialPublicKey|authenticatorData/,'UP UV'.split(' '),'webauthn-flag-name','src/protocol-data.js');
    scoped(/ssh-access|SSSD/,'Enter ENTER CREATE'.split(' '),'keyboard-key-or-authored-operation','src/ssh-access-lab.js');
    scoped(/pake/,'MHF'.split(' '),'password-mapping-function-name','src/pake-lab.js');
    scoped(/windows|wlog|wprot|wra/,'CG LATFP'.split(' '),'windows-policy-abbreviation','src/windows-logon-lab.js+windows-remote-administration-lab.js');
    scoped(/linux|macos|Kerberos|KRB_PRIV/,'FILE READ ALL IT-Admins'.split(' '),'unix-cache-policy-or-identity-literal','src/linux-logon-lab.js+linux-elevation-lab.js');
    if(/\bSYM\/HANDLE\b|\b(?:SYM|HANDLE)\(/.test(english))local.push(...['SYM','HANDLE'].map(value=>({value,formal:true,kind:'fixture-symbolic-value-marker',sourcePath:'source-audit:symbolic-fixture-notation'})));
    local.push(...['JAR','AS-REP','WWW-Authenticate'].map(value=>({value,formal:true,kind:'formal-protocol-message-or-header',sourcePath:'src/protection-lab.js+kerberos-ad-lab.js+windows-auth-lab.js'})));
    scoped(/kubernetes|k8s/,['CREATE'],'kubernetes-admission-operation','src/kubernetes-request-model.js');
    if((/\bU[PV]\s*=\s*[01]\b/.test(english)||/\bUP\b.*\bUV\b.*\bflags\b/.test(english))&&/protocol-data/.test(context.sourceModule||''))local.push(...['UP','UV'].map(value=>({value,formal:true,kind:'webauthn-flag-assignment',sourcePath:'src/protocol-data.js:FLOWS.checks'})));
    scoped(/windows|wra|wprot|win-|SMB|NTLM/,'TARGET SSP PPL RODC VM NTOWF DCOM'.split(' ').concat(['PROTECTED$']),'windows-security-name-or-fixture-identity','src/windows-protection-lab.js+windows-remote-administration-lab.js');
    scoped(/kerberos|windows|wprot|wra/,'CNAME-IN-ADDL-TKT RENEW PA-FX-ERROR137'.split(' '),'kerberos-request-flag-or-padata-name','src/windows-protection-lab.js+windows-logon-lab.js');
    scoped(/DNS|dnssec/,'SERVFAIL OPT AD CD RCODE DELETE EPP NTA'.split(' '),'dns-protocol-or-publication-control','src/dnssec-parent-cases.js+dnssec-network-cases.js+dnssec-lab.js');
    scoped(/WebAuthn|CTAP|FIDO|passkey|YubiKey|PIN\/UV|authenticator|security key/,'UP UV NFC'.split(' '),'authenticator-flag-or-transport','src/fido-direct.js+protocol-data.js+attribute-usage.js');
    if(/Kerberos|MS-KILE|RFC\s*(?:4120|6113|4556)|PKINIT|FAST/.test(standard+' '+protocol))local.push({value:'AS',formal:true,kind:'kerberos-message-name',sourcePath:'formal-domain:kerberos'});
    if(/NFS|RPCSEC|RFC\s*(?:8881|7530|5531|2203)/.test(standard))local.push(...['SEQUENCE','OPEN','READ','CLOSE','DESTROY','INIT','NULL','GETFH','CREATE','LOOKUP','PUTFH','PUTROOTFH'].map(value=>({value,formal:true,kind:'nfs-rpc-operation',sourcePath:'formal-domain:nfs-rpc'})));
    if(/SMB|MS-NLMP/.test(standard))local.push(...['CREATE','READ','NEGOTIATE','ERROR','NULL'].map(value=>({value,formal:true,kind:'smb-ntlm-operation',sourcePath:'formal-domain:smb-ntlm'})));
    if(/DNS|RFC\s*(?:1034|1035|4033|4034|4035|6891|8914)/i.test(standard+' '+protocol)||/(?:^|[.:_-])dnssec(?:[.:_-]|$)/i.test(context.ownerId||''))local.push(...['CD','DO','OPT','RCODE','SERVFAIL'].map(value=>({value,formal:true,kind:'dns-flag-record-or-result-name',sourcePath:'formal-domain:dns'})));
    if(context.protocol==='SAML'||context.formalDomain==='saml-binding'||/\bSAML\b/.test(english)&&/\b(?:binding|profile|resolution)\b/i.test(english))local=local.concat([{value:'Artifact',formal:true,kind:'saml-binding-name',sourcePath:'formal-domain:saml-binding'}]);
    local=local.concat(FORMAL_REFERENCES,['Auth Flow Studio','Device Authorization Flow','Authorization Code','Standard V2'].map(value=>({value,formal:true,kind:'formal-product-protocol-grant-name',sourcePath:'formal-technical-name:'+value})),keyInstruction?['Enter','Tab','Escape','F2'].map(value=>({value,formal:true,kind:'keyboard-key',sourcePath:'keyboard-key:'+value})):[]);
    // These symbolic examples are code, not HTML or translatable angle-bracket
    // prose. Bind the entire observed code occurrence to its semantic source.
    const codeExamples=context.ownerId==='field:webBearerHeader'?['Bearer <access_token>']:context.ownerId==='field:protResponseMode'?['response=<signed JWT>']:context.ownerId==='field:grantCibaPushAtHash'?['BASE64URL(left-half(HASH(ASCII(access_token))))']:[];
    codeExamples.push(...[...english.matchAll(/\bHTTP\/\d\.\d \d{3} [A-Z]+(?: [A-Z]+)*|\bHTTP\d{3} OK\b|\b(?:ABCD-5678|WXYZ-1234)\b/g)].map(match=>match[0]));
    codeExamples.push(...[...english.matchAll(/\bBearer\s+<[^<>\n]+>|\b(?:request|response)=<[^<>\n]+>/g)].map(match=>match[0]));
    codeExamples.push(...[...english.matchAll(/\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) \/[A-Za-z0-9._~%!$&'()*+,;=:@/-]+/g)].map(match=>match[0].replace(/[.,;:!?]+$/,'')));
    codeExamples.push(...[...english.matchAll(/\b[A-Z]->[A-Z](?:\/[A-Z]->[A-Z])*\b/g)].map(match=>match[0]));
    if(/Kerberos|KDC|MS-KILE|kerberos|krb|wlog|wprot/.test(domain))codeExamples.push(...[...english.matchAll(/\b[A-Za-z][A-Za-z0-9_.]*\s*[<>]=?\s*endtime\s*\+\s*[A-Za-z][A-Za-z0-9_.]*/g)].map(match=>match[0]));
    if(english==='Sign(privateKey, authData || clientDataHash)'&&['src/protocol-data.js','src/attribute-usage.js','src/fido-direct.js'].includes(context.sourceModule))codeExamples.push(english);
    if(context.sourceModule==='src/kerberos-ad-lab.js'&&context.fieldPath==='attributeOperations.detail'&&['AP-REQ.ap-options.','KRB_AS_REQ req-body / padata.','PublicKeyCredentialRequestOptions: challenge/rpId/userVerification.','Sign(authenticatorData || clientDataHash).'].includes(english))codeExamples.push(english);
    if(context.fieldPath==='relatedLessons.title'&&['runas /netonly','NewCredentials / netonly'].includes(english))codeExamples.push(english);
    if(/(?:^|\.)cryptoDetail$/.test(context.fieldPath||''))codeExamples.push(...[...english.matchAll(/<[^<>\n]+>/g)].map(match=>match[0]));
    local=codeExamples.map(value=>({value,formal:true,kind:'source-bound-code-example',owner:context.ownerId,sourcePath:(context.ownerId||'source')+'.'+(context.fieldPath||'occurrence')+':'+(occurrenceSha||=sha256(english))+':code:'+sha256(value)})).concat(local);
    if(context.ui&&context.credit)local.push({value:'Kirill Andrienko',formal:true,kind:'credit-proper-name',owner:context.ownerId,sourcePath:'src/app.js:canonical-credit'});
    if(context.ui&&/\b(?:Keycloak )?Realm [AB]\b/.test(english))local.push(...['Keycloak Realm A','Keycloak Realm B','Realm A','Realm B'].map(value=>({value,formal:true,kind:'formal-realm-actor-name',sourcePath:'src/protocol-data.js:ACTORS.realm'})));
    // Official registry descriptions nested in canonical state are raw table
    // values, not explanatory prose. Keep the historical snapshot byte-exact.
    if(/^(?:protocolEffects|initialState)\..*\.registry\.(?:algorithms|dsDigests)\.\d+\.description$/.test(context.fieldPath||'')&&/dnssec/.test(context.sourceModule||''))local.unshift({value:english,formal:true,kind:'official-registry-description',owner:context.ownerId,sourcePath:'src/dnssec-fixtures.js:registry:'+(context.fieldPath||'')+':'+(occurrenceSha||=sha256(english))});
    const matches=[];
    if(!context.ui)for(const span of literalStructuredExamples(english)){
      const value=english.slice(span.start,span.end);occurrenceSha||=sha256(english);
      matches.push({...span,value,kind:'source-bound-code-example',role:'literal-structured-example',owner:context.ownerId||'technical-fragment',sourcePath:'literal-structured-example:'+(context.fieldPath||'occurrence')+':'+occurrenceSha+':'+span.start,sourceEvidence:(context.sourceModule||'canonical-source')+':'+(context.ownerId||'occurrence')+'.'+(context.fieldPath||'occurrence')});
    }
    if(!context.ui)for(const span of [...sourceIdentitySpans(english,context),...semanticOccurrenceSpans(english,context,local)]){
      const value=english.slice(span.start,span.end);occurrenceSha||=sha256(english);
      matches.push({start:span.start,end:span.end,value,kind:'source-bound-technical-identity',role:'canonical-technical-identity',owner:context.ownerId,sourcePath:'canonical-technical-identity:'+(context.fieldPath||'occurrence')+':'+occurrenceSha+':'+span.start,sourceEvidence:span.evidence});
    }
    // Lesson titles and artifact captions name concepts, not every field whose
    // display name happens to be a substring. Structured identifiers still are
    // formal references; e.g. subkey (armor Authenticator) remains one island.
    const caption=/^lesson:/.test(context.ownerId||'')&&context.fieldPath==='title'||/^artifact:/.test(context.ownerId||'')&&context.fieldPath==='label';
    const providerTitle=/^provider:/.test(context.ownerId||'')&&context.fieldPath==='title';
    for(const ref of local){
      // Chooser prose is not the raw graph actor.name. Explicit product/role
      // references below still protect brands and IdP without freezing adjectives.
      if(providerTitle&&ref.owner?.startsWith('actor:')&&ref.sourcePath===ref.owner+'.name')continue;
      if(caption&&/^(?:field-name|formal-name|typed-reference)$/.test(ref.kind||'')&&ref.owner?.startsWith('field:')&&!globallyStructuredName(ref.value))continue;
      // jwtLab05/jwtLab07 discuss issuer trust and claim validation. The
      // jwtIssuer actor's generic caption is not a proper-name field reference.
      if(context.sourceModule==='src/jwt-validation-lab.js'&&/^lesson:/.test(context.ownerId||'')&&context.fieldPath==='title'&&ref.owner==='actor:jwtIssuer'&&ref.sourcePath==='actor:jwtIssuer.name')continue;
      if(!ref.value||(!ref.formal&&!structuredName(ref.value)))continue;
      let offset=0;
      while((offset=english.indexOf(ref.value,offset))!==-1){
        const end=offset+ref.value.length,plural=(/^[A-Z][A-Z0-9]+$/.test(ref.value)||ref.value==='RRset')&&english[end]==='s'&&boundary(english,offset,end+1);
        if(boundary(english,offset,end)||plural)matches.push({start:offset,end,...ref});
        offset+=ref.value.length;
      }
    }
    for(const match of english.matchAll(TECHNICAL)){
      let value=match[0];
      if(/^(?:https?:|urn:)/.test(value)){
        value=value.replace(/[.,;:!?]+$/,'');
        while(value.endsWith(')')&&(value.match(/\)/g)||[]).length>(value.match(/\(/g)||[]).length)value=value.slice(0,-1);
      }
      if(value&&!['e.g','i.e'].includes(value))matches.push({start:match.index,end:match.index+value.length,value,kind:/^https?:/.test(value)?'url':/^RFC/.test(value)?'citation':'technical-fragment'});
    }
    // A lower/upper transition denotes a source-written identifier, unlike
    // ordinary title-case User or Client. Keep the whole identifier, never its
    // misleading uppercase prefix (for example PKAuthenticator, not PKA).
    for(const match of english.matchAll(/\b(?:[A-Z]{2,}[a-z][A-Za-z0-9]*|(?=[A-Za-z0-9]*[a-z][A-Z])[A-Za-z][A-Za-z0-9]*)\b/g)){
      matches.push({start:match.index,end:match.index+match[0].length,value:match[0],kind:'source-identifier',owner:context.ownerId||'technical-fragment',sourcePath:'source-identifier:'+(context.fieldPath||'occurrence')+':'+(occurrenceSha||=sha256(english))+':'+match.index});
    }
    // JWT claims and JOSE members are opaque, case-sensitive wire identifiers.
    // Domain evidence is mandatory; ordinary scope/use/roles/groups/nonce prose
    // deliberately does not become a global match rule.
    if(/\b(?:JWT|OIDC|OAuth|JOSE|JWK|JWKS)\b|\bID[- ]token\b|RFC\s*751[5-9]|(?:field:|src\/)(?:jwt|jwe|protection)/i.test(domain)){
      for(const match of english.matchAll(/\b(?:aud|iss|sub|exp|nbf|iat|jti|azp|acr|amr|cnf|alg|enc|kty|kid|typ|cty)\b/g)){
        if(['sub','kid'].includes(match[0])&&(english[match.index-1]==='-'||english[match.index+match[0].length]==='-'))continue;
        matches.unshift({start:match.index,end:match.index+match[0].length,value:match[0],kind:'opaque-jwt-identifier',role:'jwt-or-jose-wire-identifier',owner:context.ownerId||'technical-fragment',sourcePath:'jwt-identifier:'+(context.fieldPath||'occurrence')+':'+(occurrenceSha||=sha256(english))+':'+match.index,sourceEvidence:'src/protocol-data.js:72-78,118-119; src/jwt-validation-lab.js:36-38,252; src/jwt-policy.js:58; src/jwe-data.js:42-44; src/protection-lab.js:51,83-95'});
      }
    }
    matches.sort((a,b)=>a.start-b.start||b.end-a.end);
    const accepted=[];
    for(const match of matches){
      const previous=accepted.at(-1);if(previous&&match.start<previous.end)continue;
      if(previous&&english.slice(previous.end,match.start)==='/')accepted[accepted.length-1]={...previous,end:match.end,value:english.slice(previous.start,match.end),kind:'technical-compound',sourcePath:[previous.sourcePath,match.sourcePath].filter(Boolean).join('/'),dynamic:previous.dynamic||match.dynamic};
      else accepted.push(match);
    }
    const parameters={},protectedReferences=[];let template='',last=0;
    for(const [index,match] of accepted.entries()){
      const parameter='protected'+(index+1);
      parameters[parameter]={kind:'protected',value:match.value,...(match.role?{role:match.role}:{}),...(match.sourcePath?{sourcePath:match.sourcePath}:{}),...(match.dynamic?{dynamic:true}:{})};
      const registryId=this.add(match.kind||'typed-reference',match.value,match.owner||'technical-fragment',match.sourcePath||'occurrence',match.sourceEvidence?{evidence:match.sourceEvidence,englishSourceSha256:occurrenceSha,start:match.start,end:match.end}:{});
      protectedReferences.push({parameter,occurrences:1,start:match.start,end:match.end,registryId});
      template+=english.slice(last,match.start)+'{'+parameter+'}';last=match.end;
    }
    template+=english.slice(last);
    const residue=accepted.reduceRight((text,match)=>text.slice(0,match.start)+text.slice(match.end),english);
    const ambiguousReferences=[...english.matchAll(/\b[A-Z][A-Z0-9]{1,}(?:[+/#.-][A-Za-z0-9]+)*/g)].filter(match=>[...match[0].matchAll(/[A-Z][A-Z0-9]{1,}/g)].some(part=>!HUMAN_PROSE_UPPERCASE.has(part[0])&&!(context.ui&&HUMAN_UI_UPPERCASE.has(part[0]))&&!accepted.some(ref=>match.index+part.index>=ref.start&&match.index+part.index+part[0].length<=ref.end))).map(match=>({value:match[0],start:match.index,end:match.index+match[0].length,reason:'uppercase-needs-prose-or-technical-classification'}));
    return {parameters,protectedReferences,ambiguousReferences,template,classification:ambiguousReferences.length?'ambiguous':!/[\p{L}]/u.test(residue)?'protected-only':accepted.length?'mixed':'prose'};
  }
  toJSON(){return [...this.entries.values()].sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);}
}
