// Explicit navigation metadata only. Opening a lesson starts its own demonstration.
// No model construction, credential handoff or session transfer occurs here.
const wscLesson=(id,title,summary,variantId)=>Object.freeze({id,title,summary,...(variantId?{variantId}:{})});
const wscTargets=Object.freeze({
  elevation:wscLesson('lab-welev01','Administrator membership and tokens','Compare administrator membership with the effective local process token.'),
  consent:wscLesson('lab-welev02','Same-admin consent elevation','Consent creates a new local process context; it does not set a remote network token.'),
  credentials:wscLesson('lab-welev03','Alternate-admin credential elevation','A different administrator identity supplies the elevated local process context.'),
  runas:wscLesson('lab-welev04','Ordinary runas','Compare the local process identity with independent outbound authentication.'),
  netonly:wscLesson('lab-welev05','runas /netonly','Retain local process identity while separately validating outbound domain credentials.'),
  apLocal:wscLesson('lab-welev06','Administrator Protection: local architecture','Separate local elevation architecture with declared source/build applicability, not a universal default.'),
  localAdmin:wscLesson('lab-wra01','Correct admin password, ADMIN$ denied','Target-local SAM authentication succeeds; target network-logon filtering and resource permission are separate.'),
  rid500:wscLesson('lab-wra02','Built-in Administrator and RID500 policy','Identify the built-in local account by SID/RID, not its display name, under the selected policy profile.'),
  domain:wscLesson('lab-wra03','Domain account from joined or nonjoined PC','Account authority, not client join state or client elevation, determines domain credential verification.'),
  gates:wscLesson('lab-wra04','Locate the remote denial','Distinguish proof, logon admission, endpoint permission, share permission and file access.'),
  apRemote:wscLesson('lab-wra05','Administrator Protection: remote domain policy','Inspect the build-qualified remote elevation policy; unsupported profiles remain explicitly unavailable.'),
  cg:wscLesson('lab-wprot01','Credential Guard: custody and operations','Isolated credential custody permits selected operations; it does not grant file permission or select RCG.'),
  tgt:wscLesson('lab-wlog02','Domain sign-in and protected TGT operations','Follow real protected TGT custody and permitted isolated operations during domain sign-in.'),
  ppl:wscLesson('lab-wprot02','LSA protection / RunAsPPL','Process-access and plugin-loading protection is a different boundary from Credential Guard isolation.'),
  pu:wscLesson('lab-wprot03','Protected Users restrictions','Compare client credential restrictions, protocol/delegation restrictions and DC issuance decisions.'),
  offline:wscLesson('lab-wlog04','Protected User: offline cached sign-in denied','Open the protected-user case, not normal cached sign-in; no cached credential is transferred.','protected-user'),
  policy:wscLesson('lab-wprot04','Authentication policy: allowed device and AS issuance','Evaluate device/armor evidence and enforced versus audited policy before issuing a TGT.'),
  silo:wscLesson('lab-wprot05','Silos, effective policy and service tickets','Separate silo membership, policy provenance and target service-ticket admission from resource ACLs.'),
  pkinit:wscLesson('lab-wlog05','Smart-card sign-in and PKINIT','Follow the existing certificate proof and reply-key continuation.'),
  fast:wscLesson('lab-wlog06','FAST-protected sign-in','Follow the existing armor and protected authentication continuation.'),
  workgroup:wscLesson('lab-wlog08','Workgroup desktop and domain network credentials','Keep the local desktop identity distinct from explicit domain credentials for network access.'),
  normal:wscLesson('lab-win-rdp-normal','Ordinary RDP: delegated credentials','Credentials reach the remote host; downstream operations can authenticate as the user.'),
  restricted:wscLesson('lab-win-rdp-restricted-admin','RDP Restricted Admin: downstream host identity','User credentials are not delegated; downstream access uses the remote host identity, not the user.'),
  rcg:wscLesson('lab-win-rdp-remote-credential-guard','RDP Remote Credential Guard: client-backed user operations','Kerberos operations are redirected to the client for downstream user access; required RCG has no NTLM fallback. Client Credential Guard alone does not select this mode, and the session can still exercise permitted user authority.'),
  rcgUnavailable:wscLesson('lab-win-rdp-rcg-kerberos-unavailable','Required RCG: Kerberos unavailable','Required RCG fails without Kerberos; it does not silently fall back to NTLM or ordinary credential delegation.'),
  modeUnsupported:wscLesson('lab-win-rdp-required-mode-unsupported','Required RDP protection mode unsupported','A required unsupported protection mode fails rather than silently delegating credentials.'),
  secondHop:wscLesson('lab-win-winrm-second-hop-denied','WinRM: first hop accepted, second hop denied','First-hop authorization does not imply reusable second-hop credentials.'),
});
const wscRow=(mechanism,boundary,keys)=>Object.freeze({mechanism,boundary,targets:Object.freeze(keys.map(key=>wscTargets[key]))});
export const WINDOWS_SECURITY_COMPARISONS=Object.freeze([
  wscRow('Classic local elevation','New local process context after consent or credentials',['elevation','consent','credentials']),
  wscRow('Remote token filtering','Target network-logon authorization context, separate from proof and resource permission',['localAdmin','rid500','domain','gates']),
  wscRow('Administrator Protection','Separate local elevation architecture and build-specific remote policy',['apLocal','apRemote']),
  wscRow('Credential Guard','Isolated credential custody and allowed operations, not RCG mode selection',['cg','tgt']),
  wscRow('LSA protection','Process access and plugin loading, not isolated credential custody',['ppl']),
  wscRow('Protected Users / policies','Client credential restrictions and DC issuance decisions',['pu','policy','silo']),
  wscRow('Ordinary RDP / Restricted Admin / RCG','Delegated credentials versus downstream host identity versus client-backed user operations; required RCG needs Kerberos with no NTLM fallback',['normal','restricted','rcg']),
]);
const wscRelated=Object.freeze({
  'lab-welev01':['localAdmin','consent','credentials','apLocal'],
  'lab-welev02':['localAdmin','elevation','apLocal'],
  'lab-welev03':['localAdmin','domain','runas'],
  'lab-welev04':['netonly','workgroup','domain'],
  'lab-welev05':['workgroup','domain','secondHop'],
  'lab-welev06':['apRemote','localAdmin','cg'],
  'lab-wlog01':['localAdmin','elevation'],
  'lab-wlog02':['cg','pu','policy'],
  'lab-wlog03':['localAdmin','rid500'],
  'lab-wlog04':['offline','pu'],
  'lab-wlog05':['cg','pu','policy'],
  'lab-wlog06':['policy','silo','cg'],
  'lab-wlog07':['cg','localAdmin'],
  'lab-wlog08':['domain','netonly','secondHop'],
  'lab-wra01':['gates','rid500','domain','elevation','netonly'],
  'lab-wra02':['localAdmin','apRemote','elevation'],
  'lab-wra03':['localAdmin','workgroup','netonly','apRemote'],
  'lab-wra04':['localAdmin','secondHop','normal'],
  'lab-wra05':['apLocal','domain','localAdmin'],
  'lab-wprot01':['tgt','ppl','normal','restricted','rcg'],
  'lab-wprot02':['cg','pu'],
  'lab-wprot03':['offline','policy','silo','cg','pkinit'],
  'lab-wprot04':['fast','pu','silo'],
  'lab-wprot05':['policy','pu','gates'],
  'lab-win-rdp-normal':['restricted','rcg','cg'],
  'lab-win-rdp-restricted-admin':['normal','rcg','modeUnsupported'],
  'lab-win-rdp-remote-credential-guard':['normal','restricted','rcgUnavailable','modeUnsupported','cg'],
  'lab-win-rdp-rcg-kerberos-unavailable':['rcg','modeUnsupported'],
  'lab-win-rdp-required-mode-unsupported':['rcg','restricted'],
  'lab-win-winrm-second-hop-denied':['gates','netonly','rcg'],
  'lab-smb-nonjoined-kerberos':['domain','localAdmin','workgroup'],
  'lab-smb-nonjoined-ntlm':['domain','localAdmin','workgroup'],
});
const wscEmpty=Object.freeze([]);
const wscResolvedRelated=Object.freeze(Object.fromEntries(Object.entries(wscRelated).map(([id,keys])=>[id,Object.freeze(keys.map(key=>wscTargets[key]))])));
/** Static destinations are validated against the actual catalog by the caller. */
export function windowsSecurityRelatedLessons(modelId){
  return Object.hasOwn(wscResolvedRelated,modelId)?wscResolvedRelated[modelId]:wscEmpty;
}
