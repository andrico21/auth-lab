import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {SOURCE_CSP, normalizeHtmlLines, standaloneCsp, cspMeta} from './security-policy.mjs';
const root=path.dirname(fileURLToPath(import.meta.url));
const readSource = file => normalizeHtmlLines(fs.readFileSync(path.join(root,file),'utf8'));
// Windows fixture authoring composes the accepted Kerberos inventory eagerly.
const modules=['protocol-data.js','single-realm.js','architecture-variants.js','attribute-usage.js','fido-direct.js','saml-data.js','service-account-data.js','device-flow-data.js','ciba-data.js','token-exchange-data.js','jwe-data.js','lab-common.js','web-api-lab.js','lifecycle-lab.js','protection-lab.js','extended-grants-lab.js','saml-advanced-lab.js','branching-lab.js','kerberos-context.js','kerberos-ad-lab.js','kerberos-crypto-lab.js','kerberos-forest-lab.js','ssh-access-lab.js','windows-auth-lab.js','smb-access-lab.js','smb-multichannel-lab.js','network-access-lab.js','kerberos-spake-lab.js','pake-lab.js','held-object-authoring.js','held-object-kerberos.js','nfs-access-lab.js','windows-logon-lab.js','windows-elevation-lab.js','linux-logon-lab.js','linux-elevation-lab.js','macos-logon-lab.js','macos-elevation-lab.js','jwt-policy.js','jwt-validation-lab.js','kubernetes-fixtures.js','kubernetes-case-data.js','kubernetes-request-model.js','kubernetes-auth-lab.js','kubernetes-rbac-lab.js','mcp-auth-lab.js', 'dnssec-addendum-fixtures.js', 'dnssec-completion-fixtures.js', 'dnssec-review-fixtures.js', 'dnssec-signature-fingerprints.js', 'dnssec-fixtures.js', 'dnssec-fields.js','dnssec-lessons.js','dnssec-validation.js','dnssec-authoring.js', 'dnssec-lookup.js', 'dnssec-denial.js', 'dnssec-publication.js', 'dnssec-parent-automation.js', 'dnssec-resolution-cases.js', 'dnssec-network-cases.js', 'dnssec-denial-cases.js', 'dnssec-signing-cases.js', 'dnssec-anchor-cases.js', 'dnssec-parent-cases.js', 'dnssec-zone-publication-cases.js', 'dnssec-lab.js', 'lab-catalog.js','attribute-trace.js','actor-art.js','player.js','layout.js','step-overlay-layout.js','scenario-picker.js','focus-target.js','learning-presets.js','runtime-environment.js','workspaces.js','scenario-context.js','protocol-state.js','held-object-state.js','held-object-ad.js','held-object-ssh.js','held-object-protection.js','held-object-web.js','held-object-core.js','held-object-windows.js','held-object-smb.js','held-object-network.js','held-object-spake.js','held-object-pake.js','held-object-nfs.js','held-object-windows-workstation.js','held-object-unix-workstation.js','held-object-jwt.js','held-object-kubernetes.js','held-object-mcp.js','held-object-dnssec.js','held-objects.js','held-object-view.js','app.js'];
const source=modules.map(name=>{
  const input=readSource(path.join('src',name));
  const body=input.replace(/^import .*?;\s*$/gm,'').replace(/\bexport (?=(?:const|let|class|function)\b)/g,'');
  if(!name.startsWith('held-'))return body;
  // The inventory modules retain module-private names in the offline bundle.
  // Explicit exports are the only bindings shared with subsequent modules.
  const names=[...input.matchAll(/^export\s+(?:const|let|class|function)\s+([A-Za-z_$][\w$]*)/gm)].map(match=>match[1]);
  return 'const {'+names.join(',')+'}=(()=>{\n'+body+'\nreturn {'+names.join(',')+'};\n})();';
}).join('\n\n');
const css=readSource('src/styles.css');
const script='\n(()=>{\n'+source.replace(/<\/script/gi,'<\\/script')+'\n})();\n';
const template=readSource('index.html');
const versionMarkers=[...template.matchAll(/\bdata-build-version="([^"]*)"/g)];
if(versionMarkers.length!==1)throw new Error('index.html must contain exactly one build version marker.');
const requestedVersion=process.argv.includes('--source-version')?versionMarkers[0][1]:(process.env.AUTH_FLOW_STUDIO_VERSION??(process.env.GITHUB_REF_TYPE==='tag'?process.env.GITHUB_REF_NAME:undefined)??versionMarkers[0][1]);
const buildVersion=String(requestedVersion).trim().replace(/^v(?=\d)/,'');
if(!buildVersion)throw new Error('The compiled display version must not be empty.');
const encodedBuildVersion=buildVersion.replace(/[&"<>]/g,character=>({'&':'&amp;','"':'&quot;','<':'&lt;','>':'&gt;'}[character]));
const sourceMeta=cspMeta(SOURCE_CSP);
const styleTag='<link rel="stylesheet" href="src/styles.css">';
const scriptTag='<script type="module" src="src/app.js"></script>';
if(template.split(sourceMeta).length!==2||[...template.matchAll(/http-equiv=["']Content-Security-Policy["']/gi)].length!==1){
  throw new Error('index.html must contain exactly one current source CSP meta element.');
}
const metaAt=template.indexOf(sourceMeta),headAt=template.indexOf('<head>'),headEnd=template.indexOf('</head>');
const firstAsset=template.search(/<(?:script|style|link|base|img|iframe|object|embed)\b/i);
if(headAt<0||headEnd<0||metaAt<headAt||metaAt>headEnd||firstAsset>=0&&metaAt>firstAsset){
  throw new Error('The source CSP must be inside head, before every executable or resource element.');
}
if(template.split(styleTag).length!==2||template.split(scriptTag).length!==2){
  throw new Error('The CSP build requires exactly one stylesheet and one module script placeholder.');
}
let html=template
  .replace(versionMarkers[0][0],()=>'data-build-version="'+encodedBuildVersion+'"')
  .replace(sourceMeta,()=>cspMeta(standaloneCsp(script,css)))
  .replace(styleTag,()=>'<style>'+css+'</style>')
  .replace(scriptTag,()=>'<script>'+script+'</script>');
for(const [file,type] of [['assets/favicon.ico','image/x-icon'],['assets/favicon.svg','image/svg+xml'],['assets/apple-touch-icon.png','image/png']]){
  const placeholder='href="'+file+'"';
  if(html.split(placeholder).length!==2)throw new Error('The CSP build requires exactly one favicon placeholder for '+file+'.');
  const encoded=fs.readFileSync(path.join(root,file)).toString('base64');
  html=html.replace(placeholder,()=>'href="data:'+type+';base64,'+encoded+'"');
}
fs.mkdirSync(path.join(root,'dist'),{recursive:true});
fs.writeFileSync(path.join(root,'dist','auth-flow-studio.html'),html);
console.log('Built dist/auth-flow-studio.html ('+Buffer.byteLength(html)+' bytes)');
