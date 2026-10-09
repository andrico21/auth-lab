// Bounded input contract for the lab's fixed single-realm reference fixtures.
// This character/length restriction is a teaching-app contract, not a claim
// that RFC 4120 limits all Kerberos realm or principal representations this way.
export const KERBEROS_LAB_REALM_MAX_LENGTH = 254;
const kerberosLabRealmPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$/;
const kerberosLabText = value => value == null ? '' : String(value).trim();
const kerberosLabError = (field,message) => Object.assign(new TypeError(message),{field});

export function validateKerberosRealm(value) {
  const realm=kerberosLabText(value);
  return !realm||kerberosLabRealmPattern.test(realm)?'':'This lab accepts a Kerberos realm of 1-254 letters, digits, dots, underscores or hyphens, starting with a letter or digit (for example CORP.EXAMPLE).';
}

function kerberosLabServiceIdentity(value,realm) {
  const principal=kerberosLabText(value);
  if(!principal||principal.length>2048||/[\u0000-\u001f\u007f\\]/.test(principal)||!/^[^\s/@]+\/[^\s@]+(?:@[^\s@]+)?$/.test(principal))throw kerberosLabError('servicePrincipal','Use a lab service principal such as HTTP/server.corp.example or HTTP/server.corp.example@CORP.EXAMPLE. Escaped principal names are outside this lab input contract.');
  const [name,qualifier]=principal.split('@');
  if(qualifier&&qualifier!==realm)throw kerberosLabError('servicePrincipal','The service realm qualifier must match the account Kerberos realm ('+realm+'). Use the separate cross-realm lessons for a service in another realm.');
  return Object.freeze({name,realm,qualifiedPrincipal:name+'@'+realm});
}

export function validateKerberosServicePrincipal(value,realmValue='') {
  if(!kerberosLabText(value))return '';
  const realm=kerberosLabText(realmValue)||'A.EXAMPLE';
  // The realm input owns its validation message; avoid duplicating it on SPN.
  if(validateKerberosRealm(realm))return '';
  try{kerberosLabServiceIdentity(value,realm);return '';}catch(error){return error.message;}
}

export function resolveKerberosContext(input={},defaultServicePrincipal='cifs/files.a.example') {
  const realm=kerberosLabText(input.kerberosRealm)||'A.EXAMPLE';
  const error=validateKerberosRealm(realm);
  if(error)throw kerberosLabError('kerberosRealm',error);
  const serviceIdentity=kerberosLabServiceIdentity(kerberosLabText(input.servicePrincipal)||defaultServicePrincipal,realm);
  return Object.freeze({realm,servicePrincipal:serviceIdentity.name,serviceRealm:serviceIdentity.realm,serviceIdentity});
}
