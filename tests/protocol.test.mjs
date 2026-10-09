import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createHmac} from 'node:crypto';
import {ACTORS,ATTRIBUTES,EXAMPLE,FLOWS} from '../src/protocol-data.js';

const loginFlows=['login','totpLogin','passkeyTotpLogin'];
const value=(step,name)=>step.payload.find(p=>p.name===name)?.value;

test('all journeys have valid actors, glossary references, and distinct ordered steps',()=>{
  assert.equal(Object.keys(ACTORS).length,8);
  for(const [name,steps] of Object.entries(FLOWS)){
    assert.equal(new Set(steps.map(s=>s.id)).size,steps.length,name);
    for(const s of steps){
      for(const actor of [s.from,s.to])assert.ok(actor==='authenticator'||ACTORS[actor],s.id+' actor '+actor);
      assert.ok(s.title&&s.summary&&s.detail&&s.payload.length,s.id);
      for(const id of s.fields)assert.ok(ATTRIBUTES[id],s.id+' missing '+id);
    }
  }
  for(const actor of Object.values(ACTORS))for(const a of actor.attributes)assert.ok(ATTRIBUTES[a.id],actor.id+' missing '+a.id);
  for(const [id,a] of Object.entries(ATTRIBUTES))for(const field of ['name','meaning','origin','purpose','example','standard','source'])assert.ok(a[field],id+' missing '+field);
});

test('displayed native S256 PKCE pair matches RFC 7636 and the verifier stays off redirects',()=>{
  assert.equal(createHash('sha256').update(EXAMPLE.verifier,'ascii').digest('base64url'),EXAMPLE.challenge);
  assert.match(EXAMPLE.verifier,/^[A-Za-z0-9._~-]{43,128}$/);
  for(const name of loginFlows){
    const steps=FLOWS[name];
    const exchange=steps.find(s=>s.from==='app'&&s.to==='realmA'&&s.channel==='backchannel');
    assert.ok(exchange,name+' native exchange');
    assert.equal(value(exchange,'code_verifier'),EXAMPLE.verifier);
    assert.equal(value(exchange,'code'),EXAMPLE.codeA);
    assert.equal(value(exchange,'redirect_uri'),EXAMPLE.appCallback);
    assert.equal(value(exchange,'client_secret'),undefined);
    for(const s of steps.filter(s=>s.channel==='redirect'||s.to==='browser'))assert.equal(value(s,'code_verifier'),undefined,s.id);
  }
});

test('browser delivers both independent codes; realms exchange their own tokens directly',()=>{
  for(const name of loginFlows){
    const steps=FLOWS[name];
    const upstream=steps.find(s=>s.from==='browser'&&s.to==='realmA'&&value(s,'code'));
    const callback=steps.find(s=>s.from==='browser'&&s.to==='app'&&value(s,'code'));
    assert.equal(value(upstream,'code'),EXAMPLE.codeB);assert.equal(value(upstream,'state'),EXAMPLE.stateBroker);
    assert.equal(value(callback,'code'),EXAMPLE.codeA);assert.equal(value(callback,'state'),EXAMPLE.stateApp);
    assert.notEqual(EXAMPLE.codeA,EXAMPLE.codeB);assert.notEqual(EXAMPLE.stateApp,EXAMPLE.stateBroker);assert.notEqual(EXAMPLE.nonceApp,EXAMPLE.nonceBroker);
    const bTokens=steps.find(s=>s.from==='realmB'&&s.to==='realmA'&&value(s,'id_token'));
    const aTokens=steps.find(s=>s.from==='realmA'&&s.to==='app'&&value(s,'id_token'));
    assert.equal(value(bTokens,'iss'),EXAMPLE.issuerB);assert.equal(value(bTokens,'aud'),EXAMPLE.clientBroker);
    assert.equal(value(aTokens,'iss'),EXAMPLE.issuerA);assert.equal(value(aTokens,'aud'),EXAMPLE.clientApp);
    for(const tokenStep of [bTokens,aTokens])for(const claim of ['iss','aud','sub','nonce'])assert.match(tokenStep.payload.find(p=>p.name===claim).description,/claim.*id[ _]token|id[ _]token.*claim/i);
    const broker=steps.find(s=>s.from==='realmA'&&s.to==='realmB'&&value(s,'grant_type'));
    assert.ok(value(broker,'Authorization').startsWith('Basic '));
  }
});

test('credential private keys never appear as transmitted registration or assertion data',()=>{
  for(const steps of Object.values(FLOWS))for(const s of steps.filter(s=>s.from!==s.to)){
    assert.equal(s.payload.some(p=>/^(privateKey|Private credential source|Stored privately in authenticator)$/.test(p.name)),false,s.id);
  }
  assert.equal(EXAMPLE.rpId,new URL(EXAMPLE.origin).hostname);
  assert.equal(new URL(EXAMPLE.origin).protocol,'https:');
  assert.ok(FLOWS.login.find(s=>s.from==='browser'&&s.to==='realmB'&&s.fields.includes('signature')));
});

function decodeBase32(input){
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';
  for(const c of input.replace(/=+$/,''))bits+=alphabet.indexOf(c).toString(2).padStart(5,'0');
  return Buffer.from(bits.match(/.{8}/g).map(b=>parseInt(b,2)));
}
function totp(key,time,digits=6){
  const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(time/30)));
  const digest=createHmac('sha1',key).update(counter).digest();const offset=digest.at(-1)&15;
  return ((digest.readUInt32BE(offset)&0x7fffffff)%10**digits).toString().padStart(digits,'0');
}

test('public TOTP provisioning example computes the code shown in both journeys',()=>{
  const provisioning=FLOWS.totpEnrollment.find(s=>value(s,'Provisioning URI (de facto)'));
  const uri=new URL(value(provisioning,'Provisioning URI (de facto)'));
  const secret=decodeBase32(uri.searchParams.get('secret'));
  assert.equal(secret.toString('ascii'),'12345678901234567890');
  assert.equal(uri.searchParams.get('digits'),'6');assert.equal(uri.searchParams.get('period'),'30');
  assert.equal(totp(secret,59,8),'94287082'); // RFC 6238 Appendix B.
  assert.equal(totp(secret,59),'287082');
  for(const name of ['totpLogin','passkeyTotpLogin']){
    const input=FLOWS[name].find(s=>s.from==='browser'&&s.to==='realmB'&&value(s,'otp'));
    assert.equal(value(input,'otp'),totp(secret,59));
    for(const s of FLOWS[name].filter(s=>s.from!==s.to))assert.equal(s.payload.some(p=>String(p.value).includes(uri.searchParams.get('secret'))),false,s.id+' discloses TOTP seed during sign-in');
  }
});

test('MFA is completed in Realm B before a broker authorization code is issued',()=>{
  for(const name of ['totpLogin','passkeyTotpLogin']){
    const steps=FLOWS[name];
    const verify=steps.findIndex(s=>s.from==='realmB'&&s.to==='realmB'&&s.phase==='mfa');
    const issue=steps.findIndex(s=>s.from==='realmB'&&s.to==='browser'&&s.phase==='return');
    assert.ok(verify>=0&&issue>verify,name);
    assert.equal(steps.some(s=>s.to==='app'&&s.fields.includes('otpCode')),false);
  }
  const passkeyCheck=FLOWS.passkeyTotpLogin.find(s=>s.from==='realmB'&&s.to==='realmB'&&s.phase==='passkey');
  assert.match(passkeyCheck.detail,/TOTP|OTP/);
  assert.doesNotMatch(passkeyCheck.detail,/successful check completes authentication/);
});
