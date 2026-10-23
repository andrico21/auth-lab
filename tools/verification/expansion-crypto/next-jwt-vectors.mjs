// Isolated optional QA. No imports from app builders or runtime dependencies.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createPublicKey,verify,createDecipheriv,createCipheriv,createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {captureReviewInputs} from '../review-input-identity.mjs';
const nextJwtProject=fileURLToPath(new URL('../../../',import.meta.url));
const nextJwtInputIdentity=captureReviewInputs(nextJwtProject,fileURLToPath(import.meta.url));
const nextJwtFixtureURL=new URL('./fixtures/next-jwt-official.json',import.meta.url);
const nextJwtBytes=readFileSync(nextJwtFixtureURL),nextJwtFixture=JSON.parse(nextJwtBytes);
const nextJwtRecords=[];
function nextJwtCheck(id,fn){fn();nextJwtRecords.push({id,status:'passed'});}
const nextJwtRSA=nextJwtFixture.rsa,nextJwtParts=nextJwtRSA.compact.split('.');
const nextJwtInput=Buffer.from(nextJwtParts.slice(0,2).join('.'),'ascii'),nextJwtSignature=Buffer.from(nextJwtParts[2],'base64url');
const nextJwtPublic=createPublicKey({key:nextJwtRSA.publicJwk,format:'jwk'});
nextJwtCheck('official-rs256',()=>assert.equal(verify('RSA-SHA256',nextJwtInput,nextJwtPublic,nextJwtSignature),true));
nextJwtCheck('payload-byte',()=>{const bytes=Buffer.from(nextJwtInput);bytes[30]^=1;assert.equal(verify('RSA-SHA256',bytes,nextJwtPublic,nextJwtSignature),false);});
nextJwtCheck('signature-byte',()=>{const bytes=Buffer.from(nextJwtSignature);bytes[0]^=1;assert.equal(verify('RSA-SHA256',nextJwtInput,nextJwtPublic,bytes),false);});
nextJwtCheck('wrong-rsa-key',()=>{const wrong=createPublicKey({key:{...nextJwtRSA.publicJwk,e:'Aw'},format:'jwk'});assert.equal(verify('RSA-SHA256',nextJwtInput,wrong,nextJwtSignature),false);});
const nextJwtGCM=Object.fromEntries(Object.entries(nextJwtFixture.gcm).map(([key,value])=>[key,Buffer.from(value,'hex')]));
function nextJwtDecrypt({key=nextJwtGCM.key,tag=nextJwtGCM.tag,aad=nextJwtGCM.aad,ciphertext=nextJwtGCM.ciphertext}={}) {
  // Do not publish update() output before final() authenticates all input.
  try{const d=createDecipheriv('aes-128-gcm',key,nextJwtGCM.iv);d.setAAD(aad);d.setAuthTag(tag);const pending=d.update(ciphertext),end=d.final();return Buffer.concat([pending,end]);}catch{return null;}
}
nextJwtCheck('official-gcm-encrypt',()=>{const c=createCipheriv('aes-128-gcm',nextJwtGCM.key,nextJwtGCM.iv);c.setAAD(nextJwtGCM.aad);assert.deepEqual(Buffer.concat([c.update(nextJwtGCM.plaintext),c.final()]),nextJwtGCM.ciphertext);assert.deepEqual(c.getAuthTag(),nextJwtGCM.tag);});
nextJwtCheck('official-gcm-decrypt',()=>assert.deepEqual(nextJwtDecrypt(),nextJwtGCM.plaintext));
nextJwtCheck('wrong-recipient-key',()=>{const key=Buffer.from(nextJwtGCM.key);key[0]^=1;assert.equal(nextJwtDecrypt({key}),null);});
nextJwtCheck('changed-tag',()=>{const tag=Buffer.from(nextJwtGCM.tag);tag[0]^=1;assert.equal(nextJwtDecrypt({tag}),null);});
nextJwtCheck('wrong-aad-context',()=>assert.equal(nextJwtDecrypt({aad:Buffer.from('other audience context')}),null));
assert.deepEqual(captureReviewInputs(nextJwtProject,fileURLToPath(import.meta.url)),nextJwtInputIdentity,'Review input bytes unchanged during numeric execution');
console.log(JSON.stringify({schemaVersion:1,suite:'next-jwt-official',oracle:'Native node:crypto provider, independent of app builder',runtime:process.versions,argv:[...process.argv],inputIdentity:nextJwtInputIdentity,identityContext:'Review byte identity only; numerical claims remain limited to these independent vector checks.',sourceUnchanged:true,status:'passed',exitCode:0,fixtureSha256:createHash('sha256').update(nextJwtBytes).digest('hex'),records:nextJwtRecords,limits:nextJwtFixture.claims.notNumerical},null,2));
