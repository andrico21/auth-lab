import test from 'node:test';
import assert from 'node:assert/strict';
import {NFSLAB_CASE,NFSLAB_SCENARIOS} from '../src/nfs-access-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {buildNFSHeldObjects} from '../src/held-object-nfs.js';
import {compileHeldObjects,projectHeldObjects} from '../src/held-object-state.js';

const successfulOpenCases={
  NFS01:['default','corrupt-result'],
  NFS02:['default','krb5','krb5i','alter-krb5-argument','alter-integrity-body','alter-privacy-ciphertext','repeat-gss-sequence'],
  NFS05:['default','auth-sys','expired-state'],
  NFS06:['default'],
  NFS07:['default','secinfo-no-name'],
  NFS08:['default','display-map-failed','numeric-collision'],
  NFS09:['default'],
  NFS10:['default','replayed-gss','session-retry','connection-failed'],
  NFS11:['default','tls-only','forged-uid','corrupt-application-record'],
  NFS13:['default'],
};
const alertCases=[
  ['NFS11','missing-client-certificate','tls-client-verify'],
  ['NFS11','host-unauthorized','tls-host-policy'],
  ['NFS12','missing-client-identity','tls-client-verify'],
  ['NFS12','invalid-client-identity','tls-client-verify'],
  ['NFS12','revoked-client','tls-client-verify'],
  ['NFS11','corrupt-application-record','rpc-decrypt'],
];
function fixture(code,variant='default'){
  const model=NFSLAB_CASE(code,variant),steps=model.steps();
  const plan=buildNFSHeldObjects({model,steps,actors:model.actors(),config:{},contextId:model.id+':'+variant,choiceId:model.id});
  const compiled=compileHeldObjects(plan,{model,steps});
  const index=stage=>{const i=steps.findIndex(s=>s.nfsStage===stage);assert.notEqual(i,-1,code+'/'+variant+'/'+stage);return i;};
  const id=key=>model.id+':'+variant+':'+key;
  const frameAt=i=>projectHeldObjects(compiled,{eventIndex:i,milestone:i<0?'initial':'complete'});
  const has=(i,key,actor='nfsClient',rep='plain')=>frameAt(i).holdings.some(h=>h.artifactId===id(key)&&h.actorId===actor&&h.representationId===rep);
  const state=stage=>reconstructProtocolState(model,index(stage)).nfs;
  return {model,steps,plan,index,id,has,state,step:stage=>steps[index(stage)],artifact:key=>plan.artifacts.find(a=>a.artifactId===id(key)),end:()=>reconstructProtocolState(model,steps.length-1).nfs};
}
const uses=(f,stage,key,actor)=>f.step(stage).attributeOperations.some(op=>op.instanceId===f.id(key)&&op.actorId===actor&&op.kind==='use');

test('P6-NFS-01 enumerates all 28 successful OPEN compounds and independent result provenance',()=>{
  let count=0;
  for(const model of NFSLAB_SCENARIOS)for(const choice of model.variantChoices){
    const variant=model.withVariant(choice.id),code=variant.initialState.nfs.planId;
    const expected=(successfulOpenCases[code]||[]).includes(choice.id);
    assert.equal(variant.steps().some(s=>s.nfsStage==='open-response'),expected,code+'/'+choice.id+' success inventory');
  }
  for(const [code,variants] of Object.entries(successfulOpenCases))for(const variant of variants){
    count++;const f=fixture(code,variant);
    const expected=code==='NFS05'?['PUTROOTFH','LOOKUP','OPEN','GETFH']:code==='NFS07'?['SEQUENCE','PUTFH','LOOKUP','OPEN','GETFH']:['SEQUENCE','PUTROOTFH','LOOKUP','OPEN','GETFH'];
    assert.deepEqual(f.step('namespace-open').nfsFrame.operations,expected,code+'/'+variant);
    assert.match(f.artifact('namespace').value,/OPEN report\.txt; GETFH/);
    const results=f.step('open-response').nfsFrame.operationResults;
    assert.deepEqual(results,[
      {operation:'OPEN',stateid:'HANDLE(open-stateid generation1; share_access READ; '+(code==='NFS05'?'OPEN4_RESULT_CONFIRM set':'no OPEN_CONFIRM in v4.1 base')+')',artifactId:f.id('stateid')},
      {operation:'GETFH',filehandle:'HANDLE(report.txt on /reports; not a bearer access grant)',artifactId:f.id('filehandle')},
    ]);
    assert.equal(f.state('open-server').serverCurrentFilehandle,'HANDLE(report.txt on /reports; not a bearer access grant)');
    assert.equal(f.has(f.index('open-server'),'filehandle','nfsServer'),false,'OPEN does not create a wire filehandle result');
    assert.equal(f.has(f.index('getfh-server'),'filehandle','nfsServer'),true);
    assert.ok(f.index('open-server')<f.index('getfh-server'));
    for(let i=-1;i<=f.index('open-response');i++)assert.equal(f.has(i,'filehandle'),false,code+'/'+variant+' premature accepted client handle at '+i);
    const rep=f.model.fixtureInputs.sec==='krb5p'||f.model.fixtureInputs.xprtsec!=='none'?'rpc-wire':'rpc-untrusted';
    assert.equal(f.has(f.index('open-response'),'filehandle','nfsClient',rep),true);
    assert.equal(f.has(f.index('open-response-verify'),'filehandle'),true);
    assert.equal(f.state('open-response').currentFilehandle,null);
    assert.equal(f.state('open-accept').currentFilehandle,'HANDLE(report.txt on /reports; not a bearer access grant)');
    const creation=f.steps.flatMap(s=>s.attributeOperations).filter(op=>op.instanceId===f.id('filehandle')&&op.kind==='create');
    assert.equal(creation.length,1);assert.equal(creation[0].sourceEventId,f.id('getfh-server'));
    if(code==='NFS05'){
      assert.ok(f.index('open-accept')<f.index('open-confirm-create'));
      assert.equal(uses(f,'open-confirm-create','filehandle','nfsClient'),true);
      assert.equal(uses(f,'open-confirm-create','stateid','nfsClient'),true);
      assert.match(f.artifact('open-confirm').value,/PUTFH\(HANDLE\(report\.txt on \/reports; not a bearer access grant\)\)/);
      assert.deepEqual(f.step('open-confirm').nfsFrame.operations,['PUTFH','OPEN_CONFIRM']);
      assert.equal(f.step('open-confirm').nfsFrame.filehandleSource,f.id('filehandle'));
      assert.equal(f.state('open-confirm-accept').openConfirmed,true);
    }
  }
  assert.equal(count,28);
});

test('P6-NFS-01 preserves consumed SECINFO CURRENT_FH and v3 LOOKUP provenance',()=>{
  for(const variant of ['default','secinfo-no-name']){
    const f=fixture('NFS07',variant);
    assert.equal(f.state('secinfo-server').currentFilehandle,null);
    assert.deepEqual(f.step('namespace-open').nfsFrame.operations,['SEQUENCE','PUTFH','LOOKUP','OPEN','GETFH']);
    assert.equal(f.step('namespace-open').nfsFrame.slotSequence,3);
  }
  const failed=fixture('NFS07','consumed-filehandle');
  assert.equal(failed.end().firstDetector,'secinfo-structure');
  assert.equal(failed.steps.some(s=>s.nfsStage==='namespace-open'),false);
  for(const code of ['NFS03','NFS04']){
    const f=fixture(code);assert.deepEqual(f.step('v3-lookup').nfsFrame.operations,['LOOKUP']);
    assert.equal(f.steps.some(s=>(s.nfsFrame?.operations||[]).includes('GETFH')),false);
    assert.ok(f.step('v3-lookup-server').attributeOperations.some(op=>op.instanceId===f.id('filehandle')&&op.kind==='create'));
  }
});

test('P6-NFS-02 six encrypted alert paths use independently derived directional copies and dispose them',()=>{
  for(const [code,variant,detector] of alertCases){
    const f=fixture(code,variant),creation=detector+'-failure-create',receipt=detector+'-failure-wire',accept=detector+'-failure-accept';
    for(const [actor,side] of [['nfsServer','server'],['nfsClient','client']]){
      const master='tls-master-'+side,derive='tls-'+side+'-app-derive';
      assert.ok(f.index('tls-server-sign')<f.index('tls-'+side+'-master-derive'));
      assert.ok(f.index('tls-'+side+'-master-derive')<f.index(derive));
      assert.ok(f.index(derive)<f.index(creation));
      assert.equal(uses(f,derive,master,actor),true);
      assert.equal(uses(f,derive,'tls-encrypted-flight',actor),true);
      assert.match(f.artifact(master).value,/HKDF-Extract\(Derive-Secret\(handshake_secret, derived, empty transcript\), zeros\)/);
      assert.equal(uses(f,'tls-'+side+'-master-derive','tls-'+side+'-handshake',actor),true);
      for(const direction of ['c2s','s2c']){
        const key='tls-'+direction+'-'+side;
        assert.equal(f.has(f.index(derive),key,actor),true);
        assert.equal(f.has(f.index(derive),key,actor==='nfsServer'?'nfsClient':'nfsServer'),false);
        assert.equal(f.has(f.index(accept),key,actor),true);
        assert.equal(f.has(f.steps.length-1,key,actor),false,'failed connection key disposed');
      }
    }
    assert.equal(uses(f,creation,'tls-s2c-server','nfsServer'),true);
    assert.equal(uses(f,accept,'tls-s2c-client','nfsClient'),true);
    assert.ok(f.step(creation).attributeOperations.some(op=>op.kind==='encrypt'&&op.instanceId===f.id(detector+'-failure')));
    assert.equal(f.has(f.index(receipt),detector+'-failure'),false);
    assert.equal(f.has(f.index(receipt),detector+'-failure','nfsClient','wire'),true);
    assert.ok(f.step(accept).attributeOperations.some(op=>op.kind==='decrypt'&&op.instanceId===f.id(detector+'-failure')));
    const keyIds=new Set(f.plan.artifacts.filter(a=>a.type==='key').map(a=>a.artifactId));
    for(const event of Object.values(f.plan.events))for(const message of event.messages||[]){
      if(message.from===message.to)continue;
      assert.equal(message.objects.some(o=>keyIds.has(o.artifactId)),false,'TLS denial sends no key material');
    }
    for(let i=0;i<f.steps.length;i++){
      const state=reconstructProtocolState(f.model,i).nfs;
      assert.equal(state.dispatchCount,0);assert.equal(state.clientBytes,null);assert.equal(state.clientAccepted,false);
      if(detector!=='rpc-decrypt'){
        assert.equal(state.transportAccepted,false);assert.equal(state.serverTransportAccepted,false);
      }
    }
    if(detector!=='rpc-decrypt')assert.equal(f.steps.some(s=>s.nfsStage==='namespace-open'||s.nfsStage==='rpc-request'),false);
    assert.equal(f.end().transportAccepted,false);assert.equal(f.end().serverTransportAccepted,false);
    assert.equal(f.end().decodedRpc,false);assert.equal(f.end().connection1,false);
    assert.ok(f.index(accept)<f.index(detector+'-server-key-dispose'));
    assert.ok(f.index(accept)<f.index(detector+'-client-key-dispose'));
  }
});

test('P6-NFS-03 GETATTR metadata receipt and client display conversion precede the same authorized READ',()=>{
  const mapped=fixture('NFS08'),failed=fixture('NFS08','display-map-failed');
  for(const f of [mapped,failed]){
    const stages=['open-accept','owner-getattr','owner-getattr-server','owner-getattr-response','owner-getattr-response-verify','owner-getattr-accept','owner-display-map','rpc-request','identity-map','dispatch','result-verify'];
    for(let i=1;i<stages.length;i++)assert.ok(f.index(stages[i-1])<f.index(stages[i]),stages[i]);
    assert.deepEqual(f.step('owner-getattr').nfsFrame.operations,['SEQUENCE','PUTFH','GETATTR']);
    assert.deepEqual(f.step('owner-getattr').nfsFrame.attributes,['owner','owner_group']);
    assert.equal(f.step('owner-getattr').nfsFrame.slotSequence,2);
    assert.equal(f.step('rpc-request').nfsFrame.slotSequence,3);
    assert.equal(f.step('close-request').nfsFrame.slotSequence,4);
    assert.match(f.artifact('owner-getattr-request').value,/GETATTR\(owner,owner_group\)/);
    assert.equal(f.artifact('owner-metadata').type,'metadata');
    assert.deepEqual(JSON.parse(f.artifact('owner-metadata').value),{owner:'alice@nfs.example',owner_group:'reports@nfs.example'});
    assert.deepEqual(f.step('owner-getattr-response').nfsFrame.operationResults,[{operation:'GETATTR',attributes:{owner:'alice@nfs.example',owner_group:'reports@nfs.example'},artifactId:f.id('owner-metadata')}]);
    for(let i=-1;i<=f.index('owner-getattr-response');i++)assert.equal(f.has(i,'owner-metadata'),false,'no accepted metadata before verification');
    assert.equal(f.has(f.index('owner-getattr-response'),'owner-metadata','nfsClient','rpc-wire'),true);
    assert.equal(f.has(f.index('owner-getattr-response-verify'),'owner-metadata'),true);
    assert.equal(f.state('owner-getattr-response').ownerMetadataAccepted,false);
    assert.equal(f.state('owner-getattr-accept').ownerMetadataAccepted,true);
    assert.equal(f.state('owner-getattr-accept').ownerDisplay,null);
    assert.equal(f.state('owner-getattr-accept').ownerGroupDisplay,null);
    assert.equal(f.step('owner-display-map').from,'nfsClient');assert.equal(f.step('owner-display-map').to,'nfsClient');
    assert.ok(f.step('owner-display-map').attributeOperations.some(op=>op.instanceId===f.id('owner-metadata')&&op.kind==='verify'&&op.actorId==='nfsClient'));
    assert.equal(f.end().clientAccepted,true);assert.equal(f.end().dispatchCount,1);
    assert.equal(f.end().clientBytes,'Synthetic report bytes: Alice may read this report. offset=0');
    assert.equal(f.end().selectedPrincipal,'alice@CORP.EXAMPLE');assert.equal(f.end().authentication,true);
    assert.equal(f.end().mappingStatus,'mapped');assert.equal(f.end().exportAllowed,true);assert.equal(f.end().fileAllowed,true);
    assert.deepEqual(f.state('identity-map').effectiveIdentity,{uid:1001,gid:100,groups:[100],assurance:'Kerberos-authenticated',numericCollision:false,localName:'server/alice'});
    assert.equal(f.has(f.index('owner-display-map'),'file-result'),false);
    assert.equal(f.has(f.index('owner-getattr-response-verify'),'authenticated-principal','nfsServer'),true);
    assert.equal(f.has(f.index('owner-getattr-response-verify'),'authenticated-principal','nfsClient'),false,'returned owner metadata is not the server authentication credential');
  }
  for(const path of ['selectedPrincipal','authentication','effectiveIdentity','mappingStatus','exportAllowed','fileAllowed','clientBytes','dispatchCount'])assert.deepEqual(failed.end()[path],mapped.end()[path],path);
  assert.equal(mapped.end().displayMappingStatus,'mapped');assert.equal(failed.end().displayMappingStatus,'display-only-failed');
  assert.equal(mapped.end().ownerDisplay,'alice@nfs.example');assert.equal(failed.end().ownerDisplay,'unmapped owner name; READ identity unaffected');
  for(const [variant,detector] of [['unmapped-principal','identity-map'],['acl-denied','file-policy'],['read-only-write','export-policy'],['unauthorized-group','file-policy'],['root-squash','file-policy'],['all-squash','file-policy']]){
    const f=fixture('NFS08',variant);assert.equal(f.end().firstDetector,detector);assert.equal(f.end().dispatchCount,0);assert.equal(f.end().clientBytes,null);assert.equal(f.steps.some(s=>s.nfsStage==='owner-display-map'),false);
  }
});
