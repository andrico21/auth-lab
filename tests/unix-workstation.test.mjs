import test from 'node:test';
import assert from 'node:assert/strict';
import {LINUXLOGONLAB_SCENARIOS} from '../src/linux-logon-lab.js';
import {MACOSLOGONLAB_SCENARIOS} from '../src/macos-logon-lab.js';
import {reconstructProtocolState} from '../src/protocol-state.js';
import {readFileSync} from 'node:fs';
import {LINUXELEVLAB_SCENARIOS,LINUXELEVLAB_ATTRIBUTES} from '../src/linux-elevation-lab.js';
import {MACOSELEVLAB_SCENARIOS,MACOSELEVLAB_ATTRIBUTES} from '../src/macos-elevation-lab.js';
import {LINUXLOGONLAB_ATTRIBUTES} from '../src/linux-logon-lab.js';
import {MACOSLOGONLAB_ATTRIBUTES} from '../src/macos-logon-lab.js';
import {buildUnixWorkstationHeldObjects} from '../src/held-object-unix-workstation.js';
import {compileHeldObjects,projectHeldObjects} from '../src/held-object-state.js';

const find=(all,id)=>all.find(m=>m.id===id);
const at=(m,key)=>reconstructProtocolState(m,m.steps().findIndex(s=>s.id===m.id+':'+key)).workstation;
const end=m=>reconstructProtocolState(m,m.steps().length-1).workstation;

test('Linux files lookup does not authenticate; PAM success cannot bypass account/session gates',()=>{
  const base=find(LINUXLOGONLAB_SCENARIOS,'lab-llog01');
  assert.equal(at(base,'identity-result').identityResolved,true);
  assert.equal(at(base,'identity-result').authenticated,false);
  assert.equal(at(base,'pam-auth').authenticated,true);
  assert.equal(at(base,'pam-auth').session,false);
  for(const v of ['unknown-user','wrong-password','account-denied','session-failure','blank-password']){
    const m=base.withVariant(v);assert.equal(end(m).session,false,v);assert.equal(end(m).unrelatedSession,'other-user-session-retained');
  }
  assert.equal(end(base.withVariant('account-denied')).authenticated,true);
  assert.equal(end(base.withVariant('session-failure')).admitted,true);
  assert.equal(at(base.withVariant('nullok-explicit'),'session-register').session,true);
  assert.equal(at(base.withVariant('without-logind'),'session-register').logindRegistered,false);
  assert.equal(at(base,'session-register').session,true);
  assert.equal(end(base).session,false);
  assert.equal(end(base).sessionWasCreated,true);
  assert.equal(end(base).tgt,false);
});

test('Mac initial login, locked-session unlock, keychain and Apple Account are distinct',()=>{
  const base=find(MACOSLOGONLAB_SCENARIOS,'lab-mlog01');
  assert.equal(end(base).session,true);assert.equal(end(base).createdSession,true);
  assert.equal(end(base.withVariant('apple-account-password')).session,false);
  assert.equal(end(base.withVariant('startup-needs-password')).session,false);
  for(const v of ['unsupported-touch','unavailable-touch','touch-canceled']){const s=end(base.withVariant(v));assert.equal(s.session,true);assert.equal(s.sessionLocked,true);assert.equal(s.authenticated,false);}
  assert.equal(end(base.withVariant('touch-unlock')).createdSession,false);
  assert.equal(end(base.withVariant('touch-unlock')).sessionLocked,false);
  assert.equal(end(base.withVariant('keychain-mismatch')).session,true);
  assert.equal(end(base.withVariant('keychain-mismatch')).keychainUnlocked,false);
  for(const m of [base,base.withVariant('touch-unlock')]){assert.equal(end(m).tgt,false);assert.equal(end(m).idpSSO,false);assert.equal(end(m).administrator,false);}
});

test('Fixed variants change source fixtures without mutating base or picker identity',()=>{
  for(const base of [...LINUXLOGONLAB_SCENARIOS,...MACOSLOGONLAB_SCENARIOS]){
    const before=JSON.stringify(base.fixture);
    for(const choice of base.variantChoices){const branch=base.withVariant(choice.id);assert.equal(branch.id,base.id);assert.equal(branch.variantId,choice.id);assert.ok(Object.isFrozen(branch.fixture));assert.ok(Object.isFrozen(branch));}
    assert.equal(JSON.stringify(base.fixture),before);assert.throws(()=>base.withVariant('not-authored'),RangeError);
  }
});

const unixAll=[...LINUXLOGONLAB_SCENARIOS,...LINUXELEVLAB_SCENARIOS,...MACOSLOGONLAB_SCENARIOS,...MACOSELEVLAB_SCENARIOS];
const unixOracle=JSON.parse(readFileSync(new URL('../docs/next-expansion/unix-workstation-worksheet.json',import.meta.url),'utf8'));
const unixPath=(state,path)=>path.split('.').reduce((value,key)=>value?.[key],state);

test('All17 authored rows and every named source-input branch satisfy the independent typed oracle',()=>{
  assert.equal(unixAll.length,17);
  for(const row of unixOracle.rows){
    const base=find(unixAll,row.runtimeId);assert.ok(base,row.id);
    assert.equal(base.profile.name,row.modelProfile.name);assert.equal(base.profile.version,row.modelProfile.version);
    assert.deepEqual(new Set(base.variantChoices.map(v=>v.id)),new Set(row.canonicalCases.map(c=>c.id)),row.id);
    for(const c of row.canonicalCases){const m=base.withVariant(c.id),steps=m.steps();
      assert.ok(steps.some(s=>s.id===c.firstDetector.stepId),row.id+'/'+c.id+' first detector');
      for(const a of c.assertions.filter(a=>a.target==='state')){
        const index=a.at.end?steps.length-1:a.at.milestone==='initial'?-1:steps.findIndex(s=>s.id===a.at.stepId);
        assert.ok(index>=0||a.at.milestone==='initial',row.id+'/'+c.id+'/'+a.at.stepId);
        assert.deepEqual(unixPath(reconstructProtocolState(m,index),a.path),a.equals,row.id+'/'+c.id+'/'+a.path);
      }
      const detail=row.acceptanceCases.find(a=>a.variantId===c.id);
      for(const suffix of detail.requiredEvents)assert.ok(steps.some(s=>s.id===row.eventIdPrefix+suffix),row.id+'/'+c.id+' required '+suffix);
      for(const suffix of detail.forbiddenEvents)assert.equal(steps.some(s=>s.id===row.eventIdPrefix+suffix),false,row.id+'/'+c.id+' forbidden '+suffix);
    }
  }
});

test('Every branch operational field is globally registered before variant construction, with fixed catalog union',()=>{
  const fields={...LINUXLOGONLAB_ATTRIBUTES,...LINUXELEVLAB_ATTRIBUTES,...MACOSLOGONLAB_ATTRIBUTES,...MACOSELEVLAB_ATTRIBUTES};
  for(const base of unixAll)for(const choice of base.variantChoices){const m=base.withVariant(choice.id);
    for(const step of m.steps())for(const op of step.attributeOperations||[]){assert.ok(fields[op.attributeId],op.attributeId);assert.ok(base.catalogAttributeIds.includes(op.attributeId),op.attributeId);}
  }
});

test('Offline cache never becomes new Kerberos issuance; new central information is not invented',()=>{
  const base=find(unixAll,'lab-llog03');
  for(const choice of base.variantChoices){const m=base.withVariant(choice.id),s=end(m);assert.equal(s.centralKnowledge,'stale');assert.equal(s.tgt,choice.id==='retained-ticket');assert.equal(s.tgtWasIssued,false);assert.equal(m.steps().some(step=>step.id.endsWith(':ticket-issued')),false);}
  assert.equal(end(base.withVariant('central-revoked-unknown')).session,true);
  assert.equal(end(base.withVariant('offline-failure-limit')).session,false);
  assert.equal(end(base.withVariant('offline-delay-elapsed')).session,true);
});

test('sudo identity/target/timestamps, root su exception and mandatory policy remain independent',()=>{
  const sudo=find(unixAll,'lab-lelev01');
  for(const [v,who] of [['rootpw','root'],['targetpw','backup'],['runaspw','operator']]){const s=end(sudo.withVariant(v));assert.equal(s.authenticatedIdentity,who);assert.equal(s.executionTarget,'backup');assert.equal(s.localIdentity,'uid1000');}
  assert.equal(end(sudo.withVariant('cached-policy-denied')).operation,false);
  assert.equal(end(sudo.withVariant('noninteractive')).operation,false);
  for(const v of ['nopasswd','root-caller'])assert.equal(end(sudo.withVariant(v)).passwordCompared,false);
  const su=find(unixAll,'lab-lelev02');assert.equal(end(su.withVariant('setuid-not-real-root')).operation,false);assert.equal(end(su.withVariant('real-root-bypass')).operation,true);
  const lsm=find(unixAll,'lab-lelev04');assert.equal(end(lsm).processUid,0);assert.equal(end(lsm).authenticated,true);assert.equal(end(lsm).operation,false);assert.equal(end(lsm.withVariant('no-loaded-profile')).lsmEnforced,false);
});

test('FileVault and network administrator cannot manufacture local token/ownership privileges',()=>{
  const fv=find(unixAll,'lab-mlog02');assert.equal(end(fv.withVariant('admin-alone')).volumeUnlocked,false);assert.equal(end(fv.withVariant('standard-owner')).administrator,false);assert.equal(end(fv.withVariant('standard-owner')).volumeOwner,true);assert.equal(end(fv.withVariant('os-login-denied')).volumeUnlocked,true);assert.equal(end(fv.withVariant('os-login-denied')).session,false);
  const net=find(unixAll,'lab-melev03');for(const v of ['default','secure-token-required','ownership-required','current-user-required']){const s=end(net.withVariant(v));assert.equal(s.networkLocalAccount,false);assert.equal(s.secureToken,false);assert.equal(s.volumeOwner,false);assert.equal(s.localIdentity,'uid501');assert.equal(s.operation,v==='default');}
});

test('PAM password commit leaves admission to the selected local account stack and preserves committed state on denial',()=>{
  const base=find(LINUXLOGONLAB_SCENARIOS,'lab-llog04');
  for(const variant of ['default','directory-online','post-change-account-denied']){
    const m=base.withVariant(variant),steps=m.steps();
    const raw=buildUnixWorkstationHeldObjects({model:m,steps,actors:m.actors(),choiceId:m.id,contextId:m.id+':'+variant});
    const compiled=compileHeldObjects(raw,{model:m,steps});
    const frame=key=>{
      const eventIndex=steps.findIndex(s=>s.id===m.id+':'+key);
      assert.ok(eventIndex>=0,key);
      return projectHeldObjects(compiled,{eventIndex,milestone:'complete'});
    };
    const has=(snapshot,key,actor)=>snapshot.holdings.some(h=>h.artifactId===m.id+':'+key&&(!actor||h.actorId===actor));
    for(const key of ['password-update','password-authority-result','password-reference-refresh']){
      const snapshot=frame(key);
      assert.equal(snapshot.state.workstation.authenticated,true);
      assert.equal(snapshot.state.workstation.authorityGeneration,2);
      assert.equal(snapshot.state.workstation.admitted,false);
      assert.equal(snapshot.state.workstation.session,false);
      assert.equal(snapshot.state.workstation.postChangeAccountChecked,false);
      assert.equal(has(snapshot,'session-credentials'),false);
      assert.equal(has(snapshot,'session'),false);
      assert.equal(has(snapshot,'backend-generation-g2','pamPasswordAuthority'),true);
    }
    const admitted=variant!=='post-change-account-denied',decision=frame('post-change-account');
    assert.equal(decision.state.workstation.postChangeAccountChecked,true);
    assert.equal(decision.state.workstation.admitted,admitted);
    assert.equal(decision.state.workstation.session,false);
    assert.equal(has(decision,'post-change-account-policy','pamChange'),true);
    assert.equal(has(decision,'post-change-account-policy','pamPasswordAuthority'),false);
    assert.equal(has(decision,'session-credentials'),false);
    const final=projectHeldObjects(compiled,{eventIndex:steps.length-1,milestone:'complete'});
    assert.equal(final.state.workstation.authenticated,true);
    assert.equal(final.state.workstation.authorityGeneration,2);
    assert.equal(final.state.workstation.passwordChangeRequired,false);
    assert.equal(final.state.workstation.admitted,admitted);
    assert.equal(final.state.workstation.session,admitted);
    assert.equal(final.state.workstation.unrelatedSession,'other-user-session-retained');
    assert.equal(has(final,'session-credentials','pamChange'),admitted);
    assert.equal(has(final,'session','pamChangeSession'),admitted);
    assert.equal(has(final,'backend-generation-g2','pamPasswordAuthority'),true);
    assert.equal(has(final,'authority-g2','pamChange'),true);
    for(const key of ['backend-generation','authority','old-secret','new-secret'])assert.equal(has(final,key),false,key);
    if(!admitted)assert.equal(final.state.workstation.failure,'post-change account policy denied');
    else{
      const credentials=frame('setcred');
      assert.equal(credentials.state.workstation.admitted,true);
      assert.equal(credentials.state.workstation.session,false);
      assert.equal(has(credentials,'session-credentials','pamChange'),true);
    }
    for(let eventIndex=-1;eventIndex<steps.length;eventIndex++){
      const snapshot=projectHeldObjects(compiled,{eventIndex,milestone:eventIndex<0?'initial':'complete'});
      for(const key of ['backend-generation','backend-generation-g2'])assert.ok(snapshot.holdings.filter(h=>h.artifactId===m.id+':'+key).every(h=>h.actorId==='pamPasswordAuthority'));
      for(const key of ['authority','authority-g2'])assert.ok(snapshot.holdings.filter(h=>h.artifactId===m.id+':'+key).every(h=>h.actorId==='pamChange'));
    }
  }
  for(const variant of ['new-policy-denied','wrong-current-password','update-failed','consumer-no-change','directory-unreachable','account-expired']){
    const state=end(base.withVariant(variant));
    assert.equal(state.authorityGeneration,1);
    assert.equal(state.admitted,false);
    assert.equal(state.session,false);
    assert.equal(state.postChangeAccountChecked,false);
  }
  assert.equal(end(base.withVariant('directory-online')).credentialAuthority,'directory');
  assert.equal(end(base.withVariant('directory-unreachable')).credentialAuthority,'directory');
});
