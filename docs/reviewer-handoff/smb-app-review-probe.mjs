import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';

const base = new URL('./smb-candidate/', import.meta.url);
const hash = path => createHash('sha256').update(fs.readFileSync(new URL(path, base))).digest('hex');
const before = hash('src/smb-access-lab.js');
const {installHarness} = await import(new URL('tests/dom-harness.mjs', base));
const {document, clock} = installHarness();
const {AuthFlowStudio} = await import(new URL('src/app.js', base));
const {SMBLAB_SCENARIOS} = await import(new URL('src/smb-access-lab.js', base));
const {LAB_MODELS} = await import(new URL('src/lab-catalog.js', base));
const {studioRoute, parseStudioRoute} = await import(new URL('src/workspaces.js', base));
const {heldObjectTrace, projectHeldObjects} = await import(new URL('src/held-object-state.js', base));
const app = new AuthFlowStudio(); document.body.appendChild(app); app.connectedCallback();
const observed = [];
const use = suffix => { if(app.hasTrace)app.clearAttribute();app.selectLabScenario('lab-smb-nonjoined-' + suffix, {navigate:false}); };
const stage = row => row.sourceStepId?.split(':').at(-1);
const field = (suffix, key) => {
  app.selectAttribute('smb_' + suffix.replaceAll('-', '_') + '_' + key, false);
  assert.ok(app.traceQueue.length, 'Empty field trace: ' + key);
  assert.ok(app.traceQueue.every(row => !row.title.startsWith('undefined ')));
  return [...app.traceQueue];
};
try {
  for (const model of SMBLAB_SCENARIOS) {
    const route = studioRoute(model.id, LAB_MODELS);
    assert.equal(route, '#/windows/files/' + model.id);
    assert.equal(parseStudioRoute(route, LAB_MODELS).scenarioId, model.id);
    assert.equal(model.profile.dialect, '0x0311');
  }
  use('ntlm');
  app.querySelector('[data-learning-detail="crypto"]').click();
  assert.ok(!app.querySelector('#learning-profile-crypto').textContent.includes('[object Object]'));
  assert.match(app.querySelector('#learning-profile-crypto').textContent, /SHA512/);
  let queue = field('ntlm','tree');
  const create = queue.findIndex(row => row.traceKind === 'create');
  const send = queue.findIndex(row => row.traceKind === 'send');
  assert.ok(create >= 0 && send > create, 'Share handle must be created before send');
  assert.ok(queue.some(row => stage(row) === 'tree-accept' && row.traceKind === 'verify'));
  queue = field('ntlm','session-key');
  assert.ok(queue.some(row => row.from === 'smbServer' && stage(row) === 'ntlm-accept'));
  queue = field('ntlm','ntlm-proof');
  const proofWire = queue.find(row => stage(row) === 'dc-request' && row.traceKind === 'send');
  assert.match(proofWire.payload[0].value, /Netlogon protected/);
  assert.ok(queue.some(row => stage(row) === 'dc-verify' && row.traceKind === 'decrypt'));
  assert.ok(queue.some(row => stage(row) === 'dc-verify' && row.traceKind === 'verify'));
  observed.push('NTLM proof protected wire/local validation; server key acquisition; handle create-before-send and acceptance');

  use('kerberos');
  for (const [key, acceptance] of [['tgt-key','as-accept'], ['ticket-key','tgs-accept']]) {
    queue = field('kerberos', key);
    assert.ok(queue.some(row => row.from === 'smbDC' && row.traceKind === 'create'));
    assert.ok(queue.some(row => row.from === 'smbClient' && stage(row) === acceptance));
    assert.ok(queue.every(row => row.from === row.to), 'Secret key must not be an independent wire field');
  }
  queue = field('kerberos','session-key');
  assert.ok(queue.some(row => row.from === 'smbServer' && stage(row) === 'kerberos-accept'));
  assert.ok(queue.some(row => row.from === 'smbClient' && stage(row) === 'client-mechanism'));
  queue = field('kerberos','signing-key');
  assert.ok(queue.some(row => row.from === 'smbServer' && stage(row) === 'server-key-derivation' && row.traceKind === 'derive'));
  assert.ok(queue.some(row => row.from === 'smbClient' && stage(row) === 'client-key-derivation' && row.traceKind === 'derive'));
  assert.ok(queue.every(row => row.from === row.to));
  observed.push('Kerberos secret-key local issuance/acquisition; both endpoints derive without key wire transfer');

  use('kerberos');
  app.querySelector('[data-learning-detail="fields"]').click();
  app.selectStep(app.steps.length - 1, false);
  const compiled = app.heldView.compiled();
  const final = projectHeldObjects(compiled,{eventIndex:app.steps.length-1});
  const artifact = 'lab-smb-nonjoined-kerberos:file-data';
  const selected = final.holdings.find(h => h.artifactId === artifact && h.actorId === 'smbClient' && h.store === 'accepted file data');
  assert.ok(selected); app.heldView.select(selected);
  const traceButton = app.querySelector('#held-inspector [data-held-trace]');
  assert.ok(traceButton); traceButton.click(); app.player.stop(false);
  const exact = [...app.traceQueue];
  assert.equal(app.objectTraceSelection,artifact);
  const wireIndex = exact.findIndex(row => stage(row) === 'read-success');
  const decodeIndex = exact.findIndex(row => stage(row) === 'read-success-unwrap');
  assert.ok(wireIndex >= 0 && decodeIndex > wireIndex);
  assert.equal(exact[wireIndex].representationId,'ciphertext');
  assert.equal(exact[decodeIndex].representationId,'plain');
  app.selectStep(wireIndex,false);
  assert.match(app.refs.inspector.querySelector('.field-value').textContent,/Opaque AES-128-GCM/);
  assert.doesNotMatch(app.refs.inspector.querySelector('.field-value').textContent,/Quarterly report:/);
  app.selectStep(decodeIndex,false);
  assert.match(app.refs.inspector.querySelector('.field-value').textContent,/Quarterly report:/);
  assert.equal(exact[decodeIndex].inspectionActorId,'smbClient');
  observed.push('Actual held inspector → exact-history button → wire ciphertext and local decoded rendered values');

  for (const suffix of ['signature-rejected','encryption-rejected']) {
    use(suffix); queue = field(suffix,'signing-key');
    assert.ok(queue.some(row => stage(row) === 'client-disconnect' && row.traceKind === 'evict'), 'Disconnect field replay must evict, not use');
    const c = app.heldView.compiled();
    const last = projectHeldObjects(c,{eventIndex:app.steps.length-1});
    assert.equal(last.state.smb.clientDisconnected,true);
    assert.equal(last.state.smb.clientSessionAccepted,false);
    assert.equal(last.state.smb.localDesktopIdentity,'WORKGROUPPC\\bob');
    if (suffix === 'encryption-rejected') {
      const rows = heldObjectTrace(c,app.labModel.id+':file-data');
      assert.ok(rows.some(row => row.representationId === 'ciphertext' && row.inspectionActorId === 'smbClient'));
      assert.ok(!rows.some(row => row.representationId === 'plain' && row.inspectionActorId === 'smbClient'));
    }
  }
  observed.push('Integrity rejection cleanup field eviction and no client plaintext on bad GCM tag');
  const after = hash('src/smb-access-lab.js');
  assert.equal(after,before,'Source changed during independent probe');
  console.log(JSON.stringify({result:'PASS',sourceSha256:after,scenarios:SMBLAB_SCENARIOS.length,observed},null,2));
} finally {
  app.disconnectedCallback(); document.body.removeChild(app); clock.frames.clear(); clock.timers.clear();
}
