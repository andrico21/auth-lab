import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {installHarness} from './dom-harness.mjs';
import {extractUIContracts} from '../tools/verification/localization/ui-contracts.mjs';
import {LEARNING_PRESETS} from '../src/learning-presets.js';
import {SURFACE_LOCALES,mountSurfaceApp,renderedSurfaceInventory} from '../tools/verification/localization/rendered-surface-audit.mjs';

// Source and the exact existing inline bundle are tested independently. No build
// is performed here: the integration owner builds once before the full suite.
const presets=LEARNING_PRESETS.filter(preset=>preset.common||['basic-keycloak','basic-saml'].includes(preset.id));
const card=(app,id)=>app.querySelector('.quick-start-grid [data-learning-preset="'+id+'"]');
function reveal(app){const details=app.querySelector('#ready-journeys');details.open=true;details.setAttribute('open','');assert.equal(app.querySelector('#quick-start').hidden,false);}
function state(app){return JSON.stringify({id:app.labScenarioId,variant:app.lessonVariant,config:app.protocolConfig(),cursor:app.heldView.snapshot().cursor,queue:app.studyQueue().rows.map(row=>row.id),field:app.attributeSelection});}
function assertCards(app,locale){
  reveal(app);
  assert.deepEqual([...app.querySelectorAll('.quick-start-grid [data-learning-preset]')].map(node=>node.dataset.learningPreset).sort(),presets.map(preset=>preset.id).sort(),'Every actual visible preset identity is retained');
  for(const preset of presets){
    const button=card(app,preset.id);
    for(const [field,selector] of [['title','strong'],['summary','span']]){
      const node=[...button.children].find(child=>child.tagName===selector.toUpperCase()),actual=node.textContent;
      assert.notEqual(actual,preset[field],locale+' '+preset.id+' '+field+' must not bypass localization');
      assert.equal(node.closest('[lang]')?.getAttribute('lang'),locale,'Native prose has the actual selected language');
    }
  }
  const mfa=card(app,'web-mfa');
  for(const token of ['MFA','TOTP','Keycloak']){
    assert.ok(mfa.textContent.includes(token),'Protected '+token+' survives translated teaching text');
    assert.ok([...mfa.querySelectorAll('[translate="no"]')].some(node=>node.textContent.includes(token)),token+' has a protected DOM boundary');
  }
}
for(const loading of ['source','emitted'])test(loading+' Full Web renders every quick-start title and summary in all seven native locales and retains selection/state',async()=>{
  const mounted=await mountSurfaceApp({loading}),{app}=mounted;
  try{
    reveal(app);const english=renderedSurfaceInventory(app);
    card(app,'web-mfa').click();app.selectStep(Math.min(1,app.steps.length-1));const before=state(app);
    for(const locale of SURFACE_LOCALES){
      await app.changeLocale(locale,{explicit:false});assert.equal(state(app),before);assertCards(app,locale);
      assert.equal(card(app,'web-mfa').getAttribute('aria-pressed'),'true');
      const inventory=renderedSurfaceInventory(app,{locale,english});
      assert.equal(inventory.filter(row=>row.locator.includes('data-learning-preset')&&row.classification==='unchanged-English-review').length,0,'Independent rendered text scan catches the original bypass even when diagnostics are clean');
      const svg=app.querySelector('#connections'),label=svg.getAttribute('aria-label');
      assert.equal(label,app.uiText('ui.app.fullShell.connections.label','Connections between authentication participants'),'Actual SVG accessible name follows the active locale, not a stale prior language');
      assert.notEqual(label,'Connections between authentication participants','SVG accessible names also enter localization');
    }
    await app.changeLocale('he',{explicit:false});assert.equal(state(app),before);
    await app.changeLocale('en',{explicit:false});assert.equal(state(app),before);
    await app.changeLocale('he',{explicit:false});assert.equal(state(app),before);
    app.switchPresentation('compact');assert.equal(state(app),before);
    app.switchPresentation('full');assert.equal(state(app),before);assertCards(app,'he');
    // Each actual handler once; repeating identical handlers in every locale
    // adds no coverage beyond all-seven localized markup and state checks.
    for(const preset of presets){card(app,preset.id).click();assert.equal(app.labScenarioId,preset.id);assert.equal(card(app,preset.id).getAttribute('aria-pressed'),'true');}
    // Exercise the actual helper fallback in both programs, not a manually
    // language-marked fixture or a nonempty diagnostics assertion.
    const fallback=mounted.document.createElement('p'),source='An intentionally unbound English explanation.';
    fallback.innerHTML=app.prose('lesson:r02-deliberately-missing','summary',source);app.appendChild(fallback);
    assert.equal(fallback.textContent,source);
    assert.equal(fallback.querySelector('[lang="en"]').getAttribute('dir'),'ltr');
    assert.equal(renderedSurfaceInventory(fallback,{locale:app.localizer.locale})[0].classification,'explicit-English-fallback');
    app.removeChild(fallback);
  }finally{mounted.dispose();}
});

test('independent rendered inventory distinguishes original unbound Native prose, protected tokens and explicit English fallback',()=>{
  // This deliberately recreates the original consumer bypass without consulting
  // a registry, so a clean diagnostics/corpus count cannot make this test pass.
  const {document}=installHarness();
  const english=document.createElement('section');english.innerHTML='<button data-learning-preset="web-mfa"><strong>Web sign-in with MFA</strong><span>One realm · password + TOTP · both checks at Keycloak</span></button>';
  const native=document.createElement('section');native.setAttribute('lang','he');native.innerHTML=english.innerHTML+'<code translate="no" dir="ltr">TOTP</code><p lang="en">An explicit fallback sentence.</p>';
  const rows=renderedSurfaceInventory(native,{locale:'he',english:renderedSurfaceInventory(english)});
  assert.deepEqual(rows.filter(row=>row.classification==='unchanged-English-review').map(row=>row.text),['Web sign-in with MFA','One realm · password + TOTP · both checks at Keycloak']);
  assert.equal(rows.find(row=>row.text==='TOTP').classification,'protected-directive');
  assert.equal(rows.find(row=>row.text==='An explicit fallback sentence.').classification,'explicit-English-fallback');
});
test('existing UI extractor audits human SVG names and titles but not protected geometry',()=>{
  const root=fs.mkdtempSync(path.join(tmpdir(),'l10n-svg-surface-'));
  try{
    fs.writeFileSync(path.join(root,'renderer.mjs'),'export function render(){return `<svg aria-label="Connections between authentication participants"><title>Authentication connections</title><desc>Messages between participants</desc><path d="M0 0L7 7"/></svg>`;}');
    const result=extractUIContracts({root,modules:['renderer.mjs']});
    assert.ok(result.residual.some(row=>row.element==='svg'&&row.attribute==='aria-label'&&row.english==='Connections between authentication participants'));
    assert.ok(result.residual.some(row=>row.element==='title'&&row.english==='Authentication connections'));
    assert.ok(result.residual.some(row=>row.element==='desc'&&row.english==='Messages between participants'));
    assert.equal(result.residual.some(row=>row.element==='path'),false);
  }finally{fs.rmSync(root,{recursive:true,force:true});}
});
