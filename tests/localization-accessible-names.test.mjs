import test from 'node:test';
import assert from 'node:assert/strict';
import {HarnessEvent} from './dom-harness.mjs';
import {SURFACE_LOCALES,mountSurfaceApp,resolvedAccessibleName,renderedSurfaceInventory} from '../tools/verification/localization/rendered-surface-audit.mjs';

// Actual DOM name consumers only. This is not native accessibility-tree output,
// a browser/layout check or a human assistive-technology acceptance claim.
for(const loading of ['source','emitted'])test(loading+' Full labelled-by popup and Compact field explanation retain native names and protected identifiers',async()=>{
  const mounted=await mountSurfaceApp({loading}),{app,document}=mounted;
  try{
    for(const locale of ['en',...SURFACE_LOCALES]){
      await app.changeLocale(locale,{explicit:false});app.switchPresentation('full');app.selectLabScenario('basic-keycloak');
      const field=app.refs['attribute-index-list'].querySelector('[data-index-attribute="codeVerifier"]');assert.ok(field);
      document.activeElement=field;field.dispatchEvent(new HarnessEvent('focusin'));field.dispatchEvent(new HarnessEvent('keydown',{key:'F2'}));
      const popup=app.refs['attribute-popup'];assert.equal(popup.hidden,false);assert.equal(popup.getAttribute('role'),'dialog');
      const resolved=resolvedAccessibleName(app,popup),heading=app.uiText('ui.app.showAttributePopup.text.0224','Attribute explanation');
      assert.deepEqual(resolved.targets.map(node=>node.id),['attribute-popup-title','attribute-popup-field-title'],'Both actual targets contribute to the name');
      assert.equal(resolved.targets[0].textContent,heading);
      assert.equal(resolved.targets[1].textContent,'code_verifier');
      assert.equal(resolved.name,heading+' code_verifier','Restore baseline accessible-name intent without repinning obsolete aria-label');
      const formal=resolved.targets[1].querySelector('code');assert.equal(formal.getAttribute('translate'),'no');assert.equal(formal.textContent,'code_verifier');
      if(locale!=='en')assert.notEqual(heading,'Attribute explanation','The explanatory part of the name is native');
      assert.ok(popup.contains(document.activeElement),'F2 still enters the named explanation');
      const close=popup.querySelector('[data-close]');close.dispatchEvent(new HarnessEvent('keydown',{key:'Escape'}));assert.equal(popup.hidden,true);
      assert.equal(document.activeElement,field,'Escape returns to the originating protected field control');
      app.switchPresentation('compact');app.compactView.showField('codeVerifier');
      const region=app.querySelector('#compact-field-definition'),compactName=resolvedAccessibleName(app,region);
      const expected=app.compactView.message('compact.field.definitionLabel','{field} field definition',{field:'code_verifier'});
      assert.equal(region.hidden,false);assert.equal(region.getAttribute('role'),'region');
      assert.equal(compactName.name,expected,'Resolve Compact actual aria-label API, not a fictional labelled-by migration');
      assert.equal(region.querySelector('h2 code').textContent,'code_verifier','Protected field heading remains the selected field');
      assert.equal(region.querySelector('h2 code').getAttribute('translate'),'no');
      assert.ok(compactName.name.includes('code_verifier'));
      if(locale!=='en')assert.notEqual(compactName.name,'code_verifier field definition','Compact teaching name is native');
      assert.equal(app.compactView.selectedField,'codeVerifier');
      const next=locale==='en'?'he':'en';await app.changeLocale(next,{explicit:false});
      const replacement=app.querySelector('#compact-field-definition');assert.equal(replacement.hidden,false);
      assert.equal(app.compactView.selectedField,'codeVerifier');
      assert.equal(resolvedAccessibleName(app,replacement).name,app.compactView.message('compact.field.definitionLabel','{field} field definition',{field:'code_verifier'}));
    }
  }finally{mounted.dispose();}
});

test('labelled-by resolution fails missing, duplicate and empty targets instead of accepting attribute existence',async()=>{
  const {installHarness}=await import('./dom-harness.mjs'),{document}=installHarness(),root=document.createElement('section');
  root.innerHTML='<div role="dialog" aria-labelledby="first second"></div><span id="first">Attribute explanation</span><h2 id="second">code_verifier</h2>';
  const dialog=root.querySelector('[role="dialog"]');assert.equal(resolvedAccessibleName(root,dialog).name,'Attribute explanation code_verifier');
  root.querySelector('#second').textContent='';assert.throws(()=>resolvedAccessibleName(root,dialog),/Nonempty/);
  root.querySelector('#second').textContent='code_verifier';const duplicate=document.createElement('span');duplicate.id='second';duplicate.textContent='wrong';root.appendChild(duplicate);assert.throws(()=>resolvedAccessibleName(root,dialog),/Unique/);
  root.removeChild(duplicate);root.removeChild(root.querySelector('#second'));assert.throws(()=>resolvedAccessibleName(root,dialog),/Unique/);
});

test('rendered audit includes SVG names, hidden accessible text and closed disclosure captions without calling them exposed',async()=>{
  const {installHarness}=await import('./dom-harness.mjs'),{document}=installHarness(),root=document.createElement('section');root.setAttribute('lang','de');
  root.innerHTML='<svg aria-label="Connections between authentication participants"><title>Connection caption</title></svg><section hidden aria-label="Hidden explanation">Hidden text</section><details><summary>Disclosure control</summary><table><caption>Evidence comparison</caption></table></details>';
  const rows=renderedSurfaceInventory(root,{locale:'de'});
  assert.equal(rows.find(row=>row.kind==='attribute:aria-label'&&row.text.startsWith('Connections')).exposure,'exposed');
  assert.equal(rows.find(row=>row.text==='Connection caption').kind,'text');
  assert.equal(rows.find(row=>row.text==='Hidden explanation').exposure,'hidden');
  assert.equal(rows.find(row=>row.text==='Disclosure control').exposure,'exposed');
  assert.equal(rows.find(row=>row.text==='Evidence comparison').exposure,'closed-disclosure');
});
