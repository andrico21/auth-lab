import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyWindowsProtectionCanonical} from '../tools/verification/windows-protection-canonical.mjs';

test('all new case/member graphs preserve canonical possession, source prefixes, filtered history and cleanup',()=>{
  // The shared checker asserts each actual prefix, exact sender representation,
  // inspector visibility, filtered prerequisites and registry ownership. Domain
  // outcomes are independently specified by the focused fixture manifests.
  const report=verifyWindowsProtectionCanonical();
  assert.deepEqual(report.failures,[]);
  assert.equal(report.complete,true);
  assert.equal(report.sourceUnchanged,true);
});
