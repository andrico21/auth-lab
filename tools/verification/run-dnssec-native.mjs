import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawn, spawnSync} from 'node:child_process';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {seekNativeRange} from './dnssec-native-controls.mjs';

const dnsNativeHelp = `DNSSEC native Chromium verification (run only after integration).
Usage: bun tools/verification/run-dnssec-native.mjs \\
  --root /checkout --out /new/evidence --reference /canonical-prefix-reference.json \\
  --worksheet /independent/worksheet.json --playwright /playwright-core/index.mjs \\
  --chrome /chrome --suite core|layout|interaction|zoom|all \\
  [--checkpoint-report /accepted/contract-source-09/status.json] \\
  [--xvfb /Xvfb --xdotool /xdotool --scrot /scrot]
Both --name=value and --name value are accepted. No installs or builds occur.
The output directory must not exist. Reports are projection equivalence and
native-rendering evidence, not an independent semantic/cryptographic oracle.
Suites execute serially. Core: 22 defaults x three loading modes, native full,
field and exact-object seeks, backwards and reset. Layout: every enabled chapter
of all22 defaults, both internals modes, all three loading modes. Interaction:
12 exact named task cases in DNS01/06/08/10/13/16/18/21 (eight task families),
dark/light x desktop/touch-narrow x normal/reduced motion x three loading modes
=288cells. Interaction/zoom are representative native controls/task layers:
first/middle/last rows and endpoints both ways, plus accepted independent source
checkpoints and successors in full named-task replay. They do not repeat complete
semantic coverage per theme. --checkpoint-report is required for interaction,
zoom and all. Complete159 Source/emitted semantics and every-row default core
are separate evidence. Every named task retains field/exact replay, variant reset,
workspace navigation and clock/cache/CO/owner assertions. Zoom: headed isolated
Xvfb, genuine Chrome Ctrl+0/Ctrl+plus at100/150/200; three loading modes x eight
chosen actual task cases =72cells. Missing X11 prerequisites FAIL required zoom,
never skip-as-pass. Inherit provisioned LD_LIBRARY_PATH.
Files: native-status.json, cells.jsonl, browser-events.jsonl, runner-input.mjs,
reference-input.json, checkpoint-report-input.json (when supplied), subprocess-*.stdout/stderr, bounded screenshots.
No human AT/G01, cross-engine, live DNS/OS/service, release or performance claim.`;
if (process.argv.includes('--help')) { console.log(dnsNativeHelp); process.exit(0); }

function dnsNativeOptions(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    assert.ok(argv[i].startsWith('--'), 'Expected --option');
    const split = argv[i].indexOf('=');
    const key = argv[i].slice(2, split < 0 ? undefined : split);
    const value = split < 0 ? argv[++i] : argv[i].slice(split + 1);
    assert.ok(value && !value.startsWith('--'), 'Missing value for ' + key);
    assert.ok(!Object.hasOwn(options, key), 'Duplicate option ' + key);
    assert.ok(['root', 'out', 'reference', 'worksheet', 'checkpoint-report', 'playwright', 'chrome', 'suite', 'xvfb', 'xdotool', 'scrot'].includes(key), 'Unknown option ' + key);
    options[key] = key === 'suite' ? value : path.resolve(value);
  }
  for (const key of ['root', 'out', 'reference', 'worksheet', 'playwright', 'chrome', 'suite']) assert.ok(options[key], 'Required --' + key);
  assert.ok(['core', 'layout', 'interaction', 'zoom', 'all'].includes(options.suite), 'Invalid suite');
  if (['interaction', 'zoom', 'all'].includes(options.suite)) assert.ok(options['checkpoint-report'], 'Required --checkpoint-report for representative native tasks');
  return options;
}
const dnsNativeOptionsValue = dnsNativeOptions(process.argv.slice(2));
const dnsNativeRoot = fs.realpathSync(dnsNativeOptionsValue.root);
const dnsNativeOut = dnsNativeOptionsValue.out;
fs.mkdirSync(dnsNativeOut, {recursive: false});
const dnsNativeRunner = fileURLToPath(import.meta.url);
const dnsNativeControlsRunner = fileURLToPath(new URL('./dnssec-native-controls.mjs', import.meta.url));
const dnsNativeSha = value => createHash('sha256').update(value).digest('hex');
const dnsNativeHashObject = value => dnsNativeSha(JSON.stringify(value));
const dnsNativeDigest = filename => {
  assert.ok(fs.lstatSync(filename).isFile(), 'Regular input file required: ' + filename);
  return {sha256: dnsNativeSha(fs.readFileSync(filename)), bytes: fs.statSync(filename).size};
};
const dnsNativeWrite = (name, value) => fs.writeFileSync(path.join(dnsNativeOut, name), JSON.stringify(value, null, 2) + '\n');
const dnsNativeAppend = (name, value) => fs.appendFileSync(path.join(dnsNativeOut, name), JSON.stringify(value) + '\n');
const dnsNativeReport = {
  schemaVersion: 1, kind: 'DNSSEC-native-rendering-verification', passed: false, status: 'running',
  startedAt: new Date().toISOString(), argv: process.argv, regenerateArgv: process.argv,
  options: dnsNativeOptionsValue, runtime: {execPath: process.execPath, versions: process.versions, platform: process.platform, arch: process.arch},
  scope: 'Native canonical projection/custody equivalence and rendered consumer controls. Core exhausts every visible row for22 defaults x3 modes. Interaction/zoom are representative native task/control layers, separate from complete159 Source/emitted semantic evidence, not exhaustive semantics per theme. The canonical reference is not an independent outcome oracle.',
  notEstablished: ['Human assistive-technology speech/comprehension, G01 and overall manual acceptance', 'Cross-engine conformance', 'Live DNS, native OS or remote-service interoperability', 'Native cryptographic verification', 'Performance or regression acceptance, including current and historical performance conditions', 'Release, Astra review, publication or deployment approval'],
  cells: {attempted: 0, passed: 0, failed: 0}, stages: [], sessions: [], screenshots: [], failures: [], subprocesses: [],
  zoom: {required: ['zoom', 'all'].includes(dnsNativeOptionsValue.suite), performed: false},
};
const dnsNativeSave = () => dnsNativeWrite('native-status.json', dnsNativeReport);
dnsNativeSave();
fs.copyFileSync(dnsNativeRunner, path.join(dnsNativeOut, 'runner-input.mjs'), fs.constants.COPYFILE_EXCL);
fs.copyFileSync(dnsNativeControlsRunner, path.join(dnsNativeOut, 'controls-input.mjs'), fs.constants.COPYFILE_EXCL);
fs.copyFileSync(dnsNativeOptionsValue.reference, path.join(dnsNativeOut, 'reference-input.json'), fs.constants.COPYFILE_EXCL);
if (dnsNativeOptionsValue['checkpoint-report']) fs.copyFileSync(dnsNativeOptionsValue['checkpoint-report'], path.join(dnsNativeOut, 'checkpoint-report-input.json'), fs.constants.COPYFILE_EXCL);
fs.writeFileSync(path.join(dnsNativeOut, 'cells.jsonl'), '', {flag: 'wx'});
fs.writeFileSync(path.join(dnsNativeOut, 'browser-events.jsonl'), '', {flag: 'wx'});

let dnsNativeBrowser, dnsNativeServer, dnsNativeXvfb;
let dnsNativeOrigin, dnsNativeReference, dnsNativeManifest, dnsNativeCheckpointReport;
let dnsNativeSequence = 0;
const dnsNativeTasks = [
  {planId: 'DNS01', taskFamily: 'cold-warm-lookup', caseId: 'cold-secure', zoom: true},
  {planId: 'DNS01', taskFamily: 'cold-warm-lookup', caseId: 'warm-answer-cache'},
  {planId: 'DNS06', taskFamily: 'forwarding-validation', caseId: 'local-validates-upstream-fetches'},
  {planId: 'DNS06', taskFamily: 'forwarding-validation', caseId: 'upstream-validates-local-relies'},
  {planId: 'DNS06', taskFamily: 'forwarding-validation', caseId: 'cached-upstream-servfail-cd-zero-then-cd-one', zoom: true},
  {planId: 'DNS08', taskFamily: 'opt-out-proof', caseId: 'unsigned-optout-delegation', zoom: true},
  {planId: 'DNS10', taskFamily: 'cache-expiry', caseId: 'expired-ttl', zoom: true},
  {planId: 'DNS13', taskFamily: 'rollover-clock', caseId: 'ksk-double-ds', zoom: true},
  {planId: 'DNS16', taskFamily: 'rejected-parent-change', caseId: 'one-authority-stale', zoom: true},
  {planId: 'DNS18', taskFamily: 'provider-switch', caseId: 'cached-keys-provider-switch', zoom: true},
  {planId: 'DNS21', taskFamily: 'compact-denial-co', caseId: 'co-enabled'},
  {planId: 'DNS21', taskFamily: 'compact-denial-co', caseId: 'co-disabled-downstream', zoom: true},
];
const dnsNativeZoomStates = new WeakMap();
async function dnsNativeSyncZoom(page) {
  const state = dnsNativeZoomStates.get(page);
  if (!state || state.url === page.url()) return;
  const previousURL = state.url;
  // Chrome file: hash navigation can retain DPR but mis-scale pointer input.
  // Reapply genuine zoom after route changes in every headed zoom context.
  dnsNativeCommand(dnsNativeOptionsValue.xdotool, ['key', '--clearmodifiers', 'ctrl+0'], {DISPLAY: state.display});
  for (let i = 0; i < state.presses; i++) dnsNativeCommand(dnsNativeOptionsValue.xdotool, ['key', '--clearmodifiers', 'ctrl+plus'], {DISPLAY: state.display});
  await page.waitForFunction(({dpr, ratio}) => Math.abs(devicePixelRatio / dpr - ratio) < .025, {dpr: state.baselineDpr, ratio: state.percent / 100}, {timeout: 10000});
  state.url = page.url();
  dnsNativeAppend('browser-events.jsonl', {kind: 'genuine-browser-zoom-reapplied', mechanism: 'xdotool Chrome Ctrl+0 / Ctrl+plus', previousURL, url: state.url, percent: state.percent, reason: 'same-document route change; native-coordinate-probe-02'});
}
const dnsNativeSettle = async page => {
  await dnsNativeSyncZoom(page);
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
};
function dnsNativeFiles(directory) {
  return fs.readdirSync(path.join(dnsNativeRoot, directory), {withFileTypes: true}).sort((a, b) => a.name.localeCompare(b.name)).flatMap(entry => {
    assert.ok(!entry.isSymbolicLink(), 'Source symlink: ' + directory + '/' + entry.name);
    const name = directory + '/' + entry.name;
    if (entry.isDirectory()) return dnsNativeFiles(name);
    assert.ok(entry.isFile(), 'Unsupported source input ' + name);
    return [name];
  });
}
function dnsNativeIdentity() {
  const names = ['index.html', 'build.mjs', 'package.json', 'security-policy.mjs', ...dnsNativeFiles('src'), ...dnsNativeFiles('assets'), ...dnsNativeFiles('tests')];
  return {
    sourceFiles: Object.fromEntries(names.sort().map(name => [name, dnsNativeDigest(path.join(dnsNativeRoot, name)).sha256])),
    standalone: dnsNativeDigest(path.join(dnsNativeRoot, 'dist/auth-flow-studio.html')),
    manifest: dnsNativeDigest(path.join(dnsNativeRoot, 'docs/dnssec-expansion/scenario-manifest.json')),
    worksheet: dnsNativeDigest(dnsNativeOptionsValue.worksheet), reference: dnsNativeDigest(dnsNativeOptionsValue.reference),
    ...(dnsNativeOptionsValue['checkpoint-report'] ? {checkpointReport: dnsNativeDigest(dnsNativeOptionsValue['checkpoint-report'])} : {}),
    controls: dnsNativeDigest(dnsNativeControlsRunner),
    runner: dnsNativeDigest(dnsNativeRunner), playwright: dnsNativeDigest(dnsNativeOptionsValue.playwright), chrome: dnsNativeDigest(dnsNativeOptionsValue.chrome),
  };
}
function dnsNativeValidateReference() {
  assert.equal(dnsNativeReference.schemaVersion, 1);
  assert.equal(dnsNativeReference.kind, 'DNSSEC-canonical-source-prefix-reference');
  assert.equal(dnsNativeReference.passed, true, 'Canonical reference producer must have passed its acceptance gate');
  assert.equal(dnsNativeReference.complete, true, 'Canonical reference producer must have completed its acceptance gate');
  assert.equal(dnsNativeManifest.rows.length, 22);
  assert.equal(dnsNativeReference.cases.length, 159, 'All159 reference cases required');
  const identities = dnsNativeReference.identities;
  assert.ok(identities && Object.keys(identities.sourceFiles).length, 'Reference identities required');
  for (const [name, hash] of Object.entries(identities.sourceFiles)) {
    assert.ok(!path.isAbsolute(name) && !name.split(/[\\/]/).includes('..'), 'Safe relative reference input');
    assert.equal(dnsNativeDigest(path.join(dnsNativeRoot, name)).sha256, hash, 'Reference source identity ' + name);
  }
  assert.equal(dnsNativeReport.before.standalone.sha256, identities.standaloneSha256, 'Reference HTML identity');
  assert.equal(dnsNativeReport.before.manifest.sha256, identities.manifestSha256, 'Reference manifest identity');
  assert.equal(dnsNativeReport.before.worksheet.sha256, identities.worksheetSha256, 'Independent worksheet identity');
  const seen = new Set();
  for (const row of dnsNativeManifest.rows) {
    const entries = dnsNativeReference.cases.filter(entry => entry.id === row.runtimeId);
    assert.deepEqual(entries.map(entry => entry.caseId).sort(), [...row.caseIds].sort(), row.planId + ' exact cases');
    assert.equal(entries.filter(entry => entry.variant === 'default').length, 1);
    assert.equal(entries.find(entry => entry.variant === 'default').caseId, row.defaultCaseId);
    for (const entry of entries) {
      const key = entry.id + '/' + entry.caseId;
      assert.ok(!seen.has(key), 'Duplicate reference case'); seen.add(key);
      assert.ok(entry.fieldId && entry.inspection?.artifactId && entry.inspection?.actorId, 'Real field and inspected object required: ' + key);
      assert.ok(entry.prefixes.length && entry.steps.length, 'Canonical prefixes and steps required');
      for (const prefix of entry.prefixes) {
        assert.match(prefix.stateSha256, /^[a-f0-9]{64}$/);
        assert.match(prefix.holdingsSha256, /^[a-f0-9]{64}$/);
      }
    }
  }
  assert.equal(dnsNativeTasks.length, 12, 'Twelve exact required native task cases');
  assert.equal(new Set(dnsNativeTasks.map(task => task.taskFamily)).size, 8, 'Eight required native task families');
  assert.equal(dnsNativeTasks.filter(task => task.zoom).length, 8, 'One actual zoom case per required task family');
  for (const task of dnsNativeTasks) {
    const row = dnsNativeManifest.rows.find(item => item.planId === task.planId);
    assert.ok(row?.caseIds.includes(task.caseId), 'Frozen manifest must offer exact required task: ' + task.planId + '/' + task.caseId);
  }
}
function dnsNativeValidateCheckpoints() {
  if (!dnsNativeOptionsValue['checkpoint-report']) return;
  const report = dnsNativeCheckpointReport, identities = dnsNativeReference.identities;
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.kind, 'DNSSEC-independent-contract-check');
  assert.equal(report.mode, 'source', 'Independent checkpoints must come from accepted source production');
  assert.equal(report.passed, true); assert.equal(report.status, 'passed'); assert.equal(report.exitCode, 0);
  assert.equal(report.sourceUnchanged, true); assert.ok(report.finishedAt);
  assert.deepEqual(report.failures, []);
  for (const name of ['requiredCases', 'observedCases', 'passedCases', 'referenceCases', 'attemptedCases', 'persistedCaseRows', 'persistedCaseReferences']) assert.equal(report.counts[name], 159, 'Complete checkpoint producer: ' + name);
  assert.equal(report.counts.failedCases, 0); assert.equal(report.counts.failures, 0);
  assert.equal(report.cases.length, 159);
  assert.deepEqual(report.inputIdentity.review.sourceFiles, identities.sourceFiles, 'Checkpoint/reference complete source identities');
  for (const [actual, expected, label] of [
    [report.htmlSha256, identities.standaloneSha256, 'HTML'],
    [report.inputIdentity.review.standaloneSha256, identities.standaloneSha256, 'review HTML'],
    [report.manifestSha256, identities.manifestSha256, 'manifest'],
    [report.worksheetSha256, identities.worksheetSha256, 'worksheet'],
    [report.inputIdentity.independentFiles[report.worksheet], identities.worksheetSha256, 'captured worksheet'],
    [report.runnerSha256, identities.runnerSha256, 'producer runner'],
  ]) assert.equal(actual, expected, 'Checkpoint/reference identity: ' + label);
  const seen = new Set(); let count = 0;
  for (const row of report.cases) {
    const key = row.id + '/' + row.caseId;
    assert.ok(!seen.has(key), 'Unique checkpoint case ' + key); seen.add(key);
    const entry = dnsNativeReference.cases.find(item => item.id === row.id && item.caseId === row.caseId);
    assert.ok(entry, 'Checkpoint case has canonical reference ' + key);
    assert.equal(row.variant, entry.variant); assert.equal(row.passed, true); assert.deepEqual(row.failures, []);
    assert.equal(row.events, entry.steps.length);
    assert.ok(row.checkpoints.length, 'Independent recorded checkpoints required ' + key);
    const names = new Set();
    for (const checkpoint of row.checkpoints) {
      assert.equal(checkpoint.passed, true);
      assert.ok(checkpoint.name && checkpoint.actorId && checkpoint.boundary);
      assert.ok(!names.has(checkpoint.name), 'Unique independent checkpoint name'); names.add(checkpoint.name);
      assert.ok(Number.isInteger(checkpoint.eventIndex) && checkpoint.eventIndex >= 0 && checkpoint.eventIndex < entry.steps.length);
      assert.equal(checkpoint.sourceEventId, entry.steps[checkpoint.eventIndex].id, 'Recorded canonical source event');
      assert.equal(checkpoint.boundary, entry.steps[checkpoint.eventIndex].boundary, 'Recorded canonical source boundary');
      assert.match(checkpoint.stateSha256, /^[a-f0-9]{64}$/);
      count++;
    }
  }
  assert.equal(count, report.counts.independentCheckpoints, 'All accepted recorded checkpoints retained');
}
async function dnsNativeScreenshot(page, label, failure = false) {
  const normal = dnsNativeReport.screenshots.filter(item => !item.failure).length;
  const failures = dnsNativeReport.screenshots.filter(item => item.failure).length;
  if ((failure && failures >= 24) || (!failure && normal >= 36)) {
    dnsNativeReport.screenshotsOmitted = (dnsNativeReport.screenshotsOmitted || 0) + 1;
    return;
  }
  const file = String(++dnsNativeSequence).padStart(4, '0') + '-' + label.replace(/[^A-Za-z0-9_.-]/g, '-').slice(0, 150) + '.png';
  try {
    if (!failure) {
      await page.locator('.map-panel').scrollIntoViewIfNeeded();
      await dnsNativeSettle(page);
    }
    if (dnsNativeReport.activeDisplay && dnsNativeOptionsValue.scrot) {
      dnsNativeCommand(dnsNativeOptionsValue.scrot, [path.join(dnsNativeOut, file)], {DISPLAY: dnsNativeReport.activeDisplay});
    } else await page.screenshot({path: path.join(dnsNativeOut, file), fullPage: false, timeout: 15000});
    dnsNativeReport.screenshots.push({file, failure, ...dnsNativeDigest(path.join(dnsNativeOut, file))});
  } catch (error) {
    dnsNativeReport.failures.push({kind: 'screenshot', label, error: String(error)});
    if (!failure) throw error;
  }
}
async function dnsNativeCell(stage, axes, page, run) {
  const cell = {sequence: ++dnsNativeSequence, stage, ...axes, passed: false};
  dnsNativeReport.cells.attempted++;
  try { cell.observed = await run(); cell.passed = true; dnsNativeReport.cells.passed++; }
  catch (error) {
    cell.error = error.stack || String(error); dnsNativeReport.cells.failed++;
    dnsNativeReport.failures.push({sequence: cell.sequence, stage, ...axes, error: cell.error});
    if (page && !page.isClosed()) await dnsNativeScreenshot(page, 'failure-' + stage + '-' + cell.sequence, true);
  }
  dnsNativeAppend('cells.jsonl', cell); dnsNativeSave();
  return cell;
}
async function dnsNativeClick(page, selector, touch = false) {
  await dnsNativeSyncZoom(page);
  const target = page.locator(selector).first();
  if (touch) await target.tap(); else await target.click();
  dnsNativeAppend('browser-events.jsonl', {kind: 'interaction', mechanism: touch ? 'tap' : 'click', selector, url: page.url()});
  await dnsNativeSettle(page);
}
async function dnsNativeRange(page, value) {
  await dnsNativeSyncZoom(page);
  await seekNativeRange(page, value, {
    click: selector => dnsNativeClick(page, selector),
    record: evidence => dnsNativeAppend('browser-events.jsonl', evidence),
  });
  await dnsNativeSettle(page);
}
async function dnsNativeObserve(page, entry) {
  const actual = await page.evaluate(() => {
    const app = document.querySelector('auth-flow-studio'), frame = app.heldView.snapshot();
    return {id: app.labScenarioId, caseId: app.labModel.caseId, variant: app.lessonVariant, workspace: app.workspace,
      cursor: frame.cursor, state: app.protocolSnapshot().state,
      holdings: frame.holdings.map(h => ({artifactId: h.artifactId, actorId: h.actorId, store: h.store, representationId: h.representationId, holdingId: h.holdingId})).sort((a, b) => a.holdingId.localeCompare(b.holdingId))};
  });
  assert.equal(actual.id, entry.id); assert.equal(actual.caseId, entry.caseId); assert.equal(actual.workspace, 'dnssec');
  const prefix = entry.prefixes.find(item => item.eventIndex === actual.cursor.eventIndex && item.milestone === actual.cursor.milestone);
  assert.ok(prefix, 'Observed cursor must have exact canonical reference: ' + JSON.stringify(actual.cursor));
  const stateSha256 = dnsNativeHashObject(actual.state), holdingsSha256 = dnsNativeHashObject(actual.holdings);
  assert.equal(stateSha256, prefix.stateSha256, 'Canonical source state');
  assert.equal(holdingsSha256, prefix.holdingsSha256, 'Canonical custody');
  return {cursor: {eventIndex: actual.cursor.eventIndex, milestone: actual.cursor.milestone}, stateSha256, holdingsSha256};
}
async function dnsNativeSelectVariant(page, entry, touch = false) {
  const details = page.locator('#lesson-reference');
  if (await details.getAttribute('open') === null) await dnsNativeClick(page, '#lesson-reference > summary', touch);
  const control = page.locator('#lesson-case');
  const values = await control.locator('option').evaluateAll(elements => elements.map(element => element.value));
  const index = values.indexOf(entry.variant); assert.ok(index >= 0, 'Actual named case control offers ' + entry.variant);
  await control.focus(); await page.keyboard.press('Home');
  for (let i = 0; i < index; i++) await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter'); await dnsNativeSettle(page);
  assert.equal(await control.inputValue(), entry.variant);
  dnsNativeAppend('browser-events.jsonl', {kind: 'interaction', mechanism: 'native-case-selector-keyboard', id: entry.id, caseId: entry.caseId, variant: entry.variant, keys: {Home: 1, ArrowDown: index, Enter: 1}});
  const selected = await page.evaluate(() => { const app = document.querySelector('auth-flow-studio'); return {id: app.labScenarioId, caseId: app.labModel.caseId, variant: app.lessonVariant}; });
  assert.deepEqual(selected, {id: entry.id, caseId: entry.caseId, variant: entry.variant});
}
async function dnsNativeChoose(page, entry, touch = false) {
  await page.locator('#lab-scenario-search').fill(entry.id);
  await dnsNativeClick(page, '[data-scenario-option=' + JSON.stringify(entry.id) + ']', touch);
  if (entry.variant !== 'default') await dnsNativeSelectVariant(page, entry, touch);
  if (await page.evaluate(() => document.querySelector('auth-flow-studio').hasTrace)) await dnsNativeClick(page, '[data-clear-trace]', touch);
  const selected = await page.evaluate(() => { const app = document.querySelector('auth-flow-studio'); return {id: app.labScenarioId, caseId: app.labModel.caseId, variant: app.lessonVariant}; });
  assert.deepEqual(selected, {id: entry.id, caseId: entry.caseId, variant: entry.variant});
}
async function dnsNativeWorkspace(page, family, touch = false) {
  const before = await page.evaluate(() => document.querySelector('auth-flow-studio').labScenarioId);
  await page.locator('#workspace-search').fill(family || 'DNSSEC');
  assert.equal(await page.evaluate(() => document.querySelector('auth-flow-studio').labScenarioId), before, 'Search does not navigate');
  const id = family ? 'family-dnssec-' + family : 'workspace-dnssec';
  await dnsNativeClick(page, '[data-workspace-option=' + JSON.stringify(id) + ']', touch);
  assert.equal(await page.evaluate(() => document.querySelector('auth-flow-studio').workspace), 'dnssec');
  if (family) assert.equal(await page.evaluate(() => document.querySelector('auth-flow-studio').labModel.family), family, 'Actual family destination');
}
async function dnsNativeReplay(page, entry, mode, captureTask = false, representative = false) {
  const visible = await page.evaluate(() => {
    const app = document.querySelector('auth-flow-studio'), clock = app.studyClock();
    return clock.steps.map((step, index) => ({stepId: step.id, sourceStepId: Object.hasOwn(step, 'sourceStepId') ? step.sourceStepId : step.id, initialContext: step.traceKind === 'initial' && step.sourceIndex === -1, visibleIndex: index,
      value: Math.max(1, Math.min(999, Math.round((clock.offsets[index] + clock.durations[index] * .5) / clock.total * 1000)))}));
  });
  assert.ok(visible.length, 'Replay must have real native seek rows');
  for (const target of visible) {
    target.sourceIndex = target.initialContext ? -1 : entry.steps.findIndex(step => step.id === target.sourceStepId);
    if (target.initialContext) assert.equal(target.sourceStepId, null, 'Provisioned exact history has no fabricated source event');
    else assert.ok(target.sourceIndex >= 0, 'Visible row has real canonical source event');
    target.checkpoints = [];
  }
  if (mode === 'full') assert.deepEqual(visible.map(target => target.stepId), entry.steps.map(step => step.id), 'Full journey uses real canonical source rows');
  const finalEndpointCheckpoints = [];
  const selected = new Set(representative ? [0, Math.floor(visible.length / 2), visible.length - 1] : visible.map((_, index) => index));
  if (representative && mode === 'full') {
    const recorded = dnsNativeCheckpointReport.cases.find(row => row.id === entry.id && row.caseId === entry.caseId);
    assert.ok(recorded, 'Accepted independent checkpoint case required');
    for (const checkpoint of recorded.checkpoints) {
      for (const [sourceIndex, relation] of [[checkpoint.eventIndex, 'checkpoint'], [checkpoint.eventIndex + 1, 'successor']]) {
        if (sourceIndex === entry.steps.length) {
          finalEndpointCheckpoints.push({name: checkpoint.name, relation: 'final-endpoint-after-last-checkpoint', recordedSourceIndex: checkpoint.eventIndex, recordedSourceEventId: checkpoint.sourceEventId});
          continue;
        }
        const index = visible.findIndex(target => target.sourceIndex === sourceIndex);
        assert.ok(index >= 0, 'Recorded checkpoint and successor are actual visible full rows');
        selected.add(index);
        visible[index].checkpoints.push({name: checkpoint.name, relation, recordedSourceIndex: checkpoint.eventIndex, recordedSourceEventId: checkpoint.sourceEventId});
      }
    }
  }
  const targets = [{value: 0, sourceIndex: null, checkpoints: [], endpoint: 'initial'}, ...visible.filter((_, index) => selected.has(index)), {value: 1000, sourceIndex: null, checkpoints: finalEndpointCheckpoints, endpoint: 'final'}];
  assert.equal(new Set(targets.map(target => target.value)).size, targets.length, 'Native slider must resolve every selected row, no silent quantization omissions');
  const hashes = [];
  const transitions = [];
  let lastTaskDigest;
  for (const direction of ['forward', 'backward']) for (const target of direction === 'forward' ? targets : [...targets].reverse()) {
    await dnsNativeRange(page, target.value);
    if (target.stepId) assert.equal(await page.evaluate(() => document.querySelector('auth-flow-studio').player.snapshot().step?.id), target.stepId, 'Native seek reaches exact visible replay row');
    hashes.push({direction, ...target, stepId: target.stepId || null, ...await dnsNativeObserve(page, entry)});
    if (captureTask && direction === 'forward') {
      const snapshot = await dnsNativeTaskSnapshot(page), digest = dnsNativeHashObject(snapshot.state);
      if (digest !== lastTaskDigest) {
        transitions.push({value: target.value, cursor: hashes.at(-1).cursor, ...snapshot});
        lastTaskDigest = digest;
      }
    }
  }
  return {mode, coverageMode: representative ? (mode === 'full' ? 'representative-first-middle-last-and-independent-checkpoints-with-successors' : 'representative-first-middle-last') : 'exhaustive-every-visible-row', availableNativeRows: visible.length, nativeRows: targets.length - 2, positions: targets.length, selectedRows: targets.filter(target => target.stepId), endpoints: ['initial', 'final'], directions: ['forward', 'backward'], observations: hashes, ...(captureTask ? {transitions} : {})};
}
async function dnsNativeOpenHolding(page, entry, touch = false) {
  await dnsNativeRange(page, 1000);
  const holding = await page.evaluate(inspection => document.querySelector('auth-flow-studio').heldView.snapshot().holdings.find(h => h.artifactId === inspection.artifactId && h.actorId === inspection.actorId && (!inspection.representationId || h.representationId === inspection.representationId)), entry.inspection);
  assert.ok(holding, 'Actual final held inspection object exists, including management intent/anchor');
  await dnsNativeClick(page, '#held-objects [data-held-action=' + JSON.stringify('picker:' + holding.actorId) + ']', touch);
  await dnsNativeClick(page, '#held-objects [data-holding-id=' + JSON.stringify(holding.holdingId) + ']', touch);
  assert.ok((await page.locator('#held-inspector').innerText()).includes(entry.inspection.artifactId));
  return {artifactId: holding.artifactId, actorId: holding.actorId, store: holding.store, representationId: holding.representationId};
}
async function dnsNativeCore(page, entry, touch = false, captureTask = false, representative = false) {
  await dnsNativeChoose(page, entry, touch);
  const full = await dnsNativeReplay(page, entry, 'full', captureTask, representative);
  await dnsNativeRange(page, 1000);
  const final = await page.evaluate(() => document.querySelector('auth-flow-studio').protocolSnapshot().state.dnssec);
  assert.equal(final.securityStatus, entry.final.securityStatus); assert.deepEqual(final.applicationResult, entry.final.applicationResult);
  if (!await page.locator('#attribute-search').isVisible()) await dnsNativeClick(page, '#index-open', touch);
  const fieldName = await page.evaluate(id => document.querySelector('auth-flow-studio').definition(id).name, entry.fieldId);
  await page.locator('#attribute-search').fill(fieldName);
  await dnsNativeClick(page, '[data-index-attribute=' + JSON.stringify(entry.fieldId) + ']', touch);
  assert.equal(await page.evaluate(() => document.querySelector('auth-flow-studio').attributeSelection), entry.fieldId);
  const field = await dnsNativeReplay(page, entry, 'field', false, representative);
  await dnsNativeClick(page, '[data-clear-trace]', touch);
  const inspection = await dnsNativeOpenHolding(page, entry, touch);
  await dnsNativeClick(page, '[data-held-trace=' + JSON.stringify(entry.inspection.artifactId) + ']', touch);
  assert.equal(await page.evaluate(() => document.querySelector('auth-flow-studio').objectTraceSelection), entry.inspection.artifactId);
  const exact = await dnsNativeReplay(page, entry, 'exact', false, representative);
  await dnsNativeClick(page, '[data-clear-trace]', touch); await dnsNativeClick(page, '#reset', touch);
  const reset = await dnsNativeObserve(page, entry); assert.equal(reset.cursor.eventIndex, -1, 'Reset initial canonical source cursor');
  return {coverageMode: representative ? 'representative-native-controls-and-task-checkpoints' : 'exhaustive-native-default-rows', fieldId: entry.fieldId, full, field, exact, final: {securityStatus: final.securityStatus, applicationResult: final.applicationResult}, inspection, reset};
}
async function dnsNativeTaskSnapshot(page) {
  return page.evaluate(() => {
    const app = document.querySelector('auth-flow-studio'), protocol = app.protocolSnapshot().state, state = protocol.dnssec;
    const pick = (object, keys) => Object.fromEntries(keys.filter(key => object && Object.hasOwn(object, key)).map(key => [key, object[key]]));
    const compactEntry = (entry, slot) => ({
      slot, ...pick(entry, ['id', 'kind', 'key', 'generation', 'sourceGeneration', 'rrsetId', 'keys', 'provider', 'source', 'receivedAt', 'validatedAt', 'expiresAt', 'remainingTtl', 'signatureDeadline', 'receivedTtl', 'originalTtl', 'securityStatus', 'validationOwner', 'checkingContext', 'queryCD', 'rcode', 'upstreamCO', 'hasSignedNXNAME', 'usableInCurrentContext']),
      provenance: pick(entry?.provenance, ['view', 'trustStore', 'validationOwner', 'receivedObjectRef']),
      expiredAtCurrentClock: Number.isFinite(entry?.expiresAt) ? entry.expiresAt <= protocol.protocolClock : null,
    });
    const cacheEntries = Object.entries(state.cacheEntries || {}).map(([slot, entry]) => compactEntry(entry, slot));
    const hopContexts = new Map();
    for (const hop of state.response?.hops || []) {
      const query = hop.query || {}, response = hop.response || {};
      const key = JSON.stringify([hop.from, hop.to, hop.question?.qtype, query.flags?.CD, query.edns?.CO ?? query.flags?.CO]);
      hopContexts.set(key, {
        from: hop.from, to: hop.to, question: pick(hop.question, ['qname', 'qtype']),
        query: {messageId: query.messageId, flags: pick(query.flags, ['AD', 'CD', 'DO', 'CO']), edns: pick(query.edns, ['present', 'DO', 'CO'])},
        response: {messageId: response.messageId, rcode: response.rcode, flags: pick(response.flags, ['AD', 'CD', 'DO', 'CO']), edns: pick(response.edns, ['present', 'DO', 'CO'])},
      });
    }
    const timers = Object.fromEntries(Object.entries(state.timers || {}).map(([name, value]) => [name, value === null || typeof value !== 'object' ? value : Object.fromEntries(Object.entries(value).filter(([, field]) => field === null || ['number', 'string', 'boolean'].includes(typeof field)))]));
    const rendered = {};
    for (const [name, id] of [['clock', 'lifetime-strip'], ['decisions', 'lesson-decisions'], ['event', 'inspector']]) {
      const element = app.querySelector('#' + id), text = element?.innerText?.trim() || '';
      rendered[name] = {visible: !!element && !element.closest('[hidden]') && element.getBoundingClientRect().width > 0, characters: text.length, excerpt: text.slice(0, name === 'event' ? 160 : 420)};
    }
    return {
      state: {
        ...pick(state, ['clock', 'securityStatus', 'reasonCode', 'received', 'signatureChecked', 'chainEstablished', 'denialChecked', 'acceptedForUse', 'cached', 'cacheKind', 'validationOwner', 'verificationKind', 'checkedAt', 'returnedToStub', 'stoppedAction']),
        protocolClock: protocol.protocolClock, cacheEntries, timers,
        publication: pick(state.publication, ['childGeneration', 'dnskeys', 'answerSignatures', 'parentDsGeneration', 'parentDsKeys', 'parentAccepted', 'parentPublished', 'signalsAuthenticated', 'consistencyChecked', 'consistent', 'childStillSigning', 'answerSource', 'dnskeyRefetchNeeded', 'availableAlternativePath', 'proofResult', 'result', 'proofZone', 'closestEncloser', 'nextCloser', 'nextCloserCovered', 'OptOut', 'delegationIsInsecure', 'entireIntervalNamesAbsent', 'aggressiveSynthesisAllowed', 'NXNAME', 'NSECMatchesQname']),
        validators: Object.fromEntries(Object.entries(state.validators || {}).map(([owner, value]) => [owner, pick(value, ['signatureChecked', 'chainEstablished', 'securityStatus', 'verificationKind', 'checkedAt', 'reused', 'locallyEstablishedFailure', 'freshCheckPerformed', 'oldEntryEligible', 'freshSignatureChecked'])])),
        response: {...pick(state.response, ['rcode', 'upstreamAD', 'upstreamQueryCD', 'downstreamQueryCD', 'upstreamRcode', 'freshRcode', 'upstreamCO', 'downstreamQueryDO', 'downstreamQueryCO', 'downstreamRcode', 'downstreamCO', 'cachedUpstreamRcode', 'cachedUpstreamCO']), rawHopCount: (state.response?.hops || []).length, latestHopPerEdgeTypeAndCheckingContext: [...hopContexts.values()]},
        transport: pick(state.transport, ['attempted', 'completed', 'authorityQueries', 'upstreamQueries', 'upstreamFreshQueries', 'upstreamQueryCD', 'failure']),
        application: pick(state.applicationResult, ['status', 'code', 'kind', 'positiveAnswerAccepted', 'addresses']),
      },
      rendered,
    };
  });
}
async function dnsNativeVariantReset(page, entry, touch) {
  if (!await page.locator('#attribute-search').isVisible()) await dnsNativeClick(page, '#index-open', touch);
  const fieldName = await page.evaluate(id => document.querySelector('auth-flow-studio').definition(id).name, entry.fieldId);
  await page.locator('#attribute-search').fill(fieldName);
  await dnsNativeClick(page, '[data-index-attribute=' + JSON.stringify(entry.fieldId) + ']', touch);
  await dnsNativeRange(page, 1000);
  const alternate = dnsNativeReference.cases.find(item => item.id === entry.id && item.caseId !== entry.caseId);
  assert.ok(alternate, 'Required actual alternate case for variant-reset exercise');
  const observations = [];
  for (const target of [alternate, entry]) {
    await dnsNativeSelectVariant(page, target, touch);
    const trace = await page.evaluate(() => {
      const app = document.querySelector('auth-flow-studio');
      return {attribute: app.attributeSelection, object: app.objectTraceSelection, rows: app.traceQueue.length, cursor: app.heldView.snapshot().cursor};
    });
    assert.equal(trace.attribute, null, 'Variant change clears ordinary field replay');
    assert.equal(trace.object, null, 'Variant change clears exact-object replay');
    assert.equal(trace.rows, 0, 'Variant change clears prior replay rows');
    assert.equal(trace.cursor.eventIndex, -1, 'Variant change restores its own initial canonical history');
    observations.push({caseId: target.caseId, variant: target.variant, canonical: await dnsNativeObserve(page, target), traceCleared: true});
  }
  return observations;
}
async function dnsNativeTaskJourney(page, entry, task, touch = false) {
  const replay = await dnsNativeCore(page, entry, touch, true, true), transitions = replay.full.transitions;
  assert.ok(transitions.length >= 2, 'Named task must expose meaningful observed state transitions');
  assert.ok(transitions.some(item => item.state.validationOwner), 'Actual validation/management owner observed');
  const clocks = [...new Set(transitions.map(item => item.state.protocolClock))];
  const cacheObservations = transitions.filter(item => item.state.cacheEntries.length);
  if (['cache-expiry', 'rollover-clock', 'provider-switch'].includes(task.taskFamily)) {
    assert.ok(clocks.length > 1, 'Required task exercises the actual represented protocol clock');
    assert.ok(cacheObservations.length, 'Required task exposes concrete retained cache generations/deadlines');
    assert.ok(transitions.some(item => item.rendered.clock.visible && item.rendered.clock.characters), 'Real clock/cache timeline is rendered');
  }
  const final = transitions.at(-1).state;
  if (task.taskFamily === 'compact-denial-co') {
    for (const name of ['upstreamCO', 'downstreamQueryCO', 'downstreamRcode']) assert.ok(Object.hasOwn(final.response, name), 'Actual per-hop CO/RCODE context required: ' + name);
    assert.ok(final.response.latestHopPerEdgeTypeAndCheckingContext.length, 'Actual hop header contexts observed');
  }
  const variantReset = await dnsNativeVariantReset(page, entry, touch);
  // Navigate away while an exact-object replay is active: the workspace picker
  // must not carry the old named case or trace into its destination.
  await dnsNativeOpenHolding(page, entry, touch);
  await dnsNativeClick(page, '[data-held-trace=' + JSON.stringify(entry.inspection.artifactId) + ']', touch);
  await dnsNativeRange(page, 1000);
  await dnsNativeWorkspace(page, undefined, touch);
  const navigation = await page.evaluate(() => {
    const app = document.querySelector('auth-flow-studio');
    return {id: app.labScenarioId, caseId: app.labModel.caseId, variant: app.lessonVariant, attribute: app.attributeSelection, object: app.objectTraceSelection, rows: app.traceQueue.length};
  });
  assert.equal(navigation.id, 'lab-dnssec01'); assert.equal(navigation.variant, 'default');
  assert.equal(navigation.attribute, null); assert.equal(navigation.object, null); assert.equal(navigation.rows, 0);
  const destination = dnsNativeReference.cases.find(item => item.id === navigation.id && item.caseId === navigation.caseId);
  const destinationCanonical = await dnsNativeObserve(page, destination);
  await dnsNativeChoose(page, entry, touch);
  return {taskFamily: task.taskFamily, caseId: entry.caseId, replay, clocks, cacheTransitionCount: cacheObservations.length, finalObserved: final, variantReset, workspaceNavigation: {selected: navigation, canonical: destinationCanonical}, returnedToTask: await dnsNativeObserve(page, entry)};
}
async function dnsNativeGeometry(page) {
  await dnsNativeSettle(page);
  const result = await page.evaluate(() => {
    const app = document.querySelector('auth-flow-studio');
    const box = element => { const r = element.getBoundingClientRect(); return {left: r.left, right: r.right, top: r.top, bottom: r.bottom, width: r.width, height: r.height}; };
    const visible = element => { const r = element.getBoundingClientRect(); return r.width > 0 && r.height > 0 && !element.closest('[hidden]') && getComputedStyle(element).visibility !== 'hidden' && getComputedStyle(element).display !== 'none'; };
    const graph = box(app.refs.graph);
    const cards = [...app.querySelectorAll('.actor-card,.held-dock,.held-compact-summary')].filter(visible).map(element => ({id: element.dataset.actor || element.dataset.heldDock || 'summary', kind: element.className, ...box(element)}));
    const overlaps = [], violations = [], routes = [];
    for (let i = 0; i < cards.length; i++) for (let j = i + 1; j < cards.length; j++) {
      const a = cards[i], b = cards[j];
      if (a.left < b.right - 1 && a.right > b.left + 1 && a.top < b.bottom - 1 && a.bottom > b.top + 1) overlaps.push([a.id, b.id]);
    }
    for (const route of app.refs.connections.querySelectorAll('.connection-line')) {
      if (!visible(route)) continue;
      const length = route.getTotalLength(), matrix = route.getScreenCTM();
      if (!matrix || length <= 0) { violations.push({kind: 'missing-route-transform'}); continue; }
      const problems = new Set(); let samples = 0;
      for (let distance = 0; distance <= Math.ceil(length); distance += 6) {
        const point = route.getPointAtLength(Math.min(distance, length)), screen = new DOMPoint(point.x, point.y).matrixTransform(matrix); samples++;
        if (screen.x < graph.left - 1 || screen.x > graph.right + 1 || screen.y < graph.top - 1 || screen.y > graph.bottom + 1) problems.add('outside graph');
        if (distance > 6 && distance < length - 6) for (const card of cards) if (screen.x > card.left + 2 && screen.x < card.right - 2 && screen.y > card.top + 2 && screen.y < card.bottom - 2) problems.add('inside ' + card.id);
      }
      const pair = route.closest('[data-pair]')?.dataset.pair; routes.push({pair, samples});
      if (problems.size) violations.push({pair, problems: [...problems]});
    }
    return {chapter: app.graphChapter?.id, internals: app.showInternals, geometry: app.refs.graph.dataset.heldGeometry, documentOverflow: document.documentElement.scrollWidth > innerWidth + 1, graph, cards, routes, overlaps, violations,
      outside: cards.filter(card => card.left < graph.left - 1 || card.right > graph.right + 1 || card.top < graph.top - 1 || card.bottom > graph.bottom + 1).map(card => card.id)};
  });
  assert.ok(result.cards.length, 'Rendered physical participants required');
  assert.equal(result.documentOverflow, false, 'Document horizontal bounds');
  assert.deepEqual(result.overlaps, [], 'Physical card/dock/summary overlap');
  assert.deepEqual(result.outside, [], 'Physical card/dock/summary graph bounds');
  assert.deepEqual(result.violations, [], 'Transformed SVG route graph/card-interior bounds');
  return result;
}
async function dnsNativeBoundSurface(page, selector) {
  const result = await page.locator(selector).evaluate(element => {
    const box = element.getBoundingClientRect(), style = getComputedStyle(element);
    return {width: box.width, height: box.height, left: box.left, right: box.right, viewportWidth: innerWidth, scrollWidth: element.scrollWidth, clientWidth: element.clientWidth, overflowX: style.overflowX,
      badChildren: [...element.querySelectorAll('pre,code,button,a')].filter(child => { const r = child.getBoundingClientRect(); return r.width && r.height && (r.left < box.left - 1 || r.right > box.right + 1) && !['auto', 'scroll'].includes(getComputedStyle(child.parentElement).overflowX); }).length};
  });
  assert.ok(result.width > 0 && result.height > 0, 'Inspection surface visible');
  assert.ok(result.left >= -1 && result.right <= result.viewportWidth + 1, 'Inspection surface mobile bounds');
  assert.equal(result.badChildren, 0, 'Inspection values remain inside intentional scroll surface');
  return result;
}
async function dnsNativeInspect(page, entry, touch = false, requirePayload = entry.id === 'lab-dnssec01') {
  const inspection = await dnsNativeOpenHolding(page, entry, touch);
  const held = await dnsNativeBoundSurface(page, '#held-inspector');
  await dnsNativeClick(page, '#held-inspector [data-held-help]', touch);
  const help = await dnsNativeBoundSurface(page, '#held-inspector .held-help');
  await page.locator('#held-inspector [data-held-help-close]').focus(); await page.keyboard.press('Escape');
  const helpClosed = await page.locator('#held-inspector .held-help').count(); assert.equal(helpClosed, 0, 'Escape closes real help dialog');
  const payload = await page.evaluate(() => {
    const app = document.querySelector('auth-flow-studio'), clock = app.studyClock();
    let best;
    clock.steps.forEach((step, index) => (step.detailedPayload || step.payload || []).forEach(item => { const value = typeof item.value === 'string' ? item.value : JSON.stringify(item.value); if (!best || value.length > best.length) best = {stepId: step.id, length: value.length, value: Math.max(1, Math.min(999, Math.round((clock.offsets[index] + clock.durations[index] * .5) / clock.total * 1000)))}; }));
    return best;
  });
  assert.ok(payload, 'Real authored payload exists');
  await dnsNativeRange(page, payload.value);
  const fields = page.locator('.progressive-fields > summary');
  if (await fields.count() && await fields.first().isVisible()) await fields.first().click();
  const long = page.locator('.long-protocol-value > summary');
  let longValue;
  if (await long.count()) {
    await long.first().click();
    longValue = await dnsNativeBoundSurface(page, '.long-protocol-value[open]');
    const text = await page.locator('.long-protocol-value[open] .field-value').innerText();
    assert.ok(text.length > 120, 'Long payload expansion exposes real full value');
    longValue.characters = text.length;
  } else if (requirePayload) assert.fail('No real long-value control in required representative payload inspection');
  const attribute = page.locator('.payload-row [data-attribute]').first();
  assert.ok(await attribute.count(), 'Payload has actual field explanation control');
  await attribute.focus(); await page.keyboard.press('F2'); await dnsNativeSettle(page);
  const popup = await dnsNativeBoundSurface(page, '#attribute-popup');
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#attribute-popup').isVisible(), false, 'Escape closes actual attribute popup');
  return {inspection, held, help, payload: {stepId: payload.stepId, characters: payload.length}, longValue: longValue || null, popup};
}
async function dnsNativeFooter(page) {
  const footer = page.locator('.studio-credit'); await footer.scrollIntoViewIfNeeded();
  assert.equal((await page.locator('#studio-version').innerText()).trim(), '1.0', 'Required visible footer version');
  const links = [['https://github.com/andrico21', 'Kirill Andrienko'], ['https://github.com/andrico21/auth-lab', 'andrico21/auth-lab']];
  const observations = [];
  // Tab reaches credit links from the preceding native footer summary; no focus() on tested links.
  const summary = page.locator('.sources-footer > details > summary'); await summary.focus();
  for (const [href, label] of links) {
    const target = footer.locator('a[href=' + JSON.stringify(href) + ']');
    assert.equal((await target.innerText()).trim(), label); assert.ok(await target.isVisible());
    let reached = false;
    for (let i = 0; i < 8; i++) { await page.keyboard.press('Tab'); if (await target.evaluate(element => element === document.activeElement)) { reached = true; break; } }
    assert.ok(reached, 'Credit link keyboard reachable: ' + label);
    observations.push(await target.evaluate(element => { const r = element.getBoundingClientRect(); return {href: element.href, label: element.textContent, focusVisible: element.matches(':focus-visible'), left: r.left, right: r.right, viewportWidth: innerWidth}; }));
    assert.ok(observations.at(-1).focusVisible); assert.ok(observations.at(-1).left >= 0 && observations.at(-1).right <= observations.at(-1).viewportWidth + 1);
  }
  return {version: '1.0', links: observations, bounds: await dnsNativeBoundSurface(page, '.studio-credit')};
}
async function dnsNativeFocus(page) {
  await page.locator('#reset').focus(); await page.keyboard.press('Tab');
  const state = await page.evaluate(() => { const element = document.activeElement, r = element.getBoundingClientRect(); return {id: element.id, connected: element.isConnected, focusVisible: element.matches(':focus-visible'), width: r.width, height: r.height, left: r.left, right: r.right, viewportWidth: innerWidth}; });
  assert.ok(state.connected && state.focusVisible && state.width > 0 && state.height > 0, 'Real keyboard focus visible');
  assert.ok(state.left >= -1 && state.right <= state.viewportWidth + 1, 'Keyboard focus mobile bounds'); return state;
}
async function dnsNativeNewPage(browser, mode, settings = {}) {
  const touch = settings.touch || false;
  const context = await browser.newContext({viewport: touch ? {width: 390, height: 844} : {width: 1480, height: 1000}, hasTouch: touch, isMobile: touch, reducedMotion: settings.motion || 'no-preference', colorScheme: settings.theme || 'dark'});
  return dnsNativeAttach(context, mode, settings);
}
async function dnsNativeAttach(context, mode, settings = {}) {
  const page = context.pages()[0] || await context.newPage();
  const session = {id: dnsNativeReport.sessions.length + 1, mode, ...settings, errors: 0, console: 0, csp: 0, externalRequests: 0}; dnsNativeReport.sessions.push(session);
  const event = (kind, value) => dnsNativeAppend('browser-events.jsonl', {session: session.id, kind, ...value});
  await context.exposeBinding('dnsNativeCsp', (_source, value) => { session.csp++; event('csp', value); });
  await context.addInitScript(() => document.addEventListener('securitypolicyviolation', e => window.dnsNativeCsp({directive: e.effectiveDirective, blockedURI: e.blockedURI, sourceFile: e.sourceFile, lineNumber: e.lineNumber})));
  page.on('pageerror', error => { session.errors++; event('pageerror', {message: error.stack || String(error)}); });
  page.on('console', message => { session.console++; if (message.type() === 'error') session.errors++; event('console', {type: message.type(), text: message.text(), location: message.location()}); });
  page.on('requestfailed', request => { session.errors++; event('requestfailed', {url: request.url(), failure: request.failure()}); });
  await context.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (['http:', 'https:'].includes(url.protocol) && url.origin !== dnsNativeOrigin) { session.externalRequests++; event('blocked-external-request', {url: url.href}); await route.abort(); }
    else await route.continue();
  });
  const url = mode === 'source-http' ? dnsNativeOrigin + '/' : mode === 'standalone-http' ? dnsNativeOrigin + '/dist/auth-flow-studio.html' : pathToFileURL(path.join(dnsNativeRoot, 'dist/auth-flow-studio.html')).href;
  await page.goto(url, {waitUntil: 'load'});
  await page.waitForFunction(() => document.querySelector('auth-flow-studio')?.heldView?.compiled()); await dnsNativeSettle(page);
  return {context, page, session};
}
async function dnsNativeSessionEnd(active) {
  await dnsNativeCell('browser-log', {session: active.session.id, mode: active.session.mode}, active.page, async () => {
    assert.equal(active.session.errors, 0, 'Browser/page/console/request errors'); assert.equal(active.session.csp, 0, 'CSP violations'); assert.equal(active.session.externalRequests, 0, 'Unexpected external requests'); return active.session;
  });
  await active.context.close();
}
function dnsNativeCommand(program, argv, environment = {}) {
  const index = dnsNativeReport.subprocesses.length + 1;
  const result = spawnSync(program, argv, {env: {...process.env, ...environment}, encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 * 1024});
  const prefix = 'subprocess-' + index;
  fs.writeFileSync(path.join(dnsNativeOut, prefix + '.stdout'), result.stdout || '', {flag: 'wx'});
  fs.writeFileSync(path.join(dnsNativeOut, prefix + '.stderr'), result.stderr || '', {flag: 'wx'});
  dnsNativeReport.subprocesses.push({program, identity: dnsNativeDigest(program), argv, status: result.status, signal: result.signal, error: result.error ? String(result.error) : null, stdout: prefix + '.stdout', stderr: prefix + '.stderr'});
  dnsNativeSave(); assert.equal(result.status, 0, 'Native subprocess ' + program); return (result.stdout || '').trim();
}
async function dnsNativeZoom(chromium) {
  for (const key of ['xvfb', 'xdotool', 'scrot']) {
    assert.ok(dnsNativeOptionsValue[key], 'NOT_PERFORMED_REQUIRED_ZOOM: missing --' + key);
    fs.accessSync(dnsNativeOptionsValue[key], fs.constants.X_OK);
  }
  const xvfbOut = fs.openSync(path.join(dnsNativeOut, 'xvfb.stdout'), 'wx'), xvfbErr = fs.openSync(path.join(dnsNativeOut, 'xvfb.stderr'), 'wx');
  dnsNativeXvfb = spawn(dnsNativeOptionsValue.xvfb, ['-displayfd', '3', '-screen', '0', '1600x1200x24', '-nolisten', 'tcp', '-ac'], {stdio: ['ignore', xvfbOut, xvfbErr, 'pipe'], env: process.env});
  fs.closeSync(xvfbOut); fs.closeSync(xvfbErr);
  const display = await new Promise((resolve, reject) => {
    let text = ''; const timer = setTimeout(() => reject(new Error('Xvfb display allocation timeout')), 15000);
    dnsNativeXvfb.once('error', error => { clearTimeout(timer); reject(error); });
    dnsNativeXvfb.once('exit', code => { clearTimeout(timer); reject(new Error('Xvfb exited before ready: ' + code)); });
    dnsNativeXvfb.stdio[3].on('data', data => { text += data; if (/^\d+\n/.test(text)) { clearTimeout(timer); resolve(':' + text.trim()); } });
  });
  dnsNativeReport.zoom.display = display; dnsNativeReport.zoom.displayServer = {pid: dnsNativeXvfb.pid, program: dnsNativeOptionsValue.xvfb, identity: dnsNativeDigest(dnsNativeOptionsValue.xvfb)};
  dnsNativeReport.activeDisplay = display;
  dnsNativeReport.zoom.mechanism = 'headed-isolated-Xvfb-genuine-Chrome-keyboard-shortcuts';
  let browser, context;
  try {
    browser = await chromium.launch({executablePath: dnsNativeOptionsValue.chrome, headless: false, env: {...process.env, DISPLAY: display}, args: ['--no-sandbox', '--disable-dev-shm-usage', '--ozone-platform=x11', '--window-size=1480,1000', '--no-first-run', '--disable-background-networking', '--disable-component-update']});
    dnsNativeReport.browser = browser.version();
    dnsNativeReport.zoom.contextIsolation = 'Fresh Playwright context per loading mode; no persistent-profile reuse';
    dnsNativeReport.zoom.loadingModeOrder = ['standalone-file', 'source-http', 'standalone-http'];
    for (const mode of dnsNativeReport.zoom.loadingModeOrder) {
      context = await browser.newContext({viewport: null});
      const active = await dnsNativeAttach(context, mode, {headed: true});
      const {page} = active; await page.bringToFront();
      const title = 'DNSSEC Native Zoom ' + process.pid;
      await page.evaluate(title => { document.title = title; }, title);
      const windowId = dnsNativeCommand(dnsNativeOptionsValue.xdotool, ['search', '--sync', '--onlyvisible', '--name', '^' + title], {DISPLAY: display}).split('\n');
      assert.equal(windowId.length, 1, 'Exactly one isolated Chrome window');
      dnsNativeCommand(dnsNativeOptionsValue.xdotool, ['windowfocus', '--sync', windowId[0]], {DISPLAY: display});
      const measure = () => page.evaluate(() => ({dpr: devicePixelRatio, innerWidth, outerWidth, scale: visualViewport.scale}));
      dnsNativeCommand(dnsNativeOptionsValue.xdotool, ['key', '--clearmodifiers', 'ctrl+0'], {DISPLAY: display}); await dnsNativeSettle(page);
      const baseline = await measure();
      for (const [percent, presses] of [[100, 0], [150, 3], [200, 5]]) {
        dnsNativeZoomStates.set(page, {url: page.url(), display, baselineDpr: baseline.dpr, percent, presses});
        dnsNativeCommand(dnsNativeOptionsValue.xdotool, ['key', '--clearmodifiers', 'ctrl+0'], {DISPLAY: display});
        for (let i = 0; i < presses; i++) dnsNativeCommand(dnsNativeOptionsValue.xdotool, ['key', '--clearmodifiers', 'ctrl+plus'], {DISPLAY: display});
        await page.waitForFunction(({dpr, ratio}) => Math.abs(devicePixelRatio / dpr - ratio) < .025, {dpr: baseline.dpr, ratio: percent / 100}, {timeout: 10000});
        for (const task of dnsNativeTasks.filter(item => item.zoom)) {
          const {planId, caseId, taskFamily} = task;
          const row = dnsNativeManifest.rows.find(item => item.planId === planId), entry = dnsNativeReference.cases.find(item => item.id === row.runtimeId && item.caseId === caseId);
          const taskCell = await dnsNativeCell('zoom', {mode, percent, planId, taskFamily, id: entry.id, caseId}, page, async () => {
            await dnsNativeWorkspace(page, row.family); const taskEvidence = await dnsNativeTaskJourney(page, entry, task); await dnsNativeChoose(page, entry); await dnsNativeRange(page, 1000);
            const actual = await measure(); assert.ok(Math.abs(actual.dpr / baseline.dpr - percent / 100) < .025, 'Actual Chrome page zoom DPR'); assert.equal(actual.scale, 1, 'Not pinch/CSS/CDP scale');
            const result = {mechanism: 'xdotool Chrome Ctrl+0 / Ctrl+plus', baseline, actual, taskEvidence, geometry: await dnsNativeGeometry(page), canonical: await dnsNativeObserve(page, entry), inspection: await dnsNativeInspect(page, entry), focus: await dnsNativeFocus(page), footer: await dnsNativeFooter(page)};
            dnsNativeReport.coverage.zoomCells++;
            if (planId === 'DNS01') await dnsNativeScreenshot(page, 'zoom-' + mode + '-' + percent); return result;
          });
          assert.equal(taskCell.passed, true, 'Named native zoom task failed; remaining matrix is unperformed');
        }
      }
      await dnsNativeSessionEnd(active); context = null;
    }
    dnsNativeReport.zoom.performed = true;
  } finally {
    await context?.close(); await browser?.close(); dnsNativeReport.activeDisplay = null;
    dnsNativeXvfb?.kill('SIGTERM'); dnsNativeXvfb = null;
  }
}

try {
  dnsNativeReport.before = dnsNativeIdentity();
  dnsNativeReference = JSON.parse(fs.readFileSync(dnsNativeOptionsValue.reference, 'utf8'));
  dnsNativeManifest = JSON.parse(fs.readFileSync(path.join(dnsNativeRoot, 'docs/dnssec-expansion/scenario-manifest.json'), 'utf8'));
  if (dnsNativeOptionsValue['checkpoint-report']) dnsNativeCheckpointReport = JSON.parse(fs.readFileSync(dnsNativeOptionsValue['checkpoint-report'], 'utf8'));
  dnsNativeValidateReference();
  dnsNativeValidateCheckpoints();
  const defaults = dnsNativeReference.cases.filter(entry => entry.variant === 'default'); assert.equal(defaults.length, 22);
  dnsNativeReport.coverage = {defaultLessonsRequired: 22, canonicalCasesRequired: 159, loadingModesRequired: 3, taskFamiliesRequired: 8, namedTasksRequired: dnsNativeTasks, interactionDimensions: {loadingModes: 3, themes: 2, viewports: 2, motionPreferences: 2, namedTasks: 12, requiredCells: 288}, zoomDimensions: {loadingModes: 3, browserZoomLevels: [100, 150, 200], taskFamilies: 8, cases: dnsNativeTasks.filter(task => task.zoom), requiredCells: 72}, suitesRequested: dnsNativeOptionsValue.suite, coreLessons: 0, layoutChapters: 0, interactionCells: 0, zoomCells: 0};
  dnsNativeReport.coverage.layers = {sourceAndUnalteredEmitted: 'Separate complete159 semantic/prefix/field/exact/chapter evidence; not rerun or claimed by this native driver', core: 'Exhaustive every visible full/field/exact row in both directions plus endpoints for22 defaults x3 modes', interactionAndZoom: 'Representative native controls/tasks in every requested UI context; full first/middle/last plus all accepted independent checkpoint source events and successors; field/exact first/middle/last; endpoints and both directions throughout. Not exhaustive semantics per theme.'};
  const mime = file => ({'.js': 'application/javascript', '.mjs': 'application/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.png': 'image/png'})[path.extname(file)] || 'text/html';
  dnsNativeServer = http.createServer((request, response) => {
    try {
      const relative = decodeURIComponent(new URL(request.url, 'http://localhost').pathname).replace(/^\//, '');
      assert.ok(!relative || relative === 'index.html' || relative.startsWith('src/') || relative.startsWith('assets/') || relative === 'dist/auth-flow-studio.html');
      const file = fs.realpathSync(path.resolve(dnsNativeRoot, relative || 'index.html')); assert.ok(file.startsWith(dnsNativeRoot + path.sep));
      response.writeHead(200, {'Content-Type': mime(file), 'Cache-Control': 'no-store'}); response.end(fs.readFileSync(file));
    } catch { response.writeHead(404); response.end(); }
  });
  await new Promise(resolve => dnsNativeServer.listen(0, '127.0.0.1', resolve)); dnsNativeOrigin = 'http://127.0.0.1:' + dnsNativeServer.address().port;
  const {chromium} = await import(pathToFileURL(dnsNativeOptionsValue.playwright).href);
  const stages = dnsNativeOptionsValue.suite === 'all' ? ['core', 'layout', 'interaction', 'zoom'] : [dnsNativeOptionsValue.suite];
  for (const stage of stages) {
    const stageRecord = {stage, startedAt: new Date().toISOString(), attemptedBefore: dnsNativeReport.cells.attempted, failedBefore: dnsNativeReport.cells.failed}; dnsNativeReport.stages.push(stageRecord);
    if (stage === 'zoom') {
      const result = await dnsNativeCell('zoom-prerequisites-and-stage', {}, null, () => dnsNativeZoom(chromium));
      dnsNativeReport.zoom.stagePassed = result.passed;
    } else {
      dnsNativeBrowser = await chromium.launch({executablePath: dnsNativeOptionsValue.chrome, headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-background-networking', '--disable-component-update', '--no-first-run']}); dnsNativeReport.browser = dnsNativeBrowser.version();
      for (const mode of ['source-http', 'standalone-http', 'standalone-file']) {
        if (stage === 'interaction') {
          for (const touch of [false, true]) for (const theme of ['dark', 'light']) for (const motion of ['no-preference', 'reduce']) {
            const active = await dnsNativeNewPage(dnsNativeBrowser, mode, {touch, theme, motion});
            try {
              for (const task of dnsNativeTasks) {
                const {planId, caseId, taskFamily} = task;
                const row = dnsNativeManifest.rows.find(item => item.planId === planId);
                const entry = dnsNativeReference.cases.find(item => item.id === row.runtimeId && item.caseId === caseId);
                assert.ok(entry, 'Exact required named native task exists: ' + planId + '/' + caseId);
                const taskCell = await dnsNativeCell(stage, {mode, touch, theme, motion, planId, taskFamily, id: entry.id, caseId}, active.page, async () => {
                    await dnsNativeWorkspace(active.page, row.family, touch);
                    const actualTheme = await active.page.locator('#studio').getAttribute('data-theme'); if (actualTheme !== theme) await dnsNativeClick(active.page, '#theme-toggle', touch);
                    assert.equal(await active.page.locator('#studio').getAttribute('data-theme'), theme);
                    assert.equal(await active.page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches), motion === 'reduce');
                    const taskEvidence = await dnsNativeTaskJourney(active.page, entry, task, touch);
                    await dnsNativeChoose(active.page, entry, touch);
                    await dnsNativeRange(active.page, 1000);
                    const result = {taskEvidence, geometry: await dnsNativeGeometry(active.page), canonical: await dnsNativeObserve(active.page, entry), inspection: await dnsNativeInspect(active.page, entry, touch, planId === 'DNS01'), focus: await dnsNativeFocus(active.page), footer: await dnsNativeFooter(active.page), inputMechanism: touch ? 'native-touch-tap-and-keyboard' : 'native-mouse-and-keyboard'};
                    dnsNativeReport.coverage.interactionCells++;
                    if (mode === 'standalone-http' && motion === 'reduce' && task.zoom && ['DNS01', 'DNS16', 'DNS21'].includes(planId)) await dnsNativeScreenshot(active.page, 'interaction-' + planId + '-' + theme + '-' + (touch ? 'touch' : 'desktop'));
                    return result;
                  });
                assert.equal(taskCell.passed, true, 'Named native interaction task failed; remaining matrix is unperformed');
              }
            } finally { await dnsNativeSessionEnd(active); }
          }
        } else {
          const active = await dnsNativeNewPage(dnsNativeBrowser, mode);
          try {
            await dnsNativeCell('workspace-navigation', {mode}, active.page, async () => { await dnsNativeWorkspace(active.page); return {workspace: 'dnssec', filteringDoesNotNavigate: true}; });
            for (const entry of defaults) {
              if (stage === 'core') await dnsNativeCell(stage, {mode, id: entry.id, caseId: entry.caseId}, active.page, async () => { const result = await dnsNativeCore(active.page, entry); dnsNativeReport.coverage.coreLessons++; return result; });
              else {
                await dnsNativeChoose(active.page, entry);
                for (const internals of [false, true]) {
                  await active.page.getByLabel('Show component internals', {exact: true}).setChecked(internals); await dnsNativeSettle(active.page);
                  const chapters = await active.page.locator('[data-lesson-chapter]:not([disabled])').evaluateAll(elements => elements.map(element => element.dataset.lessonChapter));
                  assert.ok(chapters.length, 'Every default must expose enabled chapters');
                  for (const chapter of chapters) await dnsNativeCell(stage, {mode, id: entry.id, caseId: entry.caseId, internals, chapter}, active.page, async () => {
                    await dnsNativeClick(active.page, '[data-lesson-chapter=' + JSON.stringify(chapter) + ']');
                    const geometry = await dnsNativeGeometry(active.page); assert.equal(geometry.chapter, chapter); assert.equal(geometry.internals, internals);
                    dnsNativeReport.coverage.layoutChapters++; return geometry;
                  });
                }
                await dnsNativeCell('layout-inspection', {mode, id: entry.id, caseId: entry.caseId}, active.page, async () => {
                  await dnsNativeChoose(active.page, entry); return dnsNativeInspect(active.page, entry);
                });
              }
            }
            if (stage === 'core') await dnsNativeCell('footer', {mode}, active.page, () => dnsNativeFooter(active.page));
            if (mode === 'standalone-http') await dnsNativeScreenshot(active.page, stage + '-representative');
          } finally { await dnsNativeSessionEnd(active); }
        }
      }
      await dnsNativeBrowser.close(); dnsNativeBrowser = null;
    }
    stageRecord.finishedAt = new Date().toISOString(); stageRecord.cells = dnsNativeReport.cells.attempted - stageRecord.attemptedBefore; stageRecord.failures = dnsNativeReport.cells.failed - stageRecord.failedBefore;
    stageRecord.passed = stageRecord.failures === 0;
    dnsNativeSave();
  }
  if (stages.includes('core')) assert.equal(dnsNativeReport.coverage.coreLessons, 66, '22 defaults in all three loading modes');
  if (stages.includes('interaction')) assert.equal(dnsNativeReport.coverage.interactionCells, 288, 'Required full interaction cross-product');
  if (stages.includes('zoom')) assert.equal(dnsNativeReport.coverage.zoomCells, 72, 'Eight actual task cases x three real browser zoom levels x three loading modes');
  dnsNativeReport.completed = true;
} catch (error) {
  dnsNativeReport.failures.push({kind: 'fatal', error: error.stack || String(error)});
} finally {
  await dnsNativeBrowser?.close().catch(error => dnsNativeReport.failures.push({kind: 'browser-close', error: String(error)}));
  if (dnsNativeServer) await new Promise(resolve => dnsNativeServer.close(resolve));
  dnsNativeXvfb?.kill('SIGTERM');
  try {
    dnsNativeReport.after = dnsNativeIdentity(); assert.deepEqual(dnsNativeReport.after, dnsNativeReport.before, 'Source/runner/HTML/reference/worksheet identities unchanged before/after');
    if (dnsNativeReference) dnsNativeValidateReference(); dnsNativeReport.identityUnchanged = true;
    if (dnsNativeCheckpointReport) dnsNativeValidateCheckpoints();
  } catch (error) { dnsNativeReport.identityUnchanged = false; dnsNativeReport.failures.push({kind: 'identity', error: error.stack || String(error)}); }
  dnsNativeReport.finishedAt = new Date().toISOString();
  dnsNativeReport.passed = Boolean(dnsNativeReport.completed && dnsNativeReport.identityUnchanged && dnsNativeReport.failures.length === 0 && (!dnsNativeReport.zoom.required || dnsNativeReport.zoom.performed));
  dnsNativeReport.status = dnsNativeReport.passed ? 'passed' : dnsNativeReport.completed ? 'failed' : 'partial';
  dnsNativeReport.exitCode = dnsNativeReport.passed ? 0 : 1; dnsNativeSave(); process.exitCode = dnsNativeReport.exitCode;
  console.log(JSON.stringify({passed: dnsNativeReport.passed, status: dnsNativeReport.status, suite: dnsNativeOptionsValue.suite, cells: dnsNativeReport.cells, coverage: dnsNativeReport.coverage, failures: dnsNativeReport.failures.length, output: dnsNativeOut}));
}
