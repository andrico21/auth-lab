#!/usr/bin/env bun
// Combine completed native cells, never rewrite or promote an interrupted run.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {captureReviewInputs} from './review-input-identity.mjs';

const usage = 'Usage: bun tools/verification/combine-dnssec-native-core.mjs --root=PATH --source-run=DIR --standalone-run=DIR --reference=FILE --out=NEW_DIRECTORY';
if (process.argv.includes('--help')) { console.log(usage); process.exit(0); }
const options = {};
for (const argument of process.argv.slice(2)) {
  const match = /^--(root|source-run|standalone-run|reference|out)=(.+)$/.exec(argument);
  assert.ok(match && !Object.hasOwn(options, match[1]), usage);
  options[match[1]] = match[2];
}
for (const key of ['root', 'source-run', 'standalone-run', 'reference', 'out']) assert.ok(options[key], usage);
const root = fs.realpathSync(options.root);
const resolve = name => {
  const filename = path.resolve(root, name);
  assert.ok(filename.startsWith(root + path.sep), 'Input/output must be inside the project: ' + name);
  return filename;
};
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const ref = filename => {
  assert.ok(fs.lstatSync(filename).isFile(), 'Regular evidence file required: ' + filename);
  const bytes = fs.readFileSync(filename);
  return {path: path.relative(root, filename).split(path.sep).join('/'), sha256: sha256(bytes), bytes: bytes.length};
};
const json = filename => JSON.parse(fs.readFileSync(filename, 'utf8'));
const referencePath = resolve(options.reference), reference = json(referencePath);
assert.equal(reference.passed, true); assert.equal(reference.complete, true);
assert.equal(reference.cases.length, 159);
const defaults = reference.cases.filter(row => row.variant === 'default');
assert.equal(defaults.length, 22);
const output = resolve(options.out); fs.mkdirSync(output, {recursive: false});
const self = fileURLToPath(import.meta.url);
const current = captureReviewInputs(root, self);
assert.deepEqual(current.sourceFiles, reference.identities.sourceFiles, 'Current complete application/test input map');
assert.equal(current.standaloneSha256, reference.identities.standaloneSha256);
const standalone = ref(path.join(root, 'dist/auth-flow-studio.html'));
const currentManifest = ref(path.join(root, 'docs/dnssec-expansion/scenario-manifest.json'));
const referenceIdentity = ref(referencePath);
const sourceDigest = createHash('sha256');
for (const name of Object.keys(current.sourceFiles).sort()) {
  sourceDigest.update(name + '\0'); sourceDigest.update(fs.readFileSync(path.join(root, name))); sourceDigest.update('\0');
}
function loadRun(name) {
  const directory = resolve(name), reportPath = path.join(directory, 'native-status.json');
  const report = json(reportPath), cellsPath = path.join(directory, 'cells.jsonl');
  const cells = fs.readFileSync(cellsPath, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
  assert.equal(report.kind, 'DNSSEC-native-rendering-verification');
  assert.deepEqual(report.before.sourceFiles, current.sourceFiles, 'Original producer application/test input map');
  assert.deepEqual(report.before.standalone, {sha256: standalone.sha256, bytes: standalone.bytes});
  assert.deepEqual(report.before.manifest, {sha256: currentManifest.sha256, bytes: currentManifest.bytes});
  assert.deepEqual(report.before.reference, {sha256: referenceIdentity.sha256, bytes: referenceIdentity.bytes});
  assert.equal(report.before.worksheet.sha256, reference.identities.worksheetSha256);
  const worksheet = ref(report.options.worksheet);
  assert.deepEqual(report.before.worksheet, {sha256: worksheet.sha256, bytes: worksheet.bytes});
  const runner = ref(path.join(directory, 'runner-input.mjs'));
  assert.deepEqual(report.before.runner, {sha256: runner.sha256, bytes: runner.bytes}, 'Exact original executed native runner retained');
  const referenceCopy = ref(path.join(directory, 'reference-input.json'));
  assert.equal(referenceCopy.sha256, referenceIdentity.sha256);
  if (report.identityUnchanged === true) assert.deepEqual(report.after, report.before, 'Original completed before/after capture');
  return {directory, report, cells, identity: {report: ref(reportPath), cells: ref(cellsPath), runner, referenceCopy, worksheet}, originalDisposition: {status: report.status, passed: report.passed, completed: report.completed ?? false, identityUnchanged: report.identityUnchanged ?? null}};
}
const sourceRun = loadRun(options['source-run']), standaloneRun = loadRun(options['standalone-run']);
assert.equal(standaloneRun.report.identityUnchanged, true, 'Completed original standalone producer has its own terminal identity capture');
assert.deepEqual(sourceRun.report.before.chrome, standaloneRun.report.before.chrome);
assert.deepEqual(sourceRun.report.before.playwright, standaloneRun.report.before.playwright);
assert.deepEqual(sourceRun.report.runtime, standaloneRun.report.runtime, 'Same actual Bun/platform runtime');
const selected = [], supporting = [];
let observationsChecked = 0;
function validateObservation(observation, entry) {
  const prefix = entry.prefixes.find(row => row.eventIndex === observation.cursor.eventIndex && row.milestone === observation.cursor.milestone);
  assert.ok(prefix, 'Actual native cursor has canonical prefix');
  assert.equal(observation.stateSha256, prefix.stateSha256, 'Actual native state hash');
  assert.equal(observation.holdingsSha256, prefix.holdingsSha256, 'Actual native custody hash');
  observationsChecked++;
}
for (const mode of ['source-http', 'standalone-http', 'standalone-file']) {
  const run = mode === 'source-http' ? sourceRun : standaloneRun;
  const session = run.report.sessions.find(row => row.mode === mode);
  assert.ok(session); for (const key of ['errors', 'console', 'csp', 'externalRequests']) assert.equal(session[key], 0, mode + ' ' + key);
  for (const stage of ['workspace-navigation', 'footer', 'browser-log']) {
    const rows = run.cells.filter(row => row.stage === stage && row.mode === mode && row.passed);
    assert.equal(rows.length, 1, 'One completed ' + mode + '/' + stage);
    supporting.push({mode, stage, sequence: rows[0].sequence, journal: run.identity.cells});
  }
  for (const entry of defaults) {
    const rows = run.cells.filter(row => row.stage === 'core' && row.mode === mode && row.id === entry.id && row.caseId === entry.caseId && row.passed);
    assert.equal(rows.length, 1, 'Exactly one completed native default cell: ' + mode + '/' + entry.id);
    const cell = rows[0], observed = cell.observed;
    assert.equal(observed.fieldId, entry.fieldId);
    assert.equal(observed.inspection.artifactId, entry.inspection.artifactId);
    assert.equal(observed.inspection.actorId, entry.inspection.actorId);
    const counts = {};
    for (const name of ['full', 'field', 'exact']) {
      const replay = observed[name]; assert.equal(replay.mode, name);
      assert.equal(replay.observations.length, replay.positions * 2);
      assert.equal(replay.nativeRows + 2, replay.positions);
      const forward = replay.observations.filter(row => row.direction === 'forward');
      const backward = replay.observations.filter(row => row.direction === 'backward');
      assert.equal(forward.length, replay.positions); assert.equal(backward.length, replay.positions);
      assert.equal(forward[0].value, 0); assert.equal(forward.at(-1).value, 1000);
      assert.deepEqual(backward.map(row => [row.value, row.stepId]), forward.map(row => [row.value, row.stepId]).reverse());
      const stepIds = forward.filter(row => row.stepId).map(row => row.stepId);
      assert.equal(new Set(stepIds).size, replay.nativeRows, 'Every distinct visible row has its own native target');
      if (name === 'full') assert.deepEqual(stepIds, entry.steps.map(row => row.id), 'Full native replay covers every canonical source step');
      for (const observation of replay.observations) validateObservation(observation, entry);
      counts[name] = {nativeRows: replay.nativeRows, observations: replay.observations.length};
    }
    assert.equal(observed.reset.cursor.eventIndex, -1); validateObservation(observed.reset, entry);
    selected.push({mode, id: entry.id, caseId: entry.caseId, sequence: cell.sequence, journal: run.identity.cells, counts});
  }
}
assert.equal(selected.length, 66); assert.equal(supporting.length, 9);
assert.deepEqual(captureReviewInputs(root, self), current, 'Inputs unchanged during combination');
const report = {schemaVersion: 1, kind: 'DNSSEC-native-core-coverage-combination', passed: true, status: 'passed', recordedAt: new Date().toISOString(), actualArgv: process.argv, runner: ref(self), sourceIdentity: {algorithm: 'sha256-path-nul-bytes-nul-v1', sha256: sourceDigest.digest('hex'), files: Object.keys(current.sourceFiles).length}, standalone, reference: referenceIdentity, completeDefaultCoverage: {required: 66, selected: selected.length, lessons: 22, loadingModes: 3, observationsChecked}, producers: {source: {identity: sourceRun.identity, originalDisposition: sourceRun.originalDisposition}, standalone: {identity: standaloneRun.identity, originalDisposition: standaloneRun.originalDisposition}}, selectedCells: selected, supportingCells: supporting, currentApplicability: {applicationTestAndStandaloneBytesUnchanged: true, checkedAfterTermination: true, originalReportsNotRewritten: true, originalSourceRunHasNoInventedTerminalIdentityCapture: sourceRun.report.identityUnchanged == null}, scope: 'Complete 22-default x3-loading-mode native full/field/exact every-row forward/backward/reset coverage, combined only from completed real native cells. No new native execution occurred during combination. Partial producer runs remain partial.', notEstablished: ['Representative named-task theme/touch/motion and real-zoom matrices', 'Human G01 or manual acceptance', 'Performance acceptance', 'Live DNS, installed-service or cross-engine conformance', 'Independent Astra review or publication authorization']};
fs.writeFileSync(path.join(output, 'native-core-combined-status.json'), JSON.stringify(report, null, 2) + '\n', {flag: 'wx'});
console.log(JSON.stringify({passed: report.passed, selected: selected.length, observationsChecked, sourceIdentity: report.sourceIdentity, output}, null, 2));
