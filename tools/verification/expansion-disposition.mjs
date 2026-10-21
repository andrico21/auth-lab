#!/usr/bin/env bun
// Evidence consumer only: never executes a gate or derives expected state from a model.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

const runner = fileURLToPath(import.meta.url);
const root = path.resolve(path.dirname(runner), '../..');
const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) {
  console.log(`Usage: bun tools/verification/expansion-disposition.mjs [--evidence-root=DIR] [--output=FILE]
Defaults: --evidence-root=docs/verification/expansion
          --output=docs/expansion/scenario-disposition.json
Relative paths resolve from the repository, independently of the working directory.
Consumes promoted final reports, all 61 independent manifest/worksheet contracts, and
current model metadata. Requires each exact source choice, compiled choice, all three
native journeys, and applicable full-suite family regressions. Checks recorded source,
standalone, worksheet, generator and fixture hashes. Missing, failed, partial or stale
evidence is an error; no gate is run. Writes atomically only after all checks succeed.
G01, cross-engine and live product/protocol interoperability remain not established.`);
  process.exit(0);
}
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const portable = file => {
  const rel = path.relative(root, file);
  return rel && !rel.startsWith('..' + path.sep) && rel !== '..' ? rel.split(path.sep).join('/') : file;
};
function requireThat(value, message) { if (!value) throw new Error(message); }
function bytes(file) {
  requireThat(fs.existsSync(file) && fs.statSync(file).isFile(), `Missing prerequisite file: ${portable(file)}`);
  return fs.readFileSync(file);
}
function digest(file) { const data = bytes(file); return { path: portable(file), bytes: data.length, sha256: hash(data) }; }
function json(file) { try { return JSON.parse(bytes(file)); } catch (error) { throw new Error(`${portable(file)}: ${error.message}`); } }
function matchingDigest(file, expected, context) {
  requireThat(typeof expected === 'string' && /^[a-f0-9]{64}$/.test(expected), `${context}: missing SHA-256 for ${portable(file)}`);
  requireThat(digest(file).sha256 === expected, `${context}: stale bytes at ${portable(file)}`);
}
function repoFile(name) {
  requireThat(typeof name === 'string' && !path.isAbsolute(name), `Invalid repository evidence path: ${name}`);
  const file = path.resolve(root, name);
  requireThat(file.startsWith(root + path.sep), `Escaping repository evidence path: ${name}`);
  return file;
}
function sourceMap(map, context) {
  requireThat(map && typeof map === 'object' && Object.keys(map).length, `${context}: missing source identity`);
  for (const [name, entry] of Object.entries(map)) matchingDigest(repoFile(name), typeof entry === 'string' ? entry : entry.sha256, context);
}
function uniqueRow(rows, key, value, context) {
  requireThat(Array.isArray(rows), `${context}: missing row array`);
  const found = rows.map((row, index) => ({ row, index })).filter(({ row }) => row[key] === value);
  requireThat(found.length === 1, `${context}: expected one ${key}=${value}, observed ${found.length}`);
  return found[0];
}
const reportSpecs = [
  ['compiled', 'offline/compiled-bundle-status.json', 'compiled-bundle-offline-smoke', 'compiled-bundle-smoke.mjs'],
  ['geometry', 'offline/independent-geometry-status.json', 'offline-independent-route-sampling', 'independent-geometry-check.mjs'],
  ['source', 'offline/held-objects-source-status.json', 'held-objects-source-semantic-acceptance', 'held-objects-check.mjs'],
  ['coverage', 'offline/held-objects-coverage-manifest.json', 'authored-held-object-manifest', null],
  ['code3', 'offline/code3-environment-bundle-status.json', 'code3-environment-emitted-bundle-check', 'code3-environment-bundle-check.mjs'],
  ['html2', 'offline/html2-r1-bundle-status.json', 'html2-r1-emitted-bundle-context-check', 'html2-r1-bundle-check.mjs'],
  ['native', 'native/expansion-native-status.json', 'expansion-native-acceptance', 'run-expansion-native.mjs'],
  ['profile', 'performance/expansion-replay-profile-status.json', 'expansion-native-replay-profile', 'profile-expansion-replay.mjs'],
  ['baselineHeld', 'baseline-held/held-objects-native-status.json', 'held-objects-native-browser', 'held-objects-browser-check.mjs'],
  ['baselineUi', 'baseline-ui/code1-correction-native-browser-status.json', 'native-browser', 'native-browser-acceptance.mjs'],
  ['focused', 'focused-native/held-objects-focused-native-status.json', 'held-objects-focused-native-smoke', 'run-focused-native.mjs'],
  ['review', 'review-file/review-file-smoke-status.json', 'delivered-held-objects-file-smoke', 'review-file-smoke.mjs'],
  ['regressions', 'regressions/held-objects-regression-status.json', 'held-objects-full-source-regressions', 'run-regressions.mjs'],
  ['crypto', 'crypto-vectors-status.json', null, 'expansion-crypto/check-vectors.mjs'],
  ['cryptoPinned', 'crypto-vectors-bun142-status.json', null, 'expansion-crypto/check-vectors.mjs'],
];
const familyTests = {
  windows: ['windows-auth-lab.test.mjs', 'held-object-windows.test.mjs'],
  network: ['network-access-lab.test.mjs', 'held-object-network.test.mjs'],
  'kerberos-spake': ['kerberos-spake-lab.test.mjs', 'held-object-spake.test.mjs'],
  pake: ['pake-lab.test.mjs', 'held-object-pake.test.mjs'],
};
const modes = ['source-http', 'standalone-http', 'standalone-file'];
const limits = [
  'Manual G01 remains open. No real assistive-technology speech, announcement comprehension or overall manual acceptance is established.',
  'Native acceptance is limited to the recorded Chromium environment. Cross-engine interoperability is not established.',
  'No live Windows, AD DS, CredSSP, RDP or WinRM interoperability is established.',
  'No live RADIUS, EAP-TLS, RadSec or RADIUS/1.1 interoperability is established.',
  'No live MIT Kerberos SPAKE interoperability is established.',
  'No live SPAKE2 or SPAKE2+ implementation interoperability is established. Fixed offline vectors are not runtime cryptography or production certification.',
];

try {
  const options = {};
  for (const arg of args) {
    const match = /^(--evidence-root|--output)=(.+)$/.exec(arg);
    requireThat(match && !options[match[1]], `Unknown, empty or duplicate argument: ${arg}; use --help`);
    options[match[1]] = match[2];
  }
  const evidenceRoot = path.resolve(root, options['--evidence-root'] || 'docs/verification/expansion');
  const output = path.resolve(root, options['--output'] || 'docs/expansion/scenario-disposition.json');
  requireThat(!evidenceRoot.split(path.sep).includes('attempts'), 'Final evidence root must not be attempts/');
  const manifestFile = repoFile('docs/expansion/plan-manifest.json');
  const manifest = json(manifestFile);
  requireThat(manifest.fixedPresetCount === 61 && manifest.scenarios?.length === 61 && new Set(manifest.scenarios.map(row => row.id)).size === 61, `${portable(manifestFile)}: expected 61 independently fixed unique IDs`);
  const worksheets = new Map(), worksheetIdentity = {}, negativeVariants = [];
  for (const family of Object.keys(familyTests)) {
    const file = repoFile(`docs/expansion/${family}-scenarios.json`), sheet = json(file);
    worksheetIdentity[portable(file)] = digest(file).sha256;
    requireThat(Array.isArray(sheet.scenarios), `${portable(file)}: missing independent scenarios`);
    for (const [index, row] of sheet.scenarios.entries()) {
      requireThat(!worksheets.has(row.id), `${portable(file)}: duplicate worksheet ${row.id}`);
      worksheets.set(row.id, { family, row, sheet, file, index });
      for (const key of ['namedNegativeCases', 'negativeCases', 'negativeVariants']) {
        for (const [variantIndex, variant] of (row[key] || []).entries()) {
          // String aliases are retained as declarations, not misrepresented as observed cases.
          negativeVariants.push({ parentId: row.id, family, catalogEntry: false, declaration: variant,
            worksheet: { path: portable(file), sha256: digest(file).sha256, pointer: `/scenarios/${index}/${key}/${variantIndex}` },
            disposition: 'Independent negative contract; family regression evidence only, not a separate fixed native preset or live interoperability claim' });
        }
      }
    }
    for (const [index, variant] of (sheet.independentNegativeValidation || []).entries()) negativeVariants.push({ family, catalogEntry: false, declaration: variant,
      worksheet: { path: portable(file), sha256: digest(file).sha256, pointer: `/independentNegativeValidation/${index}` },
      disposition: 'Independent offline negative contract; family regression evidence only, not a separate fixed native preset or live interoperability claim' });
  }
  requireThat(worksheets.size === 61 && [...worksheets.keys()].every(id => manifest.scenarios.some(row => row.id === id)), 'Independent worksheets do not match the exact manifest IDs');
  const standalone = digest(repoFile('dist/auth-flow-studio.html'));
  const reports = {}, evidence = [];
  for (const [key, relative, kind, generator] of reportSpecs) {
    const file = path.join(evidenceRoot, relative), data = json(file), identity = digest(file);
    requireThat(!kind || data.kind === kind, `${identity.path}: wrong report kind; expected ${kind}`);
    if (key === 'baselineUi') requireThat(data.status === 'passed' && data.verified === true, `${identity.path}: native UI acceptance did not pass`);
    else if (key !== 'coverage') requireThat(data.passed === true, `${identity.path}: required gate did not pass`);
    if (key === 'review') requireThat(data.lifecycle?.disconnectedComponentCollected === true, `${identity.path}: disconnected component remains retained`);
    if (generator && data.runnerSha256 !== undefined) matchingDigest(repoFile(`tools/verification/${generator}`), data.runnerSha256, identity.path);
    if (key === 'profile') {
      requireThat(data.nativeBrowser === true && data.exitCode === 0 && data.phases?.length === 12 && data.files?.length === 24, `${identity.path}: incomplete native cost diagnostics`);
      for (const version of ['baseline', 'expanded', 'baseline-index-closed', 'expanded-index-closed']) for (const phase of ['idle-search', 'replay-start', 'playing-search']) {
        requireThat(data.phases.filter(row => row.version === version && row.phase === phase).length === 1, `${identity.path}: missing unique ${version}/${phase}`);
      }
      requireThat(data.baseline?.identity?.standalone?.sha256 === manifest.baselineStandaloneSha256, `${identity.path}: wrong profiling baseline`);
      for (const entry of data.files) {
        requireThat(typeof entry.file === 'string' && entry.file === path.basename(entry.file), `${identity.path}: invalid profile filename`);
        const raw = path.join(path.dirname(file), entry.file); matchingDigest(raw, entry.sha256, identity.path);
        evidence.push({ ...digest(raw), kind: 'native-cost-profile', report: identity.path });
      }
    }
    for (const field of ['failures', 'errors']) if (data[field] !== undefined) requireThat(Array.isArray(data[field]) && data[field].length === 0, `${identity.path}: nonempty ${field}`);
    if (data.sourceIdentity) sourceMap(data.sourceIdentity, identity.path);
    if (data.identity?.sources) sourceMap(data.identity.sources, identity.path);
    if (data.identity?.worksheets) sourceMap(data.identity.worksheets, identity.path);
    if (data.identity?.manifestSha256) matchingDigest(manifestFile, data.identity.manifestSha256, identity.path);
    if (data.inputs) for (const input of data.inputs) matchingDigest(repoFile(input.path), input.sha256, identity.path);
    for (const recorded of [data.htmlSha256, data.standaloneSha256, data.standalone?.sha256, data.artifact?.sha256, data.artifact?.standalone?.sha256, data.identity?.standalone?.sha256]) {
      if (recorded !== undefined) requireThat(recorded === standalone.sha256, `${identity.path}: stale standalone SHA-256`);
    }
    if (data.identityUnchanged !== undefined) requireThat(data.identityUnchanged === true, `${identity.path}: source identity changed during gate`);
    reports[key] = { file, data, identity };
    evidence.push({ ...identity, kind: data.kind || 'expansion-fixed-crypto-vectors' });
    for (const capture of data.screenshots || []) {
      const recordedName = typeof capture === 'string' ? capture : capture.file;
      requireThat(typeof recordedName === 'string' && recordedName.length > 0, `${identity.path}: missing capture filename`);
      // Older UI generators recorded absolute output paths. Promotion preserves the
      // capture basename beside the report, not the original workstation directory.
      const relativeName = path.isAbsolute(recordedName) ? path.basename(recordedName) : recordedName;
      const captureFile = path.resolve(path.dirname(file), relativeName);
      requireThat(captureFile.startsWith(path.dirname(file) + path.sep), `${identity.path}: escaping capture reference ${recordedName}`);
      const captureIdentity = digest(captureFile);
      if (typeof capture !== 'string' && capture.sha256 !== undefined) matchingDigest(captureFile, capture.sha256, identity.path);
      evidence.push({ ...captureIdentity, kind: 'native-capture', recordedReference: recordedName, report: identity.path });
    }
  }
  const pointer = (key, location = '') => ({ path: reports[key].identity.path, sha256: reports[key].identity.sha256, pointer: location });
  const snapshotNames = ['index.html', 'build.mjs', 'package.json', ...fs.readdirSync(path.join(root, 'src')).filter(name => /\.(js|css)$/.test(name)).sort().map(name => `src/${name}`)];
  const sources = Object.fromEntries(snapshotNames.map(name => [name, digest(repoFile(name)).sha256]));
  const legacySnapshot = createHash('sha256');
  for (const name of snapshotNames) { legacySnapshot.update(name + '\0'); legacySnapshot.update(bytes(repoFile(name))); legacySnapshot.update('\0'); }
  const legacySha256 = legacySnapshot.digest('hex');
  requireThat(reports.native.data.identity?.sourceSnapshotSha256 === hash(JSON.stringify(sources)), `${reports.native.identity.path}: stale or incomplete source snapshot`);
  for (const key of ['baselineUi', 'focused']) {
    const recorded = key === 'baselineUi' ? reports[key].data.artifact?.sourceSnapshotSha256 : reports[key].data.identity?.sourceSnapshotSha256;
    requireThat(recorded === legacySha256, `${reports[key].identity.path}: stale or missing source snapshot`);
  }
  requireThat(reports.native.data.complete === true && reports.native.data.nativeBrowser === true, `${reports.native.identity.path}: partial native run is not final acceptance`);
  requireThat(reports.native.data.scope?.requestedIds?.length === 0 && modes.every(mode => reports.native.data.scope?.modes?.includes(mode)), `${reports.native.identity.path}: diagnostic subset cannot establish final acceptance`);
  const testNames = fs.readdirSync(path.join(root, 'tests')).filter(name => name.endsWith('.test.mjs')).sort();
  const regressionRows = reports.regressions.data.files;
  requireThat(Array.isArray(regressionRows) && regressionRows.length === testNames.length, `${reports.regressions.identity.path}: incomplete full regression report`);
  for (const name of testNames) {
    const { row } = uniqueRow(regressionRows, 'file', name, reports.regressions.identity.path);
    requireThat(row.passed === true && row.exitCode === 0 && row.testsFailed === 0 && row.testsPassed > 0, `${reports.regressions.identity.path}: failed or empty tests/${name}`);
    requireThat(row.log === `regression-logs/${name}.log`, `${reports.regressions.identity.path}: unexpected regression log ${row.log}`);
    const log = digest(path.join(path.dirname(reports.regressions.file), row.log));
    evidence.push({ ...log, kind: 'regression-log' });
  }
  for (const key of ['crypto', 'cryptoPinned']) {
    const data = reports[key].data;
    requireThat(Array.isArray(data.files) && data.files.length > 0 && data.cases?.length > 0 && data.cases.every(row => row.passed === true), `${reports[key].identity.path}: incomplete crypto-vector evidence`);
    for (const file of data.files) matchingDigest(repoFile(`tools/verification/expansion-crypto/${file.path}`), file.sha256, reports[key].identity.path);
    for (const source of data.sources || []) matchingDigest(repoFile(`tools/verification/expansion-crypto/${source.snapshot}`), source.actualSha256, reports[key].identity.path);
  }
  requireThat(reports.cryptoPinned.data.runtime?.bun === '1.4.2', `${reports.cryptoPinned.identity.path}: pinned Bun 1.4.2 evidence required`);
  const { LAB_MODELS } = await import(pathToFileURL(repoFile('src/lab-catalog.js')).href);
  const scenarios = manifest.scenarios.map((planned, planIndex) => {
    const independent = worksheets.get(planned.id), { row, family, file, index } = independent;
    requireThat(planned.family === family && planned.worksheet === portable(file), `${planned.id}: manifest/worksheet family mismatch`);
    const model = LAB_MODELS[planned.id];
    requireThat(model && model.id === planned.id && model.title && model.workspace && model.family && model.profile && model.prerequisites, `${planned.id}: incomplete actual model metadata`);
    const actors = model.actors();
    requireThat(actors && Object.keys(actors).length > 0, `${planned.id}: no actual model actors`);
    const source = uniqueRow(reports.source.data.choices, 'choiceId', planned.id, reports.source.identity.path);
    requireThat(source.row.complete === true && source.row.sourceEvents > 0 && source.row.equalCursorComparisons > 0, `${planned.id}: incomplete exact source semantics`);
    const compiled = uniqueRow(reports.compiled.data.scenarios, 'id', planned.id, reports.compiled.identity.path);
    requireThat(compiled.row.steps > 0 && compiled.row.actors?.length > 0, `${planned.id}: incomplete compiled choice`);
    const coverage = uniqueRow(reports.coverage.data.choices, 'choiceId', planned.id, reports.coverage.identity.path);
    const geometry = reports.geometry.data.scenarios.map((item, itemIndex) => ({ row: item, index: itemIndex })).filter(item => item.row.id === planned.id);
    const requiredViews = Object.values(actors).some(actor => actor.parentId) ? [false, true] : [false];
    requireThat(geometry.length === requiredViews.length && requiredViews.every(expanded => geometry.filter(item => item.row.expanded === expanded && item.row.routeCount > 0 && item.row.sampleCount > 0).length === 1), `${planned.id}: incomplete exact geometry views`);
    const nativeModes = modes.map(mode => {
      const modeResult = uniqueRow(reports.native.data.modes, 'mode', mode, reports.native.identity.path);
      requireThat(modeResult.row.passed === true, `${planned.id}: failed native mode ${mode}`);
      const observed = uniqueRow(modeResult.row.scenarios, 'id', planned.id, `${reports.native.identity.path} ${mode}`);
      requireThat(observed.row.passed === true && observed.row.requiredTerminalBoundary === planned.requiredTerminalBoundary, `${planned.id}: failed or mismatched native contract in ${mode}`);
      return { mode, status: 'passed', evidence: pointer('native', `/modes/${modeResult.index}/scenarios/${observed.index}`) };
    });
    const regressions = familyTests[family].map(name => {
      const { index: testIndex } = uniqueRow(regressionRows, 'file', name, reports.regressions.identity.path);
      return pointer('regressions', `/files/${testIndex}`);
    });
    const expected = {};
    for (const key of ['terminal', 'terminalPredicate', 'expectedMilestones', 'checkablePredicates', 'expectedHistory', 'success', 'failureKnowledge', 'boundaryAssertions', 'observationRequirements', 'groupedOmissions']) if (row[key] !== undefined) expected[key] = row[key];
    requireThat(row.terminal !== undefined || row.terminalPredicate !== undefined, `${planned.id}: missing independently authored terminal predicate`);
    return {
      id: planned.id, reviewLabel: planned.reviewLabel, plannedFamily: family,
      title: model.title, workspace: model.workspace, family: model.family, protocol: model.protocol,
      profile: model.profile, prerequisites: model.prerequisites,
      actorIds: Object.keys(actors), actors,
      sourceSections: { actual: model.profile.sources || model.source, independent: row.sourceSections || row.profileSources || row.sources, pinnedSources: independent.sheet.sources || row.profileSources || row.sourceErrataMap || row.sourceRevisionNotes },
      expected: { authorship: 'Independent manifest and worksheet; not inferred from model execution', prerequisiteOrLesson: planned.prerequisiteOrLesson, requiredTerminalBoundary: planned.requiredTerminalBoundary, predicates: expected,
        manifest: { path: portable(manifestFile), sha256: digest(manifestFile).sha256, pointer: `/scenarios/${planIndex}` },
        worksheet: { path: portable(file), sha256: worksheetIdentity[portable(file)], pointer: `/scenarios/${index}` } },
      source: { status: 'passed', evidence: [pointer('source', `/choices/${source.index}`), pointer('coverage', `/choices/${coverage.index}`), pointer('compiled', `/scenarios/${compiled.index}`), ...geometry.map(item => pointer('geometry', `/scenarios/${item.index}`)), ...regressions] },
      native: { status: 'passed', modes: nativeModes },
      interoperability: { status: 'not-established', evidence: [], limits },
      manualG01: { status: 'open', evidence: [], statement: manifest.manualG01 },
    };
  });
  for (const variant of negativeVariants) variant.evidence = familyTests[variant.family].map(name => pointer('regressions', `/files/${uniqueRow(regressionRows, 'file', name, reports.regressions.identity.path).index}`));
  const result = {
    schemaVersion: 1, kind: 'expansion-scenario-disposition', passed: true, fixedPresetCount: 61,
    reviewDisposition: 'Evidence complete for independent Astra review; not an Astra approval or publication authorization',
    generator: { path: portable(runner), sha256: digest(runner).sha256, argv: [process.execPath, ...process.argv.slice(1)], runtime: { executable: process.execPath, version: process.version, bun: process.versions.bun || null, platform: process.platform, arch: process.arch } },
    identity: { sources, standalone, manifest: digest(manifestFile), worksheets: worksheetIdentity },
    evidenceRoot: portable(evidenceRoot), evidence, scenarios, negativeVariants,
    performance: {
      status: reports.native.data.performance.comparisons.some(row => row.materialRegression) ? 'material-interaction-regressions-reported' : 'no-material-flags',
      comparisons: pointer('native', '/performance/comparisons'),
      materialFlags: reports.native.data.performance.comparisons.filter(row => row.materialRegression).map(({ mode, metric }) => ({ mode, metric })),
      costDiagnostics: pointer('profile', '/phases'),
      explanation: digest(repoFile('docs/expansion/implementation.md')),
      limitation: 'Three observations per checkout/mode are descriptive. Instrumented open/closed-index controls explain cost; they do not replace or clear the default-open acceptance flags.',
    },
    limits, manualG01: { status: 'open', statement: manifest.manualG01 },
  };
  evidence.push({ ...result.performance.explanation, kind: 'performance-explanation' });
  const protectedInputs = [runner, manifestFile, ...Object.keys(worksheetIdentity).map(repoFile), ...Object.keys(sources).map(repoFile), repoFile('dist/auth-flow-studio.html')];
  requireThat(!evidence.some(entry => path.resolve(root, entry.path) === output) && !protectedInputs.includes(output), 'Output would overwrite an evidence input or source');
  fs.mkdirSync(path.dirname(output), { recursive: true });
  const temporary = output + `.tmp-${process.pid}`;
  try { fs.writeFileSync(temporary, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' }); fs.renameSync(temporary, output); }
  finally { if (fs.existsSync(temporary)) fs.unlinkSync(temporary); }
  console.log(JSON.stringify({ passed: true, fixedPresetCount: scenarios.length, negativeDeclarations: negativeVariants.length, output: portable(output), sha256: digest(output).sha256, manualG01: 'open', interoperability: 'not-established' }, null, 2));
} catch (error) {
  console.error(`Expansion disposition failed: ${error.message}`);
  process.exitCode = 1;
}
