#!/usr/bin/env bun
// Local-only review packaging. Reports are inputs, never rewritten as passing evidence.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const runner = fileURLToPath(import.meta.url);
const root = path.resolve(path.dirname(runner), '../..');
const usage = 'Usage: bun tools/verification/package-expansion-review.mjs --out=DIR --baseline-archive=FILE [--evidence-root=DIR]\nRequires Bun, zip and unzip on PATH, final current passing evidence and scenario-disposition.json. Creates a new external directory, extracts the source ZIP and performs a real offline Bun rebuild. No gate reruns, downloads or publication.';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const digest = file => hash(fs.readFileSync(file));
const fail = message => { throw new Error(message); };
const within = (base, file) => file === base || file.startsWith(base + path.sep);
const slash = file => file.split(path.sep).join('/');
function regular(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) fail('Expected regular non-symlink file: ' + file);
  return stat;
}
function json(file) { regular(file); return JSON.parse(fs.readFileSync(file, 'utf8')); }
function run(argv, cwd, input) {
  const result = spawnSync(argv[0], argv.slice(1), { cwd, input, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...process.env, BUN_INSTALL_AUTO: 'disable' } });
  if (result.error || result.status !== 0) fail('Command failed: ' + JSON.stringify(argv) + '\n' + (result.error?.message || result.stderr || result.stdout));
  return { argv, exitStatus: result.status, stdout: result.stdout, stderr: result.stderr };
}
const excluded = new Set(['.git', 'node_modules', '.cache', '.bun', '__pycache__', '.DS_Store', 'Thumbs.db', '__MACOSX']);
function walk(directory, relative = '') {
  const result = [];
  for (const entry of fs.readdirSync(path.join(directory, relative), { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
    if (excluded.has(entry.name) || entry.name.endsWith('.pyc')) continue;
    const name = relative ? relative + '/' + entry.name : entry.name;
    if (/[\r\n\0]/.test(name)) fail('Unsafe archive filename: ' + JSON.stringify(name));
    if (entry.isSymbolicLink()) fail('Refusing symlink in package: ' + path.join(directory, name));
    if (entry.isDirectory()) result.push(...walk(directory, name));
    else if (entry.isFile()) result.push(name);
    else fail('Refusing special file: ' + name);
  }
  return result;
}
function copy(file, target) {
  regular(file); fs.mkdirSync(path.dirname(target), { recursive: true }); fs.copyFileSync(file, target, fs.constants.COPYFILE_EXCL);
}
function verifyMap(map, base, label) {
  if (!map || !Object.keys(map).length) fail('Missing identity map: ' + label);
  for (const [name, value] of Object.entries(map)) {
    const file = path.resolve(base, name);
    if (!within(base, file)) fail('Escaping identity path: ' + name);
    regular(file);
    if (digest(file) !== (typeof value === 'string' ? value : value.sha256)) fail('Stale evidence identity: ' + label + ' -> ' + file);
  }
}
function baselineTar(bytes, expected) {
  // The accepted baseline is an uncompressed git archive TAR. Never extract it.
  let offset = 0, found = false;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512); offset += 512;
    if (header.every(byte => byte === 0)) break;
    const field = (start, length) => header.subarray(start, start + length).toString('utf8').replace(/\0.*$/s, '');
    const name = [field(345, 155), field(0, 100)].filter(Boolean).join('/');
    const size = parseInt(field(124, 12).trim() || '0', 8);
    if (!Number.isSafeInteger(size) || size < 0 || offset + size > bytes.length) fail('Invalid baseline TAR length');
    if (name.startsWith('/') || name.split('/').includes('..')) fail('Unsafe baseline TAR member: ' + name);
    const type = field(156, 1);
    if (!['', '0', '5', 'g', 'x'].includes(type)) fail('Unsupported baseline TAR member: ' + name);
    const content = bytes.subarray(offset, offset + size);
    if (name === 'dist/auth-flow-studio.html') { if (hash(content) !== expected) fail('Accepted baseline standalone hash mismatch'); found = true; }
    offset += Math.ceil(size / 512) * 512;
  }
  if (!found) fail('Accepted baseline TAR missing dist/auth-flow-studio.html');
}

async function main() {
  if (process.argv.slice(2).some(arg => arg === '--help' || arg === '-h')) { console.log(usage); return; }
  const options = {};
  for (const arg of process.argv.slice(2)) {
    const match = /^--(out|baseline-archive|evidence-root)=(.+)$/.exec(arg);
    if (!match || options[match[1]]) fail('Unknown, empty or duplicate option: ' + arg + '\n' + usage);
    options[match[1]] = match[2];
  }
  if (!options.out || !options['baseline-archive']) fail(usage);
  if (!process.versions.bun) fail('Run this tool with Bun');
  const evidence = path.resolve(root, options['evidence-root'] || 'docs/verification/expansion');
  if (!within(root, evidence)) fail('Evidence root must be inside the source tree for reproducible packaging: ' + evidence);
  const output = path.resolve(options.out);
  const parent = fs.realpathSync(path.dirname(output));
  if (within(root, path.join(parent, path.basename(output))) || within(output, root)) fail('Output must be external to the repository');
  if (fs.existsSync(output)) fail('Refusing conflicting output: ' + output);
  const baseline = path.resolve(options['baseline-archive']); regular(baseline);
  const manifest = json(path.join(root, 'docs/expansion/plan-manifest.json'));
  const standalone = path.join(root, 'dist/auth-flow-studio.html'); regular(standalone);
  const standaloneHash = digest(standalone);
  const files = ['index.html', 'build.mjs', 'package.json', ...fs.readdirSync(path.join(root, 'src')).filter(n => /\.(js|css)$/.test(n)).sort().map(n => 'src/' + n)];
  const sourceHash = createHash('sha256');
  for (const name of files) { sourceHash.update(name + '\0'); sourceHash.update(fs.readFileSync(path.join(root, name))); sourceHash.update('\0'); }
  const snapshot = sourceHash.digest('hex');
  const requirements = [
    ['offline/compiled-bundle-status.json', 'compiled-bundle-smoke.mjs'],
    ['offline/independent-geometry-status.json', 'independent-geometry-check.mjs'],
    ['offline/held-objects-source-status.json', 'held-objects-check.mjs'],
    ['offline/code3-environment-bundle-status.json', 'code3-environment-bundle-check.mjs'],
    ['offline/html2-r1-bundle-status.json', 'html2-r1-bundle-check.mjs'],
    ['native/expansion-native-status.json', 'run-expansion-native.mjs'],
    ['performance/expansion-replay-profile-status.json', 'profile-expansion-replay.mjs'],
    ['baseline-held/held-objects-native-status.json', 'held-objects-browser-check.mjs'],
    ['baseline-ui/code1-correction-native-browser-status.json', 'native-browser-acceptance.mjs'],
    ['focused-native/held-objects-focused-native-status.json', 'run-focused-native.mjs'],
    ['review-file/review-file-smoke-status.json', 'review-file-smoke.mjs'],
    ['regressions/held-objects-regression-status.json', 'run-regressions.mjs'],
    ['crypto-vectors-status.json', 'expansion-crypto/check-vectors.mjs'],
    ['crypto-vectors-bun142-status.json', 'expansion-crypto/check-vectors.mjs'],
  ];
  const evidenceHashes = {};
  for (const [name, generator] of requirements) {
    const location = path.join(evidence, name), report = json(location);
    const nativeUI = name.startsWith('baseline-ui/');
    if (nativeUI ? report.verified !== true || report.status !== 'passed' : report.passed !== true) fail('Missing successful gate: ' + location);
    if (report.failures?.length || report.fatal || report.reason) fail('Failed evidence: ' + location);
    const generatorFile = path.join(root, 'tools/verification', generator);
    if (report.runnerSha256 && report.runnerSha256 !== digest(generatorFile)) fail('Stale generator: ' + location + ' -> ' + generatorFile);
    const htmlHash = report.htmlSha256 || report.standaloneSha256 || report.artifact?.sha256 || report.artifact?.standalone?.sha256 || report.identity?.standalone?.sha256 || report.standalone?.sha256;
    if (htmlHash && htmlHash !== standaloneHash) fail('Stale standalone: ' + location);
    for (const map of [report.sourceIdentity, report.identity?.sources]) if (map) verifyMap(map, root, location);
    if (report.inputs) verifyMap(Object.fromEntries(report.inputs.map(item => [item.path, item.sha256])), root, location);
    const snapshotHash = report.artifact?.sourceSnapshotSha256 || (!report.identity?.sources && report.identity?.sourceSnapshotSha256);
    if (snapshotHash && snapshotHash !== snapshot) fail('Stale source snapshot: ' + location);
    if (report.identity?.manifestSha256 && report.identity.manifestSha256 !== digest(path.join(root, 'docs/expansion/plan-manifest.json'))) fail('Stale manifest: ' + location);
    if (report.identity?.worksheets) verifyMap(report.identity.worksheets, root, location);
    if (name.startsWith('crypto-')) {
      if (report.runnerSha256 !== digest(generatorFile)) fail('Missing crypto generator identity: ' + location);
      if (name === 'crypto-vectors-bun142-status.json' && report.runtime?.bun !== '1.4.2') fail('Required Bun 1.4.2 crypto evidence: ' + location);
      verifyMap(Object.fromEntries((report.files || []).map(item => [item.path, item.sha256])), path.dirname(generatorFile), location);
      for (const item of report.sources || []) if (digest(path.join(path.dirname(generatorFile), item.snapshot)) !== item.sha256 || item.actualSha256 !== item.sha256) fail('Stale crypto primary source: ' + location);
    }
    if (name.startsWith('native/') && (report.complete !== true || report.performance?.available !== true)) fail('Incomplete native/performance gate: ' + location);
    if (name.startsWith('review-file/') && report.lifecycle?.disconnectedComponentCollected !== true) fail('Missing native disconnected-component collection proof: ' + location);
    if (name.startsWith('performance/')) {
      if (report.nativeBrowser !== true || report.exitCode !== 0 || report.phases?.length !== 12 || report.files?.length !== 24) fail('Incomplete native cost diagnostics: ' + location);
      for (const entry of report.files) {
        if (typeof entry.file !== 'string' || entry.file !== path.basename(entry.file)) fail('Invalid native cost filename: ' + location);
        const raw = path.join(path.dirname(location), entry.file); regular(raw);
        if (digest(raw) !== entry.sha256) fail('Changed native cost profile: ' + raw);
        evidenceHashes[path.relative(evidence, raw)] = entry.sha256;
      }
    }
    for (const capture of report.screenshots || []) {
      const filename = typeof capture === 'string' ? capture : capture.file;
      const capturePath = path.resolve(path.dirname(location), path.isAbsolute(filename) ? path.basename(filename) : filename);
      if (!within(evidence, capturePath)) fail('Escaping capture: ' + capturePath);
      if (path.isAbsolute(filename) && fs.existsSync(filename) && digest(filename) !== digest(capturePath)) fail('Promoted capture differs from original: ' + capturePath);
      regular(capturePath);
      if (capture.sha256 && capture.sha256 !== digest(capturePath)) fail('Changed capture: ' + capturePath);
    }
    for (const row of report.files || []) if (row.log) regular(path.join(path.dirname(location), row.log));
    evidenceHashes[slash(path.relative(root, location))] = digest(location);
  }
  const coverage = path.join(evidence, 'offline/held-objects-coverage-manifest.json'); json(coverage); evidenceHashes[slash(path.relative(root, coverage))] = digest(coverage);
  const dispositionFile = path.join(root, 'docs/expansion/scenario-disposition.json'); json(dispositionFile);
  const baselineBytes = fs.readFileSync(baseline); baselineTar(baselineBytes, manifest.baselineStandaloneSha256);
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-lab-expansion-package-'));
  let ownsOutput = false;
  try {
    const freshDisposition = path.join(temporary, 'scenario-disposition.json');
    run([process.execPath, path.join(root, 'tools/verification/expansion-disposition.mjs'), '--evidence-root=' + evidence, '--output=' + freshDisposition], root);
    // Only the generator invocation changes when validation uses a temporary output.
    const stable = value => ({ ...value, generator: { ...value.generator, argv: [] } });
    if (JSON.stringify(stable(json(dispositionFile))) !== JSON.stringify(stable(json(freshDisposition)))) fail('Stale final disposition: ' + dispositionFile);
    const repositoryFiles = walk(root);
    const bulkCaptures = repositoryFiles.filter(name => /^docs\/verification\/.+\.png$/i.test(name));
    const sourceFiles = repositoryFiles.filter(name => !/^docs\/verification\/.+\.png$/i.test(name));
    const sourceStage = path.join(temporary, 'source'), verifyStage = path.join(temporary, 'verification');
    fs.mkdirSync(sourceStage); fs.mkdirSync(verifyStage);
    const sourceIdentity = {};
    for (const name of sourceFiles) {
      const bytes = fs.readFileSync(path.join(root, name)); sourceIdentity[name] = hash(bytes);
      copy(path.join(root, name), path.join(sourceStage, name));
      if (digest(path.join(sourceStage, name)) !== sourceIdentity[name]) fail('Source changed while snapshotting: ' + name);
    }
    const verificationFiles = new Set([...walk(evidence).map(name => slash(path.relative(root, path.join(evidence, name)))), ...bulkCaptures, ...walk(path.join(root, 'tools/verification')).map(name => 'tools/verification/' + name)]);
    const verificationIdentity = {};
    for (const name of verificationFiles) {
      const expected = digest(path.join(root, name));
      copy(path.join(root, name), path.join(verifyStage, name));
      if (digest(path.join(verifyStage, name)) !== expected) fail('Evidence changed while snapshotting: ' + name);
      verificationIdentity[name] = expected;
    }
    copy(baseline, path.join(verifyStage, 'baseline/accepted-22242f2.tar'));
    if (digest(path.join(verifyStage, 'baseline/accepted-22242f2.tar')) !== hash(baselineBytes)) fail('Accepted baseline changed while packaging');
    fs.writeFileSync(path.join(verifyStage, 'REVIEW-README.txt'), 'Local review candidate only. Independent Astra review and manual G01 remain open. No publication or live interoperability claim.\nSource ZIP is rooted at the repository root; extract verification ZIP over it to restore repository-relative evidence captures. Bulk docs/verification PNG captures are omitted from source ZIP only. Failed/superseded attempts remain under the evidence attempts directory and are not passing gates.\nAll permanent regenerators, fixtures, primary-source provenance, licenses and pinned QA manifests/locks are under tools/verification. Installed dependencies and browsers are intentionally absent. Consult their README files for offline environment prerequisites and the preserved reports for exact regeneration commands.\nAccepted performance baseline: baseline/accepted-22242f2.tar; extract to a separate checkout and set AUTH_LAB_EXPANSION_BASELINE_ROOT for run-expansion-native.mjs. Its standalone is checked against the independent plan baseline hash.\nRebuild source with Bun: bun run build. Package CLI: ' + usage.split('\n')[0] + '\n');
    fs.mkdirSync(output); ownsOutput = true;
    const sourceZip = path.join(output, 'auth-flow-studio-expansion-source.zip');
    const verificationZip = path.join(output, 'auth-flow-studio-expansion-verification.zip');
    run(['zip', '-q', sourceZip, '-@'], sourceStage, sourceFiles.join('\n') + '\n');
    const extracted = path.join(temporary, 'extracted'); fs.mkdirSync(extracted);
    run(['unzip', '-q', sourceZip, '-d', extracted], temporary);
    if (JSON.stringify(walk(extracted).sort()) !== JSON.stringify([...sourceFiles].sort())) fail('Source ZIP extraction inventory differs');
    for (const [name, expected] of Object.entries(sourceIdentity)) if (digest(path.join(extracted, name)) !== expected || digest(path.join(root, name)) !== expected) fail('Fresh-source byte comparison failed: ' + name);
    const build = run([process.execPath, 'build.mjs'], extracted);
    const rebuilt = path.join(extracted, 'dist/auth-flow-studio.html');
    if (digest(rebuilt) !== standaloneHash) fail('Fresh-source Bun rebuild differs from delivered standalone');
    for (const [name, expected] of Object.entries(sourceIdentity)) if (digest(path.join(root, name)) !== expected) fail('Working source changed during packaging: ' + name);
    copy(standalone, path.join(output, 'auth-flow-studio-expansion.html'));
    run(['zip', '-q', verificationZip, '-@'], verifyStage, walk(verifyStage).join('\n') + '\n');
    for (const [name, expected] of Object.entries(verificationIdentity)) if (digest(path.join(root, name)) !== expected) fail('Evidence changed during packaging: ' + name);
    const artifacts = Object.fromEntries(['auth-flow-studio-expansion-source.zip', 'auth-flow-studio-expansion.html', 'auth-flow-studio-expansion-verification.zip'].map(name => [name, { bytes: fs.statSync(path.join(output, name)).size, sha256: digest(path.join(output, name)) }]));
    const status = { kind: 'expansion-review-package', timestamp: new Date().toISOString(), passed: true, status: 'local-review-candidate-not-independent-acceptance', manualG01: 'open', independentReview: 'pending Astra review; no publication', generator: { path: slash(path.relative(root, runner)), sha256: digest(runner), argv: [process.execPath, ...process.argv.slice(1)] }, runtime: { executable: process.execPath, version: process.version, bun: process.versions.bun }, evidenceRoot: slash(path.relative(root, evidence)), evidenceHashes, disposition: { path: slash(path.relative(root, dispositionFile)), sha256: digest(dispositionFile), freshlyRegeneratedAndCompared: true }, source: { files: sourceIdentity, count: sourceFiles.length, extractedEveryFileByteIdentical: true, bulkCaptureExclusion: 'docs/verification/**/*.png; supplied as repository-relative verification overlay for final evidence' }, baseline: { sha256: hash(baselineBytes), bytes: baselineBytes.length, archiveMember: 'baseline/accepted-22242f2.tar', expectedCommit: manifest.baselineCommit, standaloneSha256: manifest.baselineStandaloneSha256 }, rebuild: { ...build, cwd: 'fresh extraction of generated source ZIP (tool-owned temporary directory)', standaloneSha256: digest(rebuilt), byteIdentical: true }, artifacts, limits: ['No gates were rerun by packaging except disposition validation and the real fresh-source Bun build.', 'Real screen-reader speech/comprehension and manual G01 remain open.', 'No live AD/KDC/IdP/SSH/RADIUS or PAKE interoperability or certification established.'] };
    status.runtime.os = { type: os.type(), release: os.release(), version: os.version() };
    fs.writeFileSync(path.join(output, 'review-package-status.json'), JSON.stringify(status, null, 2) + '\n', { flag: 'wx' });
    const sumNames = [...Object.keys(artifacts), 'review-package-status.json'];
    fs.writeFileSync(path.join(output, 'SHA256SUMS'), sumNames.map(name => digest(path.join(output, name)) + '  ' + name).join('\n') + '\n', { flag: 'wx' });
    console.log(JSON.stringify({ status: status.status, output, standaloneSha256: standaloneHash, freshSourceRebuild: true }, null, 2));
  } catch (error) {
    if (ownsOutput) {
      for (const name of fs.readdirSync(output)) fs.rmSync(path.join(output, name));
      fs.writeFileSync(path.join(output, 'review-package-status.json'), JSON.stringify({ kind: 'expansion-review-package', passed: false, status: 'failed-not-reviewable', error: String(error.message), timestamp: new Date().toISOString() }, null, 2) + '\n', { flag: 'wx' });
    }
    throw error;
  } finally { fs.rmSync(temporary, { recursive: true, force: true }); }
}
main().catch(error => { console.error(error.stack || String(error)); process.exitCode = 1; });
