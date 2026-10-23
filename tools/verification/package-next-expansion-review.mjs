#!/usr/bin/env bun
// Phase-scoped packaging only. Input evidence is immutable, not regenerated or relabeled.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const runner = fileURLToPath(import.meta.url);
const root = fs.realpathSync(path.resolve(path.dirname(runner), '../..'));
const usage = `Usage:
  bun tools/verification/package-next-expansion-review.mjs --identity --manifest=REPO_FILE
  bun tools/verification/package-next-expansion-review.mjs --phase=P0..P6 --out=NEW_EXTERNAL_DIR --contract=JSON --status=JSON
Requires Bun, zip and unzip. Packaging performs one extracted-source offline build, never installs, tests or browser runs.
See docs/next-expansion/packaging.md for the versioned input schemas and extraction/checksum bases.`;
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const inside = (base, file) => file === base || file.startsWith(base + path.sep);
const slash = name => name.split(path.sep).join('/');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const digest = file => hash(fs.readFileSync(file));
const same = (a, b) => JSON.stringify(normalize(a)) === JSON.stringify(normalize(b));
function normalize(value) {
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, normalize(value[key])]));
  return value;
}
function text(value, label) { assert(typeof value === 'string' && value.trim(), 'Missing ' + label); return value; }
function array(value, label, nonempty = true) { assert(Array.isArray(value) && (!nonempty || value.length), 'Missing array: ' + label); return value; }
function safeRelative(name) {
  text(name, 'relative filename');
  assert(!name.startsWith('-') && !name.includes('\\') && !/[\r\n\0]/.test(name) && !path.isAbsolute(name) && name.split('/').every(part => part && part !== '.' && part !== '..'), 'Unsafe relative filename: ' + name);
  return name;
}
function regular(file) {
  // Check ancestor components too, so input refs cannot escape through a symlink directory.
  const absolute = path.resolve(file);
  let cursor = path.parse(absolute).root;
  for (const component of absolute.slice(cursor.length).split(path.sep)) {
    cursor = path.join(cursor, component);
    assert(!fs.lstatSync(cursor).isSymbolicLink(), 'Refusing symlink input: ' + cursor);
  }
  const stat = fs.lstatSync(absolute);
  assert(stat.isFile(), 'Expected regular file: ' + absolute);
  return stat;
}
function json(file) { regular(file); return JSON.parse(fs.readFileSync(file, 'utf8')); }
const tracked = new Map();
function ref(value, label, repositoryOnly = false) {
  assert(value && typeof value === 'object', 'Missing file reference: ' + label);
  const file = path.resolve(root, text(value.path, label + '.path'));
  if (repositoryOnly) assert(inside(root, file), 'Reference must be repository-relative: ' + label);
  const stat = regular(file);
  assert(/^[a-f0-9]{64}$/.test(value.sha256) && digest(file) === value.sha256, 'Missing/stale SHA256: ' + label);
  assert(Number.isSafeInteger(value.bytes) && value.bytes === stat.size, 'Missing/stale byte count: ' + label);
  tracked.set(file, value.sha256);
  return { file, path: value.path, sha256: value.sha256, bytes: value.bytes };
}
const excludedNames = new Set(['.git', 'node_modules', '.cache', '.bun', '__pycache__', '.DS_Store', 'Thumbs.db', '__MACOSX', 'coverage', '.nyc_output']);
function walk(base, relative = '', source = false) {
  const result = [];
  for (const entry of fs.readdirSync(path.join(base, relative), { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
    if (source && (excludedNames.has(entry.name) || entry.name.endsWith('.pyc'))) continue;
    const name = safeRelative(relative ? relative + '/' + entry.name : entry.name);
    // Current verification is an explicit overlay. Bulk predecessor captures and archives stay in their original packages.
    if (source && (name === 'docs/verification' || /\.(?:zip|tar|tar\.gz|tgz|7z)$/i.test(name))) continue;
    assert(!entry.isSymbolicLink(), 'Refusing symlink package member: ' + name);
    if (entry.isDirectory()) result.push(...walk(base, name, source));
    else { assert(entry.isFile(), 'Refusing special package member: ' + name); result.push(name); }
  }
  return result;
}
function sourceIdentity() {
  const files = ['index.html', 'build.mjs', 'security-policy.mjs', 'package.json', ...['assets', 'src', 'tests'].flatMap(directory => walk(path.join(root, directory), '', true).map(name => directory + '/' + name))].sort();
  const snapshot = createHash('sha256');
  const identities = {};
  for (const name of files) {
    regular(path.join(root, name));
    const bytes = fs.readFileSync(path.join(root, name));
    snapshot.update(name + '\0'); snapshot.update(bytes); snapshot.update('\0');
    identities[name] = hash(bytes);
  }
  return { algorithm: 'sha256-path-nul-bytes-nul-v1', sha256: snapshot.digest('hex'), files: identities };
}
function fileIdentity(file) { return { path: slash(path.relative(root, file)), sha256: digest(file), bytes: regular(file).size }; }
function copy(from, to) {
  regular(from); fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.copyFileSync(from, to, fs.constants.COPYFILE_EXCL);
}
function writeJson(file, value) { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx' }); }
function execute(argv, cwd, input) {
  const result = spawnSync(argv[0], argv.slice(1), { cwd, input, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...process.env, BUN_INSTALL_AUTO: 'disable', npm_config_offline: 'true' } });
  assert(!result.error && result.status === 0, 'Command failed: ' + JSON.stringify(argv) + '\n' + (result.error?.message || result.stderr || result.stdout));
  return { argv, exitStatus: result.status, stdout: result.stdout, stderr: result.stderr };
}
function pointer(document, expression) {
  assert(typeof expression === 'string' && (expression === '' || expression.startsWith('/')), 'Invalid JSON pointer: ' + expression);
  let values = [document];
  for (const segment of expression === '' ? [] : expression.slice(1).split('/')) {
    assert(!/~(?![01])/u.test(segment), 'Invalid JSON pointer escape: ' + expression);
    const key = segment.replace(/~1/g, '/').replace(/~0/g, '~');
    values = values.flatMap(value => {
      if (key === '*') { assert(Array.isArray(value), 'Wildcard requires array: ' + expression); return value; }
      assert(value !== null && typeof value === 'object' && Object.hasOwn(value, key), 'Missing report pointer: ' + expression);
      return [value[key]];
    });
  }
  assert(values.length, 'Empty report pointer: ' + expression);
  return values;
}
function check(document, rule, label) {
  for (const actual of pointer(document, rule.pointer)) {
    let passed = false;
    switch (rule.op) {
      case 'equals': assert(Object.hasOwn(rule, 'value'), 'Missing equals value'); passed = same(actual, rule.value); break;
      case 'length': passed = (Array.isArray(actual) || typeof actual === 'string') && actual.length === rule.value; break;
      case 'minLength': passed = (Array.isArray(actual) || typeof actual === 'string') && actual.length >= rule.value; break;
      case 'includes': passed = Array.isArray(actual) && actual.some(value => same(value, rule.value)); break;
      case 'notEmpty': passed = typeof actual === 'string' ? !!actual.trim() : Array.isArray(actual) ? actual.length > 0 : actual !== null && typeof actual === 'object' && Object.keys(actual).length > 0; break;
      default: throw new Error('Unknown check operation: ' + rule.op);
    }
    assert(passed, 'Unsatisfied phase evidence: ' + label + ' ' + rule.pointer + ' (' + rule.op + ')');
  }
}
function uniqueIds(rows, label) {
  const ids = new Set();
  for (const row of rows) { assert(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(row.id) && !ids.has(row.id), 'Invalid/duplicate ' + label + ' ID'); ids.add(row.id); }
}
function main() {
  if (process.argv.slice(2).some(arg => arg === '--help' || arg === '-h')) { console.log(usage); return; }
  const options = {};
  for (const arg of process.argv.slice(2)) {
    if (arg === '--identity') { assert(!options.identity, 'Duplicate --identity'); options.identity = true; continue; }
    const match = /^--(phase|out|contract|status|manifest)=(.+)$/.exec(arg);
    assert(match && !options[match[1]], 'Unknown/duplicate option: ' + arg + '\n' + usage); options[match[1]] = match[2];
  }
  assert(process.versions.bun, 'Run this packager with Bun');
  if (options.identity) {
    assert(options.manifest && Object.keys(options).length === 2, usage);
    const manifest = path.resolve(root, options.manifest);
    assert(inside(root, manifest), 'Manifest must be in source tree');
    console.log(JSON.stringify({ source: sourceIdentity(), standalone: fileIdentity(path.join(root, 'dist/auth-flow-studio.html')), manifest: fileIdentity(manifest), packager: fileIdentity(runner) }, null, 2)); return;
  }
  assert(/^P[0-6]$/.test(options.phase) && options.out && options.contract && options.status && !options.manifest, usage);
  const output = path.resolve(options.out);
  const actualOutput = path.join(fs.realpathSync(path.dirname(output)), path.basename(output));
  assert(output === actualOutput && !inside(root, actualOutput) && !inside(actualOutput, root) && !fs.existsSync(output), 'Output must be new, external and have no symlink parent');
  const contractFile = path.resolve(root, options.contract), statusFile = path.resolve(root, options.status);
  const contract = json(contractFile), inputStatus = json(statusFile);
  tracked.set(contractFile, digest(contractFile)); tracked.set(statusFile, digest(statusFile));
  assert(contract.schemaVersion === 1 && contract.kind === 'next-expansion-phase-package-contract', 'Unsupported phase contract');
  assert(inputStatus.schemaVersion === 1 && inputStatus.kind === 'next-expansion-phase-package-input', 'Unsupported status schema');
  assert(contract.phase === options.phase && inputStatus.phase === options.phase && inputStatus.contractSha256 === digest(contractFile), 'Phase/contract identity mismatch');
  assert(contract.scope && typeof contract.scope === 'object' && Object.keys(contract.scope).length && same(contract.scope, inputStatus.scope), 'Missing/mismatched contract scope');
  const currentSource = sourceIdentity();
  assert(same(currentSource, inputStatus.source), 'Stale/incomplete current source identity');
  const standalone = ref(inputStatus.standalone, 'standalone', true), manifest = ref(contract.manifest, 'manifest', true);
  assert(standalone.file === path.join(root, 'dist/auth-flow-studio.html'), 'Standalone must be the current dist/auth-flow-studio.html');
  assert(same(contract.manifest, inputStatus.manifest), 'Status manifest identity mismatch');
  const references = array(contract.references, 'immutable references');
  uniqueIds(references, 'reference');
  for (const role of ['plan', 'accepted-review']) assert(references.some(row => row.role === role), 'Missing immutable ' + role + ' reference');
  const immutable = references.map(row => ({ ...ref(row, row.id), id: row.id, role: text(row.role, 'reference role') }));
  const limitations = inputStatus.limitations;
  for (const key of ['manualG01', 'siblingKeyOrigins', 'historicalPerformance', 'currentPerformance', 'livePlatform', 'source']) {
    assert(limitations?.[key], 'Missing limitation: ' + key); text(limitations[key].status, key + ' status'); text(limitations[key].details, key + ' details');
  }
  assert(limitations.siblingKeyOrigins.total === 6 && limitations.historicalPerformance.total === 7, 'Retain the six disclosed sibling-key-origin omissions and seven historical performance flags explicitly');
  text(inputStatus.remainingScope, 'remaining phase scope');
  const requirements = array(contract.requiredEvidence, 'required evidence'); uniqueIds(requirements, 'requirement');
  const evidence = array(inputStatus.evidence, 'evidence'); uniqueIds(evidence, 'evidence');
  const knownStatuses = new Set(['passed', 'partial', 'failed', 'blocked', 'unverified', 'not-performed']);
  const retained = array(inputStatus.retained, 'retained evidence', false); uniqueIds(retained, 'retained evidence');
  const records = [];
  for (const row of evidence) {
    const requirement = requirements.find(item => item.id === row.id);
    assert(requirement, 'Evidence not declared by phase contract: ' + row.id);
    assert(knownStatuses.has(row.status) && array(requirement.allowedStatuses, row.id + ' allowed statuses').includes(row.status), 'Unacceptable phase evidence status: ' + row.id);
    assert(row.current === true, 'Historical evidence cannot satisfy current phase requirement: ' + row.id);
    text(requirement.kind, row.id + ' kind'); text(row.summary, row.id + ' summary');
    const report = ref(row.report, row.id + ' report', true), data = json(report.file);
    const generator = ref(row.runner, row.id + ' runner', true);
    assert(generator.file === path.resolve(root, text(requirement.runner, row.id + ' required runner')), 'Wrong runner for ' + row.id);
    const targets = { sourceSha256: currentSource.sha256, sourceFiles: currentSource.files, standaloneSha256: standalone.sha256, manifestSha256: manifest.sha256, runnerSha256: generator.sha256, status: row.status };
    const bindings = array(requirement.bindings, row.id + ' identity bindings');
    for (const target of ['standaloneSha256', 'manifestSha256', 'runnerSha256', 'status']) assert(bindings.some(binding => binding.target === target), 'Missing ' + target + ' binding: ' + row.id);
    assert(bindings.some(binding => ['sourceSha256', 'sourceFiles'].includes(binding.target)), 'Missing source binding: ' + row.id);
    for (const binding of bindings) {
      assert(Object.hasOwn(targets, binding.target), 'Unknown identity binding: ' + binding.target);
      for (const value of pointer(data, binding.pointer)) assert(same(value, targets[binding.target]), 'Stale report ' + binding.target + ': ' + row.id);
    }
    for (const rule of array(requirement.checks, row.id + ' checks')) check(data, rule, row.id);
    // These pointer locations are supplied by the phase contract, not guessed report shapes.
    const execution = requirement.execution;
    assert(execution, 'Missing execution pointer contract: ' + row.id);
    const one = key => { const values = pointer(data, execution[key]); assert(values.length === 1, 'Execution pointer must select one value: ' + key); return values[0]; };
    const argv = one('argv'), runtime = one('runtime'), exitStatus = one('exitStatus');
    array(argv, row.id + ' argv').forEach(value => text(value, 'argv value'));
    assert(runtime && typeof runtime === 'object' && Object.keys(runtime).length && Number.isInteger(exitStatus), 'Missing execution provenance: ' + row.id);
    if (row.status === 'passed') assert(exitStatus === 0, 'Passed evidence has nonzero exit status: ' + row.id);
    const members = array(row.files, row.id + ' raw files', false).map((value, index) => ref(value, row.id + ' file ' + index, true));
    // Optional declared path pointers prove report references are among the delivered source/overlay files.
    for (const reference of requirement.fileReferences || []) {
      assert(['report', 'repository'].includes(reference.base), 'Unknown report reference base: ' + row.id);
      const paths = pointer(data, reference.pointer);
      const hashes = reference.sha256Pointer === undefined ? null : pointer(data, reference.sha256Pointer);
      assert(!hashes || hashes.length === paths.length, 'Report reference/hash selection count differs: ' + row.id);
      for (const [index, value] of paths.entries()) {
        const file = path.resolve(reference.base === 'report' ? path.dirname(report.file) : root, text(value, 'report file reference'));
        assert(inside(root, file) && (members.some(member => member.file === file) || Object.hasOwn(currentSource.files, slash(path.relative(root, file)))), 'Undelivered report reference: ' + row.id + ' -> ' + value);
        if (hashes) assert(hashes[index] === digest(file), 'Stale raw report file identity: ' + row.id + ' -> ' + value);
      }
    }
    records.push({ id: row.id, kind: requirement.kind, status: row.status, summary: row.summary, current: true, report, runner: generator, files: members, execution: { argv, runtime, exitStatus } });
  }
  for (const requirement of requirements) assert(records.some(row => row.id === requirement.id), 'Missing required phase evidence: ' + requirement.id);
  if (limitations.manualG01.status === 'passed') assert(records.some(row => row.kind === 'manual' && row.status === 'passed'), 'G01 cannot pass without current manual evidence');
  const history = retained.map(row => {
    assert(['original', 'failing', 'historical', 'superseded'].includes(row.role), 'Invalid retained evidence role');
    return { id: row.id, role: row.role, status: text(row.status, 'retained status'), summary: text(row.summary, 'retained summary'), files: array(row.files, 'retained files').map((value, index) => ref(value, row.id + ' retained ' + index)) };
  });
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-lab-next-package-'));
  let ownsOutput = false;
  try {
    const sourceStage = path.join(temporary, 'source-stage'), delivery = path.join(temporary, 'delivery');
    fs.mkdirSync(sourceStage); fs.mkdirSync(delivery);
    const sourceFiles = walk(root, '', true), sourceMap = {};
    for (const name of sourceFiles) {
      const file = path.join(root, name); sourceMap[name] = digest(file); tracked.set(file, sourceMap[name]);
      copy(file, path.join(sourceStage, name));
      assert(digest(path.join(sourceStage, name)) === sourceMap[name], 'Source changed while snapshotting: ' + name);
    }
    for (const [name, sha256] of Object.entries(currentSource.files)) assert(sourceMap[name] === sha256, 'Source archive omitted/changed required input: ' + name);
    assert(Object.hasOwn(sourceMap, slash(path.relative(root, manifest.file))) && Object.hasOwn(sourceMap, slash(path.relative(root, runner))), 'Source archive must include manifest and packaging runner');
    for (const row of records) assert(sourceMap[slash(path.relative(root, row.runner.file))] === row.runner.sha256, 'Source archive omitted/changed current evidence runner: ' + row.id);
    const stem = 'auth-flow-studio-next-expansion-' + options.phase.toLowerCase();
    const sourceName = stem + '-source.zip', htmlName = stem + '.html', verifyName = stem + '-verification.zip';
    const sourceZip = path.join(delivery, sourceName);
    execute(['zip', '-q', sourceZip, '-@'], sourceStage, sourceFiles.join('\n') + '\n');
    const extracted = path.join(temporary, 'extracted'); fs.mkdirSync(extracted);
    execute(['unzip', '-q', sourceZip, '-d', extracted], temporary);
    assert(same(walk(extracted).sort(), sourceFiles.slice().sort()), 'Extracted source inventory differs');
    for (const [name, expected] of Object.entries(sourceMap)) assert(digest(path.join(extracted, name)) === expected, 'Extracted source byte mismatch: ' + name);
    const rebuild = execute([process.execPath, 'build.mjs'], extracted);
    const rebuilt = path.join(extracted, 'dist/auth-flow-studio.html');
    assert(fs.readFileSync(rebuilt).equals(fs.readFileSync(standalone.file)), 'Actual extracted-source offline rebuild differs from delivered standalone');
    copy(standalone.file, path.join(delivery, htmlName));
    const mappings = [];
    function promote(value, target, role) {
      safeRelative(target);
      const destination = path.join(delivery, target);
      if (fs.existsSync(destination)) assert(digest(destination) === value.sha256, 'Conflicting delivered evidence: ' + target);
      else copy(value.file, destination);
      assert(digest(destination) === value.sha256, 'Input changed while copying: ' + value.path);
      mappings.push({ originalPath: value.path, deliveredPath: target, sha256: value.sha256, bytes: value.bytes, role });
      return target;
    }
    const overlay = value => 'verification/overlay/' + safeRelative(slash(path.relative(root, value.file)));
    const portableRecords = records.map(row => ({ ...row, report: promote(row.report, overlay(row.report), 'current-report'), runner: { path: 'source/' + slash(path.relative(root, row.runner.file)), sha256: row.runner.sha256, bytes: row.runner.bytes }, files: row.files.map(value => promote(value, overlay(value), 'current-raw')) }));
    const portableHistory = history.map(row => ({ ...row, files: row.files.map((value, index) => promote(value, 'verification/retained/' + row.id + '/' + index + '-' + safeRelative(path.basename(value.file)), row.role)) }));
    const portableReferences = immutable.map(value => ({ id: value.id, role: value.role, path: promote(value, 'verification/inputs/' + value.id + '-' + safeRelative(path.basename(value.file)), 'immutable-' + value.role), sha256: value.sha256, bytes: value.bytes }));
    promote({ file: contractFile, path: options.contract, sha256: digest(contractFile), bytes: regular(contractFile).size }, 'verification/inputs/phase-contract.json', 'phase-contract');
    promote({ file: statusFile, path: options.status, sha256: digest(statusFile), bytes: regular(statusFile).size }, 'verification/inputs/evidence-input.json', 'evidence-input');
    const packageStatus = {
      schemaVersion: 1, kind: 'next-expansion-review-package', phase: options.phase, timestamp: new Date().toISOString(),
      packageIntegrity: 'verified', status: 'phase-review-candidate-not-release-acceptance', scope: contract.scope,
      evidenceStatuses: portableRecords, retained: portableHistory, limitations, remainingScope: inputStatus.remainingScope,
      source: { archive: sourceName, files: sourceMap, identity: currentSource, extractedInventoryAndBytesMatched: true },
      standalone: { path: htmlName, sha256: standalone.sha256, bytes: standalone.bytes }, manifest: { ...contract.manifest, path: 'source/' + slash(path.relative(root, manifest.file)) }, references: portableReferences,
      generator: { path: 'source/' + slash(path.relative(root, runner)), sha256: digest(runner), actualArgv: [process.execPath, ...process.argv.slice(1)] },
      runtime: { bun: process.versions.bun, version: process.version, os: { type: os.type(), release: os.release(), arch: os.arch() } },
      rebuild: { argv: ['bun', 'build.mjs'], cwd: 'source', exitStatus: rebuild.exitStatus, stdout: rebuild.stdout, stderr: rebuild.stderr, byteIdentical: true, automaticInstalls: 'disabled', acceptanceSuitesRunByPackager: false },
      checksumBase: 'delivery root after verification ZIP extraction; source/ exists only after source ZIP extraction',
      checksumExclusions: ['verification/INTERNAL-SHA256SUMS', verifyName, 'SHA256SUMS'],
      publication: 'not authorized; no commit, push, deployment or live authentication performed'
    };
    writeJson(path.join(delivery, 'verification/package-status.json'), packageStatus);
    writeJson(path.join(delivery, 'verification/path-manifest.json'), { schemaVersion: 1, base: 'delivery-root', inputPathsAreHistoricalProvenanceNotPortableInstructions: true, mappings });
    const handoff = `${options.phase} next-expansion reviewer handoff\n\nPhase review candidate only. Packaging integrity is not protocol, manual, performance, native or independent release acceptance.\nScope (contract-derived): ${JSON.stringify(contract.scope)}\nRemaining scope: ${inputStatus.remainingScope}\n\nDelivered siblings: ${htmlName}, ${sourceName}, ${verifyName}, HANDOFF.txt, SHA256SUMS.\nStandalone SHA256: ${standalone.sha256}\nSource ZIP SHA256: ${digest(sourceZip)}\nCanonical build/test source SHA256: ${currentSource.sha256}\nManifest: source/${slash(path.relative(root, manifest.file))} (${manifest.sha256})\n\nExtraction and offline rebuild (run from the directory holding ALL delivered siblings):\n  sha256sum -c SHA256SUMS\n  unzip -n ${verifyName}\n  sha256sum -c verification/INTERNAL-SHA256SUMS\n  mkdir source\n  unzip -n ${sourceName} -d source\n  cp -R verification/overlay/. source/\n  (cd source && BUN_INSTALL_AUTO=disable bun build.mjs)\n  cmp source/dist/auth-flow-studio.html ${htmlName}\nNo install step. Bun, zip/unzip and sha256sum/cmp are environment prerequisites. The package already performed an actual extracted-source Bun rebuild and byte comparison; no tests/browser runs were performed by packaging.\n\nChecksum base: delivery root, NOT verification/. Internal checksums cover the sibling source ZIP/HTML, this handoff and all verification members except INTERNAL-SHA256SUMS itself. They intentionally exclude the not-yet-created verification ZIP and outer SHA256SUMS. Outer checksums cover final sibling artifacts including the completed verification ZIP. The final ZIP never hashes itself.\n\nVerification ZIP extraction creates verification/ and this identical HANDOFF.txt. Source ZIP is repository-rooted and extracts into source/. Copy verification/overlay/. over source/ to restore original repository-relative current evidence paths. verification/retained/ preserves exact original/failing/historical bytes separately. verification/path-manifest.json maps original provenance paths (including absolute archival paths inside immutable logs) to delivered paths; original paths are not portable instructions.\n\nRead verification/package-status.json for exact evidence statuses, current versus retained identities, runner/argv/runtime/exit status, source inventory, rebuild and limitations. Read verification/inputs/phase-contract.json and evidence-input.json for the supplied contract/status bytes and verification/inputs/ for immutable plan/review references. No old runner or acceptance result is invented. Source omits docs/verification, caches, dependency directories and archive files; only explicitly provided evidence is promoted. Historical originals remain untouched.\n\nCurrent evidence:\n${portableRecords.map(row => `- ${row.id}: ${row.status} (${row.kind}); ${row.report}; ${row.summary}`).join('\n')}\n\nLimitations (not hidden by packaging integrity):\n${Object.entries(limitations).map(([key, value]) => `- ${key}: ${value.status}; ${value.details}${value.total === undefined ? '' : '; disclosed total=' + value.total}`).join('\n')}\n\nRetained evidence:\n${portableHistory.map(row => `- ${row.id}: ${row.role}/${row.status}; ${row.summary}; ${row.files.join(', ')}`).join('\n') || '- None supplied; no historical result is claimed.'}\n\nNo commit, push, deploy, live authentication or independent acceptance is performed by this tool.\n`;
    fs.writeFileSync(path.join(delivery, 'HANDOFF.txt'), handoff, { flag: 'wx' });
    const internalFiles = [sourceName, htmlName, 'HANDOFF.txt', ...walk(path.join(delivery, 'verification')).map(name => 'verification/' + name)].sort();
    const payload = Object.fromEntries(internalFiles.map(name => [name, { sha256: digest(path.join(delivery, name)), bytes: regular(path.join(delivery, name)).size }]));
    writeJson(path.join(delivery, 'verification/internal-manifest.json'), { schemaVersion: 1, base: 'delivery-root', files: payload, exclusions: ['verification/internal-manifest.json', 'verification/INTERNAL-SHA256SUMS', verifyName, 'SHA256SUMS'], sourceExtractedFiles: { base: 'source/', files: sourceMap } });
    const sumFiles = [...internalFiles, 'verification/internal-manifest.json'].sort();
    fs.writeFileSync(path.join(delivery, 'verification/INTERNAL-SHA256SUMS'), sumFiles.map(name => digest(path.join(delivery, name)) + '  ' + name).join('\n') + '\n', { flag: 'wx' });
    const verificationFiles = ['HANDOFF.txt', ...walk(path.join(delivery, 'verification')).map(name => 'verification/' + name)].sort();
    execute(['zip', '-q', path.join(delivery, verifyName), '-@'], delivery, verificationFiles.join('\n') + '\n');
    const verifyExtracted = path.join(temporary, 'verification-extracted'); fs.mkdirSync(verifyExtracted);
    execute(['unzip', '-q', path.join(delivery, verifyName), '-d', verifyExtracted], temporary);
    assert(same(walk(verifyExtracted).sort(), verificationFiles), 'Verification ZIP inventory differs');
    for (const name of verificationFiles) assert(fs.readFileSync(path.join(verifyExtracted, name)).equals(fs.readFileSync(path.join(delivery, name))), 'Verification ZIP byte mismatch: ' + name);
    for (const [file, expected] of tracked) assert(digest(file) === expected, 'Input changed during packaging: ' + file);
    assert(same(sourceIdentity(), currentSource), 'Current source changed during packaging');
    const outerFiles = [sourceName, htmlName, verifyName, 'HANDOFF.txt'].sort();
    fs.writeFileSync(path.join(delivery, 'SHA256SUMS'), outerFiles.map(name => digest(path.join(delivery, name)) + '  ' + name).join('\n') + '\n', { flag: 'wx' });
    fs.mkdirSync(output); ownsOutput = true;
    for (const name of [...outerFiles, 'SHA256SUMS']) copy(path.join(delivery, name), path.join(output, name));
    console.log(JSON.stringify({ phase: options.phase, status: packageStatus.status, output, standaloneSha256: standalone.sha256, sourceZipSha256: digest(path.join(output, sourceName)), verificationZipSha256: digest(path.join(output, verifyName)), extractedSourceRebuild: 'byte-identical', limitations }, null, 2));
  } catch (error) {
    if (ownsOutput) writeJson(path.join(output, 'package-failure.json'), { status: 'failed-not-reviewable', phase: options.phase, error: error.message });
    throw error;
  } finally { fs.rmSync(temporary, { recursive: true, force: true }); }
}
try { main(); } catch (error) { console.error(error.stack || String(error)); process.exitCode = 1; }
