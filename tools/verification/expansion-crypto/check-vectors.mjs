#!/usr/bin/env bun
// Fixed public fixtures only. No user inputs, network clients or runtime imports.
import { readFile, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join, relative, sep } from 'node:path';
import {captureReviewInputs} from '../review-input-identity.mjs';

const root = fileURLToPath(new URL('.', import.meta.url));
const project = fileURLToPath(new URL('../../../', import.meta.url));
const command = 'bun tools/verification/expansion-crypto/check-vectors.mjs';
const setup = 'bun install --cwd tools/verification/expansion-crypto --frozen-lockfile --ignore-scripts';
const digest = (data) => createHash('sha256').update(data).digest('hex');
const load = async (path) => JSON.parse(await readFile(join(root, path), 'utf8'));
const shaFile = async (path) => digest(await readFile(join(root, path)));
const report = {
  schemaVersion: 1,
  purpose: 'Fixed official-vector and synthetic-negative offline QA, not production authentication, a password checker or live interoperability evidence',
  regenerationCommand: command,
  frozenSetupCommand: setup,
  runtime: { bun: typeof Bun === 'undefined' ? null : Bun.version, platform: process.platform, arch: process.arch, openssl: process.versions.openssl ?? null },
  runnerSha256: null,
  argv: [...process.argv],
  inputIdentity: captureReviewInputs(project, fileURLToPath(import.meta.url)),
  identityContext: 'Review byte identity only; product behavior is not numerically verified by hashing it.',
  files: [],
  sources: [],
  dependencies: [],
  cases: [],
  passed: false,
};
async function tree(path, base = path) {
  const entries = (await readdir(path, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name, 'en'));
  const items = [];
  for (const entry of entries) {
    const p = join(path, entry.name);
    if (entry.isDirectory()) items.push(...await tree(p, base));
    else if (entry.isFile()) items.push({ path: relative(base, p).split(sep).join('/'), sha256: digest(await readFile(p)) });
    else throw new Error('Unexpected non-file dependency entry');
  }
  return items;
}
try {
  if (typeof Bun === 'undefined') throw new Error('Run this optional QA package with Bun');
  if (process.argv.length !== 2) throw new Error('This fixed-fixture runner accepts no arguments or password input');
  report.runnerSha256 = await shaFile('check-vectors.mjs');
  const identities = ['check-vectors.mjs', 'primitives.mjs', 'pake-vectors.mjs', 'kerberos-vectors.mjs', 'windows-vectors.mjs', 'derive-synthetic.py', 'package.json', 'bun.lock', 'sources.json'];
  for (const file of identities) report.files.push({ path: file, sha256: await shaFile(file) });
  for (const entry of await tree(join(root, 'fixtures'))) report.files.push({ path: `fixtures/${entry.path}`, sha256: entry.sha256 });
  for (const source of await load('sources.json')) {
    const actualSha256 = await shaFile(source.snapshot);
    report.sources.push({ ...source, actualSha256 });
    if (actualSha256 !== source.sha256) throw new Error(`Primary source snapshot changed: ${source.id}`);
  }
  const pkg = await load('package.json');
  for (const [name, expectedVersion] of Object.entries(pkg.dependencies)) {
    if (!/^\d+\.\d+\.\d+$/.test(expectedVersion)) throw new Error('QA dependency version is not exact');
    const directory = join(root, 'node_modules', name);
    const installed = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8'));
    if (installed.version !== expectedVersion) throw new Error(`Dependency pin mismatch: ${name}`);
    const entries = await tree(directory);
    report.dependencies.push({ name, version: installed.version, license: installed.license, fileCount: entries.length, contentTreeSha256: digest(JSON.stringify(entries)) });
  }
  const [{ registerPake }, { registerKerberos }, { registerWindows }, primitives] = await Promise.all([
    import('./pake-vectors.mjs'), import('./kerberos-vectors.mjs'), import('./windows-vectors.mjs'), import('./primitives.mjs'),
  ]);
  const fixtures = {};
  for (const name of ['rfc9382', 'rfc9383', 'rfc9588', 'ntlmv2', 'synthetic']) fixtures[name] = await load(`fixtures/${name}.json`);
  const pending = [], seen = new Set();
  const add = (id, source, fn) => {
    if (seen.has(id)) throw new Error(`Duplicate vector case ID: ${id}`);
    seen.add(id); pending.push({ id, source, fn });
  };
  add('rfc3961-A1-nfold', 'RFC 3961 section 5.1 and Appendix A.1', (check) => {
    for (const [input, size, expected] of [
      ['012345', 8, 'be072631276b1955'],
      ['password', 7, '78a07b6caf85fa'],
      ['password', 21, '59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e'],
      ['kerberos', 16, '6b65726265726f737b9b5b2b93132b93'],
    ]) check(`n-fold ${input}/${size * 8}`, primitives.nfold(primitives.utf8(input), size), primitives.bytes(expected));
  });
  registerPake(add, fixtures);
  registerKerberos(add, fixtures);
  registerWindows(add, fixtures);
  for (const { id, source, fn } of pending) {
    const result = { id, source, passed: false, checked: [] };
    try {
      await fn((name, actual, expected) => { primitives.requireEqual(actual, expected, name); result.checked.push(name); });
      result.passed = true;
    } catch (error) {
      result.error = String(error.message ?? error).slice(0, 400);
    }
    report.cases.push(result);
  }
  report.passed = report.cases.length > 0 && report.cases.every((x) => x.passed);
} catch (error) {
  report.fatal = String(error.message ?? error).slice(0, 800);
}
const afterInputs = captureReviewInputs(project, fileURLToPath(import.meta.url));
report.sourceUnchanged = JSON.stringify(afterInputs) === JSON.stringify(report.inputIdentity);
if (!report.sourceUnchanged) { report.passed = false; report.fatal = 'Review input bytes changed during numeric execution'; }
report.status = report.passed ? 'passed' : 'failed';
report.exitCode = report.passed ? 0 : 1;
report.summary = { total: report.cases.length, passed: report.cases.filter((x) => x.passed).length, failed: report.cases.filter((x) => !x.passed).length };
let output = JSON.stringify(report, null, 2);
if (Buffer.byteLength(output) > 128 * 1024) {
  output = JSON.stringify({ schemaVersion: 1, passed: false, fatal: 'Bounded report exceeded 128 KiB', runnerSha256: report.runnerSha256 });
  report.passed = false;
}
console.log(output);
if (!report.passed) process.exitCode = 1;
