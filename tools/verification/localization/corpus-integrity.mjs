import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';
import { pipeline } from 'node:stream/promises';

const producerPath = fileURLToPath(import.meta.url);
const root = path.resolve(path.dirname(producerPath), '../../..');
const usage = `Usage: bun tools/verification/localization/corpus-integrity.mjs --inventory=DIR --ui=UI_JSON --out=NEW_DIR [--handoff-dir=DIR]

DIR contains summary.json and messages.jsonl.gz. UI_JSON is the explicit SHA-bound
UI sidecar; provenance paths in summaries are never followed. Handoff files are
resolved by basename in --handoff-dir (default: repo/docs/localization/generated).
NEW_DIR must be fresh and outside the repository, inventory and UI parent roots.
Writes summary.json, report.txt and failures.jsonl.gz (every failure, no sampling).
Exit statuses: 0 = completed with no integrity failures; 1 = retained integrity
failures or collection failure; 2 = invalid arguments or output setup failure.
This is source-data integrity only, not native/browser/human/AT/release acceptance.
`;
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const expand = (text, parameters, includeDynamic = false) => text.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g, (literal, name) => {
  const definition = parameters?.[name];
  return definition?.kind === 'protected' && (includeDynamic || !definition.dynamic) && typeof definition.value === 'string' ? definition.value : literal;
});
async function fingerprint(file) {
  const digest = crypto.createHash('sha256');
  let bytes = 0;
  for await (const chunk of fs.createReadStream(file)) { digest.update(chunk); bytes += chunk.length; }
  return { path: file, sha256: digest.digest('hex'), bytes };
}
function within(child, parent) {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}
function canonicalDestination(destination) {
  let existing = destination;
  const missing = [];
  while (!fs.existsSync(existing)) { missing.unshift(path.basename(existing)); existing = path.dirname(existing); }
  return path.join(fs.realpathSync(existing), ...missing);
}
async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && (args[0] === '--help' || args[0] === '-h')) { console.log(usage); return; }
  let options, out;
  try {
    options = {};
    for (const argument of args) {
      const match = /^--(inventory|ui|out|handoff-dir)=(.+)$/.exec(argument);
      if (!match || Object.hasOwn(options, match[1])) throw new Error(`Invalid or duplicate argument: ${argument}`);
      options[match[1]] = path.resolve(match[2]);
    }
    for (const name of ['inventory', 'ui', 'out']) if (!options[name]) throw new Error(`Missing --${name}`);
    options['handoff-dir'] ??= path.join(root, 'docs/localization/generated');
    out = canonicalDestination(options.out);
    for (const forbidden of [root, options.inventory, path.dirname(options.ui)]) {
      if (within(out, fs.realpathSync(forbidden))) throw new Error(`Output must be outside ${forbidden}`);
    }
    fs.mkdirSync(out, { recursive: false });
  } catch (error) {
    console.error(`${error.message}\n${usage}`); process.exitCode = 2; return;
  }
  const report = {
    schemaVersion: 1,
    kind: 'streaming-corpus-integrity',
    scope: 'Exact source restoration and runtime English placeholder grammar only. Body protected captured values include retained dynamic values. UI static authored parameters and injected slots expand on both sides using SHA-bound declarations; dynamic UI parameters remain placeholders. Audit-only raw data is exempt from runtime placeholder grammar.',
    acceptance: { native: false, browser: false, human: false, assistiveTechnology: false, release: false },
    invocation: { argv: process.argv, cwd: process.cwd(), executable: process.execPath, versions: process.versions },
    input: { inventory: options.inventory, ui: options.ui, handoffDir: options['handoff-dir'], files: [] },
    counts: { records: 0, bodyRecords: 0, uiRecords: 0, sourceOnlyRecords: 0, rawEnglishFingerprints: 0, forms: 0, exactRoundtrips: 0, runtimeTemplateForms: 0, malformedRuntimeTemplateForms: 0, unboundRuntimeTemplateTokens: 0 },
    failures: 0, failureKinds: {}, completed: false, unchangedAfterCollection: false,
  };
  const gzip = zlib.createGzip();
  const failureOutput = pipeline(gzip, fs.createWriteStream(path.join(out, 'failures.jsonl.gz'), { flags: 'wx' }));
  // Observe asynchronous write errors immediately, then await the original promise below.
  failureOutput.catch(() => {});
  const fail = async row => {
    report.failures++;
    report.failureKinds[row.kind] = (report.failureKinds[row.kind] || 0) + 1;
    if (!gzip.write(`${JSON.stringify(row)}\n`)) await once(gzip, 'drain');
  };
  const snapshots = [];
  async function capture(file) {
    const snapshot = await fingerprint(file);
    snapshots.push(snapshot);
    return snapshot;
  }
  async function readBoundJson(file) {
    const bytes = fs.readFileSync(file);
    const snapshot = { path: file, sha256: hash(bytes), bytes: bytes.length };
    snapshots.push(snapshot);
    return { value: JSON.parse(bytes), snapshot };
  }
  try {
    report.producer = await capture(producerPath);
    report.runtime = await capture(fs.realpathSync(process.execPath));
    const { value: summary, snapshot: summarySnapshot } = await readBoundJson(path.join(options.inventory, 'summary.json'));
    const { value: ui, snapshot: uiSnapshot } = await readBoundJson(options.ui);
    report.input.summary = summarySnapshot;
    report.input.uiSidecar = uiSnapshot;
    if (!summary.uiSidecar?.sourceSha256 || uiSnapshot.sha256 !== summary.uiSidecar.sourceSha256) throw new Error('UI sidecar raw SHA256 does not match inventory summary.uiSidecar.sourceSha256');
    if (!Array.isArray(ui.summary?.authoringInputs) || !ui.summary.authoringInputs.length) throw new Error('UI sidecar has no authoringInputs');
    const declarations = new Map();
    report.input.authoringInputs = [];
    for (const input of ui.summary.authoringInputs) {
      if (typeof input.file !== 'string' || !input.file) throw new Error('Invalid authoring input filename');
      const file = path.join(options['handoff-dir'], path.basename(input.file));
      const { value: declaration, snapshot } = await readBoundJson(file);
      report.input.authoringInputs.push(snapshot);
      if (snapshot.sha256 !== input.sourceSha256) throw new Error(`UI declaration provenance mismatch: ${input.file}`);
      if (!Array.isArray(declaration.messages)) throw new Error(`Missing declaration messages: ${input.file}`);
      // Actual UI authoring input order is authoritative; later declarations win.
      for (const message of declaration.messages) declarations.set(message.key, message);
    }
    const messagesPath = path.join(options.inventory, 'messages.jsonl.gz');
    const messagesSnapshot = await capture(messagesPath);
    report.input.messages = messagesSnapshot;
    const artifact = summary.artifacts?.find(item => item.file === 'messages.jsonl.gz');
    if (artifact?.sha256 && artifact.sha256 !== messagesSnapshot.sha256) await fail({ kind: 'messages-artifact-sha256', expected: artifact.sha256, actual: messagesSnapshot.sha256 });
    if (artifact?.encodedBytes !== undefined && artifact.encodedBytes !== messagesSnapshot.bytes) await fail({ kind: 'messages-artifact-bytes', expected: artifact.encodedBytes, actual: messagesSnapshot.bytes });
    const source = fs.createReadStream(messagesPath);
    const gunzip = zlib.createGunzip();
    source.on('error', error => gunzip.destroy(error));
    source.pipe(gunzip);
    const rows = readline.createInterface({ input: gunzip, crlfDelay: Infinity });
    let lineNumber = 0;
    try {
      for await (const line of rows) {
        lineNumber++;
        if (!line) continue;
        let message;
        try { message = JSON.parse(line); } catch (error) { await fail({ kind: 'invalid-message-json', line: lineNumber, error: error.message, raw: line }); continue; }
        try {
          const isUi = message.owner.semanticId.startsWith('ui:');
          report.counts.records++;
          report.counts[isUi ? 'uiRecords' : 'bodyRecords']++;
          if (message.sourceDeclared) report.counts.sourceOnlyRecords++;
          if (!isUi) {
            if (hash(message.english) === message.sourceSha256) report.counts.rawEnglishFingerprints++;
            else await fail({ key: message.key, kind: 'raw-English-fingerprint' });
          }
          const template = isUi ? message.english : message.template;
          const original = isUi ? message.sourceEnglish : message.english;
          const forms = typeof template === 'string' ? { singular: template } : template?.plural;
          if (!forms || !Object.keys(forms).length) throw new Error('Missing or empty English template forms');
          for (const [form, text] of Object.entries(forms)) {
            report.counts.forms++;
            if (typeof text !== 'string') throw new Error(`Non-string template form: ${form}`);
            if (isUi || message.runtime !== false) {
              report.counts.runtimeTemplateForms++;
              if (/[{}]/.test(text.replace(/\{[A-Za-z][A-Za-z0-9_]*\}/g, ''))) {
                report.counts.malformedRuntimeTemplateForms++;
                await fail({ key: message.key, form, kind: 'malformed-runtime-placeholder' });
              }
              for (const token of text.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g)) {
                if (!Object.hasOwn(message.parameters || {}, token[1])) {
                  report.counts.unboundRuntimeTemplateTokens++;
                  await fail({ key: message.key, form, parameter: token[1], kind: 'unbound-runtime-placeholder' });
                }
              }
            }
            const rawExpected = typeof original === 'string' ? original : original?.plural?.[form];
            if (typeof rawExpected !== 'string') throw new Error(`Missing retained source form: ${form}`);
            const declaration = isUi ? declarations.get(message.key) : null;
            const expected = isUi ? expand(rawExpected, { ...message.parameters, ...declaration?.parameters }) : rawExpected;
            const restored = expand(text, message.parameters, !isUi);
            if (restored === expected) report.counts.exactRoundtrips++;
            else await fail({ key: message.key, form, kind: 'restored-source-mismatch', expectedSha256: hash(expected), restoredSha256: hash(restored), expected, restored });
          }
        } catch (error) { await fail({ kind: 'invalid-message-shape', line: lineNumber, key: message?.key, error: error.message, message }); }
      }
    } finally { rows.close(); source.destroy(); gunzip.destroy(); }
    const expectedCounts = {
      records: summary.counts?.uniqueMessageUnits,
      uiRecords: ui.summary?.counts?.sourceContracts,
      sourceOnlyRecords: summary.counts?.sourceDeclaredOnlyContracts,
    };
    report.expectedCounts = { ...expectedCounts, artifactRecords: artifact?.records };
    for (const [field, expected] of Object.entries(expectedCounts)) {
      if (expected !== undefined && report.counts[field] !== expected) await fail({ kind: 'summary-count-mismatch', field, expected, actual: report.counts[field] });
    }
    if (artifact?.records !== undefined && report.counts.records !== artifact.records) await fail({ kind: 'artifact-record-count-mismatch', expected: artifact.records, actual: report.counts.records });
    if (!report.counts.records || !report.counts.forms) await fail({ kind: 'empty-corpus' });
    report.completed = true;
  } catch (error) { await fail({ kind: 'collection-error', error: error.stack || String(error) }); }
  try {
    report.unchangedAfterCollection = true;
    for (const before of snapshots) {
      const after = await fingerprint(before.path);
      report.input.files.push({ ...before, after });
      if (before.sha256 !== after.sha256 || before.bytes !== after.bytes) {
        report.unchangedAfterCollection = false;
        await fail({ kind: 'input-or-producer-changed', before, after });
      }
    }
  } catch (error) { report.unchangedAfterCollection = false; await fail({ kind: 'post-collection-fingerprint-error', error: error.message }); }
  gzip.end();
  await failureOutput;
  report.failureArtifact = await fingerprint(path.join(out, 'failures.jsonl.gz'));
  report.status = report.completed && report.failures === 0 && report.unchangedAfterCollection ? 'passed-source-integrity-only' : 'failed';
  fs.writeFileSync(path.join(out, 'summary.json'), `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });
  fs.writeFileSync(path.join(out, 'report.txt'), `Corpus integrity: ${report.status}\nRecords: ${report.counts.records}\nForms: ${report.counts.forms}\nExact restored forms: ${report.counts.exactRoundtrips}\nFailures: ${report.failures}\nAll failures: failures.jsonl.gz\nNative/browser/human/AT/release acceptance: not performed, not claimed.\n`, { flag: 'wx' });
  console.log(JSON.stringify({ out, status: report.status, counts: report.counts, failures: report.failures }));
  if (report.status === 'failed') process.exitCode = 1;
}
main().catch(error => { console.error(error.stack || String(error)); process.exitCode = 1; });
