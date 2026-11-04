// Premeasurement metadata only. Importing this module starts no browser or CLI job.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {compactEnumerate} from '../compact-view-fixtures.mjs';
import {LOAD_MODES, captureInputs} from '../compact-mobile-browser.mjs';

export const PERFORMANCE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
export const CONTRACT_PATH = 'docs/localization/performance-contract.json';
export const LOCALE_STORAGE_KEY = 'auth-flow-studio.locale.v1';
export const PRESENTATION_STORAGE_KEY = 'auth-flow-studio.presentation.v1';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const freeze = value => {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) freeze(item);
    Object.freeze(value);
  }
  return value;
};

export const PERFORMANCE_FIXTURES = freeze([
  {id:'perf-basic-web', role:'Basic Keycloak and RTL ordinary control', classification:'ordinary', scenarioId:'basic-keycloak', variantId:'default', subfixtureId:null, caseId:'case-85457009fd7c6fe09f547c56', startupScenarioId:'basic-keycloak', caseKind:'preset'},
  {id:'perf-nested-jwt-payload', role:'Dense explanatory detail and nested payload', classification:'large-payload', scenarioId:'lab-jwt03', variantId:'invalid-inner-signature', subfixtureId:null, caseId:'case-7e076fabd96a9617c8b77e29', startupScenarioId:'basic-keycloak', caseKind:'registered-case', queueBoundary:3, queueEdge:'end', sourceSteps:7, authoredRowBytes:7007},
  {id:'perf-long-dnssec-history', role:'Long authored trace and exact history', classification:'large-history', scenarioId:'lab-dnssec15', variantId:'rfc5011-add', subfixtureId:null, caseId:'case-00c443eef8bd975051379505', startupScenarioId:'basic-keycloak', caseKind:'registered-case', queueBoundary:24, queueEdge:'end', sourceSteps:25, historyArtifactId:'lab-dnssec15:anchor-signature-child-anchor-observation-long-signature', historyHoldingId:'lab-dnssec15:rfc5011-add:holding:29', historyOwner:'dnsResolver', historyRows:10},
  {id:'perf-core-fields', role:'Global field search and Compact 40-to-80 expansion', classification:'ordinary', scenarioId:'core', variantId:'default', subfixtureId:null, caseId:'case-b646f3408ce01b24b034e470', startupScenarioId:'basic-keycloak', caseKind:'configurable-core'},
  {id:'perf-mcp09-fields', role:'Scoped model field search and global expansion control', classification:'ordinary', scenarioId:'lab-mcp09', variantId:'default', subfixtureId:null, caseId:'case-faef933402f71b48aab6a623', startupScenarioId:'basic-keycloak', caseKind:'registered-case'}
]);

export function loadPerformanceContract(root = PERFORMANCE_ROOT) {
  const contract = JSON.parse(fs.readFileSync(path.join(root, CONTRACT_PATH), 'utf8'));
  assert.equal(contract.kind, 'localization-premeasurement-performance-contract');
  assert.equal(contract.status, 'predeclared-not-collected');
  const startingBytes = fs.readFileSync(path.join(root, contract.authority.startingInputsPath));
  assert.equal(digest(startingBytes), contract.authority.startingInputsSha256, 'Frozen starting-input record changed');
  const starting = JSON.parse(startingBytes);
  assert.equal(starting.immutableSnapshot, contract.inputs.baseline.root);
  assert.equal(starting.canonical.canonicalSha256, contract.inputs.baseline.sourceSha256);
  assert.equal(starting.canonical.standalone.sha256, contract.inputs.baseline.standaloneSha256);
  assert.equal(starting.authority.sha256, contract.authority.sha256);
  assert.equal(digest(fs.readFileSync(path.join(root, contract.authority.path))), contract.authority.sha256);
  assert.deepEqual(contract.matrix.loadModes, LOAD_MODES);
  assert.deepEqual(contract.matrix.fixtureIds, PERFORMANCE_FIXTURES.map(fixture => fixture.id));
  return freeze(contract);
}

// Only registered metadata is needed here. The frozen source snapshot intentionally
// does not contain verification helpers. Never import app.js or invent a Core
// configuration product merely to obtain registered case identities.
export async function registeredPerformanceCatalog(root) {
  const importSource = name => import(pathToFileURL(path.join(root, 'src', name)).href);
  const [presets, catalog] = await Promise.all([importSource('learning-presets.js'), importSource('lab-catalog.js')]);
  return compactEnumerate({...presets, ...catalog, heldCoreConfigurations:function* () {}});
}

export function resolvePerformanceFixtures(catalog) {
  assert.ok(Array.isArray(catalog.cases), 'Actual compactEnumerate catalog required');
  return freeze(PERFORMANCE_FIXTURES.map(fixture => {
    const matches = catalog.cases.filter(entry => entry.choiceId === fixture.scenarioId && entry.variant === fixture.variantId && entry.member === fixture.subfixtureId && entry.kind === fixture.caseKind);
    assert.equal(matches.length, 1, 'Unique actual registered fixture: ' + fixture.id);
    assert.equal(matches[0].id, fixture.caseId, 'Canonical case identity changed: ' + fixture.id);
    return {...fixture, canonicalCase:matches[0]};
  }));
}

export async function bindPerformanceFixtures({candidateRoot = PERFORMANCE_ROOT, baselineRoot} = {}) {
  const contract = loadPerformanceContract(candidateRoot);
  baselineRoot = fs.realpathSync(baselineRoot ?? contract.inputs.baseline.root);
  const baselineInputs = captureInputs(baselineRoot);
  assert.equal(baselineInputs.canonicalSha256, contract.inputs.baseline.sourceSha256, 'Use the exact frozen 1.2 source bytes, not an older Compact control');
  assert.equal(baselineInputs.standalone.bytes, contract.inputs.baseline.standaloneBytes);
  assert.equal(baselineInputs.standalone.sha256, contract.inputs.baseline.standaloneSha256, 'Exact frozen 1.2 standalone required');
  const [baseline, candidate] = await Promise.all([registeredPerformanceCatalog(baselineRoot), registeredPerformanceCatalog(candidateRoot)]);
  const baselineFixtures = resolvePerformanceFixtures(baseline), candidateFixtures = resolvePerformanceFixtures(candidate);
  assert.deepEqual(baselineFixtures, candidateFixtures, 'Selected canonical fixture metadata must remain unchanged');
  return freeze({contract, fixtures:candidateFixtures, baselineRoot, candidateRoot, scope:'Selected registered metadata only; no full corpus count or performance acceptance'});
}

export function performanceTarget({root, rootName, loadingMode, origin}) {
  assert.ok(LOAD_MODES.includes(loadingMode));
  if (loadingMode === 'standalone-file') return pathToFileURL(path.join(root, 'dist/auth-flow-studio.html')).href;
  assert.ok(['baseline', 'candidate'].includes(rootName));
  const base = new URL(origin);
  assert.equal(base.protocol, 'http:');
  assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname), 'Loopback source/emitted server only');
  return base.origin + '/' + rootName + '/' + (loadingMode === 'source-http' ? 'index.html' : 'dist/auth-flow-studio.html');
}

export function pairedSampleOrder(sampleIndex) {
  assert.ok(Number.isInteger(sampleIndex) && sampleIndex >= 0 && sampleIndex < 7);
  return sampleIndex % 2 === 0 ? ['baseline', 'candidate'] : ['candidate', 'baseline'];
}

// Freeze these plans into the collector's exact-input manifest before any timed
// navigation. A cell is a real selected fixture, never a historical count product.
export function performanceCells(contract = loadPerformanceContract()) {
  const cells = [];
  for (const fixture of PERFORMANCE_FIXTURES.filter(item => contract.matrix.primaryFixtureIds.includes(item.id))) for (const presentation of contract.matrix.presentations)
    for (const loadingMode of contract.matrix.loadModes) for (const locale of contract.matrix.locales) {
      const viewportId = contract.matrix.viewportByPresentation[presentation], indexState = 'closed';
      cells.push({id:[fixture.id, presentation, loadingMode, viewportId, indexState, locale].join('/'),
        fixtureId:fixture.id, caseId:fixture.caseId, presentation, loadingMode, viewportId, indexState, locale,
        direction:contract.matrix.rtlLocales.includes(locale) ? 'rtl' : 'ltr',
        fieldExpansion:false, comparison:locale === 'en' ? 'baseline-English' : 'native-overhead',
        baselineLocale:'en', candidateLocale:locale});
    }
  return freeze(cells);
}

const nativeScript = locale => locale === 'he' ? /\p{Script=Hebrew}/u : locale === 'ar-AE' ? /\p{Script=Arabic}/u
  : ['ru', 'uk'].includes(locale) ? /\p{Script=Cyrillic}/u : /[^\x00-\x7f]/u;

// Caller supplies selected-locale lightweight entries and the actual production
// matcher, not guessed translated text. Materialize and hash the returned query
// and exact ordered expected IDs before samples. No English fallback qualifies.
export function freezeNativeSearchFixture({locale, entries, match}) {
  assert.ok(['ru', 'uk', 'he', 'de', 'ar-AE', 'fr', 'pl'].includes(locale));
  assert.ok(Array.isArray(entries) && entries.length && typeof match === 'function');
  const script = nativeScript(locale);
  for (const entry of entries) {
    assert.equal(typeof entry.id, 'string');
    const text = [entry.title, entry.summary, entry.category, ...(entry.searchTags || []), ...(entry.searchVariants || [])].filter(value => typeof value === 'string').join(' ');
    for (const token of text.match(/[\p{L}\p{M}]{3,}/gu) || []) {
      if (!script.test(token)) continue;
      const results = match(token);
      assert.ok(Array.isArray(results), 'Production matcher returns ordered canonical entries');
      const expectedIds = results.map(item => typeof item === 'string' ? item : item.id);
      assert.ok(expectedIds.every(id => typeof id === 'string'));
      if (!expectedIds.includes(entry.id)) continue;
      return freeze({locale, query:token, sourceEntryId:entry.id, expectedIds,
        sha256:digest(JSON.stringify({locale, query:token, sourceEntryId:entry.id, expectedIds}))});
    }
  }
  throw new Error('No matching native Unicode prose available for predeclared locale: ' + locale);
}

export function freezeFieldSearchFixture({locale, query, expectedIds}) {
  assert.ok(typeof query === 'string' && query.length > 0);
  assert.ok(Array.isArray(expectedIds) && expectedIds.length > 0 && expectedIds.every(id => typeof id === 'string'));
  assert.equal(new Set(expectedIds).size, expectedIds.length);
  return freeze({locale, query, expectedIds:[...expectedIds], sha256:digest(JSON.stringify({locale, query, expectedIds}))});
}

export function classifyPerformanceSamples({baseline, candidate, kind = 'interaction'}) {
  assert.ok(['startup', 'interaction'].includes(kind));
  for (const samples of [baseline, candidate]) assert.ok(Array.isArray(samples) && samples.length === 7 && samples.every(value => Number.isFinite(value) && value >= 0), 'Exactly seven measured nonnegative latency samples');
  const stats = values => {
    const sorted = [...values].sort((a, b) => a - b), median = sorted[3], range = sorted[6] - sorted[0];
    return {medianMs:median, maximumMs:sorted[6], minimumMs:sorted[0], rangeMs:range,
      variation:range > median * 0.25 && range > (kind === 'startup' ? 100 : 50)};
  };
  const before = stats(baseline), after = stats(candidate), increase = after.medianMs - before.medianMs;
  return {baseline:before, candidate:after,
    materialRegression:increase > before.medianMs * 0.25 && increase > (kind === 'startup' ? 100 : 50),
    candidateOrdinaryTargetMiss:after.medianMs > 250 || after.maximumMs > 500,
    disposition:'open-if-flagged-not-owner-acceptance'};
}

// Pass directly to page.waitForFunction in an uninstrumented compare session;
// waiting is outside setup and inside the action-to-usable endpoint.
export function performanceReady({scenarioId = 'basic-keycloak', presentation, locale = 'en', minimumRevision = 0, baseline = false}) {
  const app = document.querySelector('auth-flow-studio');
  if (!app?.heldView || !app.player || !app.steps?.length || !app.scenarioPicker || app.labScenarioId !== scenarioId || (app.presentationMode || 'full') !== presentation) return false;
  const visible = selector => {
    const element = app.querySelector(selector);
    return !!element && !element.hidden && element.getClientRects().length > 0;
  };
  const contentSelector = presentation === 'compact' ? '#compact-current-title' : '#story';
  if (!visible('#lab-scenario-search') || !visible('#scenario-title') || !visible(contentSelector) || !visible(presentation === 'compact' ? '[data-compact-command="play"]' : '#play')) return false;
  if (!app.querySelector(contentSelector).textContent.trim() || app.heldView.snapshot().cursor == null) return false;
  if (baseline) return true;
  const direction = ['he', 'ar-AE'].includes(locale) ? 'rtl' : 'ltr';
  if (app.localizer?.locale !== locale || app.localizer.revision < minimumRevision || app.pendingLocale || app.getAttribute('lang') !== locale || app.getAttribute('dir') !== direction || app.querySelector('#language-select')?.value !== locale) return false;
  const studio = app.querySelector('#studio'), presentationHost = app.querySelector('#presentation-host');
  if (studio?.lang !== locale || studio?.dir !== direction || !presentationHost || app.presenter?.host !== presentationHost || !presentationHost.contains(app.querySelector(contentSelector))) return false;
  if (app.hasAttribute('data-document-owner') && (document.documentElement.lang !== locale || document.documentElement.dir !== direction)) return false;
  return true;
}
