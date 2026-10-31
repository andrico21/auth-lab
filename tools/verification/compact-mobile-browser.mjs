// Shared offline Chromium helpers. Importing this module never launches a browser.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {fileURLToPath, pathToFileURL} from 'node:url';

export const DEFAULT_CHECKOUT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const PRESENTATION_KEY = 'auth-flow-studio.presentation.v1';
export const DEFAULT_BROWSER = '/home/andrico/.cache/auth-lab-held-qa/browser/chrome/linux-155.0.8059.84/chrome-linux64/chrome';
export const DEFAULT_PLAYWRIGHT = path.join(DEFAULT_CHECKOUT, 'tools/verification/native-qa/node_modules/playwright-core/index.mjs');
export const DEFAULT_LIBRARIES = '/home/andrico/.cache/auth-lab-held-qa/libs/runtime/usr/lib/x86_64-linux-gnu:/home/andrico/.cache/auth-lab-held-qa/next-desktop-tools-hsQCXd/runtime/usr/lib/x86_64-linux-gnu';
export const LOAD_MODES = ['source-http', 'emitted-http', 'standalone-file'];
const within = (root, file) => file === root || file.startsWith(root + path.sep);
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export function fileIdentity(file) {
  assert.ok(fs.lstatSync(file).isFile(), 'Expected regular input: ' + file);
  const bytes = fs.readFileSync(file);
  return {bytes: bytes.length, sha256: sha256(bytes)};
}
export function captureInputs(inputRoot) {
  const root = fs.realpathSync(inputRoot), names = ['index.html', 'build.mjs', 'package.json', 'security-policy.mjs'];
  function walk(relative) {
    assert.ok(fs.lstatSync(path.join(root, relative)).isDirectory(), 'Expected real input directory: ' + relative);
    for (const entry of fs.readdirSync(path.join(root, relative), {withFileTypes: true}).sort((a,b) => a.name.localeCompare(b.name))) {
      const name = relative + '/' + entry.name;
      assert.ok(!entry.isSymbolicLink(), 'Input symlink: ' + name);
      if (entry.isDirectory()) walk(name);
      else { assert.ok(entry.isFile(), 'Non-file input: ' + name); names.push(name); }
    }
  }
  for (const directory of ['src', 'assets', 'tests']) walk(directory);
  const sources = Object.fromEntries(names.sort().map(name => [name, fileIdentity(path.join(root, name))]));
  const canonical = createHash('sha256');
  for (const [name] of Object.entries(sources)) canonical.update(name).update('\0').update(fs.readFileSync(path.join(root, name))).update('\0');
  assert.ok(fs.lstatSync(path.join(root, 'dist')).isDirectory(), 'No symlink dist');
  return {root, sourceAlgorithm: 'sha256-path-nul-bytes-nul-v1', sourceFileCount: names.length,
    canonicalSha256: canonical.digest('hex'), sources, standalone: fileIdentity(path.join(root, 'dist/auth-flow-studio.html'))};
}
export function runtimeIdentity() {
  return {executable: process.execPath, ...fileIdentity(process.execPath), versions: process.versions,
    platform: process.platform, arch: process.arch, os: {type: os.type(), release: os.release(), version: os.version()},
    cpuModel: os.cpus()[0]?.model, logicalCpus: os.cpus().length};
}
function packageIdentity(entry) {
  let directory = path.dirname(entry);
  while (!fs.existsSync(path.join(directory, 'package.json'))) {
    const parent = path.dirname(directory); assert.notEqual(parent, directory, 'No package metadata for browser module'); directory = parent;
  }
  const packageFile = path.join(directory, 'package.json'), pkg = JSON.parse(fs.readFileSync(packageFile, 'utf8'));
  return {entry, ...fileIdentity(entry), packageFile, package: fileIdentity(packageFile), name: pkg.name, version: pkg.version};
}
export async function launchBrowser({modulePath = process.env.PLAYWRIGHT_MODULE || DEFAULT_PLAYWRIGHT,
  executablePath = process.env.CHROMIUM_EXECUTABLE || DEFAULT_BROWSER,
  libraryPath = process.env.LD_LIBRARY_PATH || DEFAULT_LIBRARIES, headless = true} = {}) {
  const moduleFile = fs.realpathSync(modulePath), executable = fs.realpathSync(executablePath);
  const identity = {executable: {path: executable, ...fileIdentity(executable)}, module: packageIdentity(moduleFile),
    libraryPath, headless, runtime: runtimeIdentity()};
  const {chromium} = await import(pathToFileURL(moduleFile).href);
  assert.ok(chromium, 'Provisioned module must expose chromium');
  const browser = await chromium.launch({executablePath: executable, headless, env: {...process.env, LD_LIBRARY_PATH: libraryPath}});
  identity.version = browser.version();
  return {browser, identity, close: () => browser.close()};
}
const isRuntime = name => name === 'index.html' || name.startsWith('src/') || name.startsWith('assets/');
export async function createStaticServer({roots, identities}) {
  const errors = [];
  const server = http.createServer((request, response) => {
    try {
      if (!['GET', 'HEAD'].includes(request.method)) { response.writeHead(405); response.end(); return; }
      const parsed = new URL(request.url, 'http://127.0.0.1'), parts = decodeURIComponent(parsed.pathname).split('/');
      const name = parts[1], root = roots[name], relative = parts.slice(2).join('/') || 'index.html';
      const expected = relative === 'dist/auth-flow-studio.html' ? identities[name]?.standalone : isRuntime(relative) && identities[name]?.sources[relative];
      if (!root || !expected || parsed.search || relative.split('/').some(p => p === '..' || p === '.')) { response.writeHead(404); response.end(); return; }
      const file = path.join(root, relative);
      assert.ok(within(root, file) && fs.realpathSync(file) === file, 'No-follow runtime path');
      const bytes = fs.readFileSync(file);
      assert.equal(sha256(bytes), expected.sha256, 'Served bytes changed: ' + file);
      response.writeHead(200, {'Content-Type': {'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'}[path.extname(file)] || 'application/octet-stream', 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff'});
      response.end(request.method === 'HEAD' ? undefined : bytes);
    } catch (error) { errors.push(String(error.stack || error)); response.writeHead(500); response.end(); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return {origin: 'http://127.0.0.1:' + server.address().port, errors,
    close: () => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()))};
}
export async function createBrowserSession({browser, server, rootName, root, identity, loadingMode, viewport,
  dpr = 1, touch = false, reducedMotion = 'no-preference', preference = null, diagnostic = false}) {
  assert.ok(LOAD_MODES.includes(loadingMode), 'Unknown load mode');
  assert.ok([null, 'full', 'compact'].includes(preference), 'Explicit valid preference or null');
  const target = loadingMode === 'standalone-file' ? pathToFileURL(path.join(root, 'dist/auth-flow-studio.html')).href
    : server.origin + '/' + rootName + '/' + (loadingMode === 'source-http' ? 'index.html' : 'dist/auth-flow-studio.html');
  const evidence = {console: [], pageerrors: [], csp: [], blockedRequests: [], requestFailures: [], httpErrors: [], trustedEvents: [], truncated: false};
  const retain = (key, value) => { if (evidence[key].length < 200) evidence[key].push(value); else evidence.truncated = true; };
  const context = await browser.newContext({viewport, ...(viewport===null?{}:{deviceScaleFactor:dpr,isMobile:touch}), hasTouch:touch,
    reducedMotion, serviceWorkers: 'block', bypassCSP: false});
  try {
    await context.route('**/*', route => {
      const url = route.request().url(); let allowed = url === target;
      if (loadingMode === 'source-http') {
        const parsed = new URL(url), prefix = '/' + rootName + '/';
        const name = decodeURIComponent(parsed.pathname).slice(prefix.length);
        allowed = parsed.origin === server.origin && parsed.pathname.startsWith(prefix) && !parsed.search && isRuntime(name) && Object.hasOwn(identity.sources, name);
      }
      if (allowed && ['GET', 'HEAD'].includes(route.request().method())) return route.continue();
      retain('blockedRequests', url); return route.abort('blockedbyclient');
    });
    // Preference is the only compare-mode init script. It does not observe or wrap application execution.
    if (preference !== null) await context.addInitScript(({key, value, documentURL}) => {
      if (location.href === documentURL) localStorage.setItem(key, value);
    }, {key: PRESENTATION_KEY, value: preference, documentURL: target});
    const page = await context.newPage(); page.setDefaultTimeout(60000); page.setDefaultNavigationTimeout(60000);
    page.on('console', message => {
      const record = {type: message.type(), text: message.text().slice(0, 4000)}; retain('console', record);
      if (/content security policy|violates.*directive/i.test(record.text)) retain('csp', record);
    });
    page.on('pageerror', error => retain('pageerrors', String(error.stack || error).slice(0, 8000)));
    page.on('requestfailed', request => retain('requestFailures', {url: request.url(), failure: request.failure()}));
    page.on('response', response => { if (response.status() >= 400) retain('httpErrors', {url: response.url(), status: response.status()}); });
    if (diagnostic) {
      await page.addInitScript(readStudyState, {install:true});
      await page.exposeBinding('__compactEvidence', (_, event) => retain(event.kind === 'csp' ? 'csp' : 'trustedEvents', event));
      await page.addInitScript(() => {
        addEventListener('securitypolicyviolation', event => window.__compactEvidence({kind:'csp', directive:event.effectiveDirective, blocked:event.blockedURI}));
        for (const type of ['pointerdown', 'keydown', 'input', 'change']) addEventListener(type, event => window.__compactEvidence({kind:'input', type, trusted:event.isTrusted, pointerType:event.pointerType, key:event.key, target:event.target?.id || event.target?.getAttribute?.('data-compact-action')}), true);
      });
    }
    return {context, page, target, evidence, close: () => context.close()};
  } catch (error) { await context.close(); throw error; }
}
export const settle = page => page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
export async function activate(page, selector, {touch = false} = {}) {
  const control = page.locator(selector); assert.equal(await control.count(), 1, 'Exactly one actual action control: ' + selector);
  if (touch) await control.tap(); else await control.click();
}
export function assertClean(evidence) {
  for (const key of ['pageerrors', 'csp', 'blockedRequests', 'requestFailures', 'httpErrors']) assert.deepEqual(evidence[key], [], 'Clean browser ' + key);
  assert.ok(!evidence.console.some(item => item.type === 'error'), 'No console errors'); assert.ok(!evidence.truncated, 'Evidence cap exceeded');
}
// Self-contained so diagnostic contexts can install this exact snapshotter before application boot.
export function readStudyState({install = false} = {}) {
    if (install) { window.__compactReadStudyState = readStudyState; return; }
    const app = document.querySelector('auth-flow-studio'), p = app.player, held = app.heldView;
    const identities = window.__compactStudyIdentities ||= {objects:new WeakMap(),next:1};
    const identity = value => {
      if (!value || typeof value !== 'object') return null;
      if (!identities.objects.has(value)) identities.objects.set(value,identities.next++);
      return identities.objects.get(value);
    };
    const safe = (value, ancestors = new Set()) => {
      if (value === undefined) return {$undefined:true};
      if (typeof value === 'bigint') return {$bigint:String(value)};
      if (typeof value === 'number' && !Number.isFinite(value)) return {$number:String(value)};
      if (value === null || typeof value !== 'object') return value;
      if (ancestors.has(value)) throw new Error('Cyclic study state cannot be silently normalized');
      const next = new Set(ancestors); next.add(value);
      if (value instanceof Map) return {$map:[...value].map(([k,v]) => [safe(k,next),safe(v,next)])};
      if (value instanceof Set) return {$set:[...value].map(v => safe(v,next))};
      if (value instanceof Date) return {$date:value.toISOString()};
      if (value instanceof ArrayBuffer) return {$arrayBuffer:[...new Uint8Array(value)]};
      if (value instanceof DataView) return {$typed:'DataView',bytes:[...new Uint8Array(value.buffer,value.byteOffset,value.byteLength)]};
      if (ArrayBuffer.isView(value)) return {$typed:value.constructor.name,values:Array.from(value,v=>safe(v,next))};
      return Array.isArray(value) ? value.map(v => safe(v,next)) : Object.fromEntries(Object.keys(value).sort().map(k => [k,safe(value[k],next)]));
    };
    const index = app.querySelector('#attribute-index'), snapshot = held.snapshot();
    const active = document.activeElement, r = active?.getBoundingClientRect();
    let preference=null,preferenceStorage={status:'available'};
    try { preference=localStorage.getItem('auth-flow-studio.presentation.v1'); }
    catch(error) { preferenceStorage={status:'blocked',errorName:error?.name||typeof error}; }
    return safe({presentation:app.presentationMode || 'full', preference, preferenceStorage,
      preferenceSource:app.presentationSource, scenario:app.labScenarioId, variant:app.lessonVariant, subfixture:app.lessonSubfixture,
      session:{workspace:app.workspace, family:app.family, configuration:app.protocolConfig(), runtime:{draft:app.runtimeEnvironment.draft,applied:app.runtimeEnvironment.applied,revision:app.runtimeEnvironment.revision},
        scenarioSnapshot:app.scenarioSnapshot(), scenarioSnapshotIdentity:identity(app.scenarioSnapshot()), learningProfile:app.learningProfile, learningDetail:app.learningDetail,
        showInternals:app.showInternals, theme:app.theme, customLayouts:app.customLayouts, lastRunningSpeed:app.lastRunningSpeed},
      player:{identity:identity(p), queue:p.queue, queueIdentity:identity(p.queue), position:p.position, elapsed:p.elapsed, kind:p.kind, status:p.status, speed:p.speed},
      scheduling:{frame:p.handle!=null,timer:p.timer!=null},
      studyQueue:app.studyQueue?.(), held:{identity:identity(held), context:held.contextId, compiledIdentity:identity(held.compiled()), cursor:snapshot.cursor, initial:held.initial, selected:held.selected,
        selection:held.selection, actorId:held.actorId, expanded:held.expanded},
      trace:{queue:app.traceQueue, queueIdentity:identity(app.traceQueue), attribute:app.attributeSelection, object:app.objectTraceSelection, hasTrace:app.hasTrace},
      selection:{sourceIndex:app.index, visibleIndex:app.visibleIndex, currentStep:app.currentStep?.id},
      indexVisible:!!index && !index.hidden && !!index.getClientRects().length,
      viewport:{width:innerWidth,height:innerHeight,dpr:devicePixelRatio,visualWidth:visualViewport?.width,visualHeight:visualViewport?.height,visualScale:visualViewport?.scale,
        touchPoints:navigator.maxTouchPoints,coarse:matchMedia('(pointer: coarse)').matches,reducedMotion:matchMedia('(prefers-reduced-motion: reduce)').matches},
      focus:{id:active?.id, tag:active?.tagName, compactAction:active?.getAttribute('data-compact-command'), holdingId:active?.dataset?.holdingId, heldKey:active?.dataset?.heldKey, stepIndex:active?.dataset?.compactStepIndex, connected:active?.isConnected,
        bounds:r ? {x:r.x,y:r.y,width:r.width,height:r.height}:null},
      scroll:{x:scrollX,y:scrollY,containers:[...app.querySelectorAll('[data-presentation-scroll], #studio, .compact-study, .map-scroll')].map(n=>({id:n.id,class:n.className,x:n.scrollLeft,y:n.scrollTop}))},
      liveNodes:document.querySelectorAll('*').length});
}
export const studyState = page => page.evaluate(readStudyState);

export function continuityProjection(state) {
  return {scenario:state.scenario,variant:state.variant,subfixture:state.subfixture,session:state.session,
    player:state.player,held:state.held,trace:state.trace,selection:state.selection};
}
// Diagnostic-only: synchronous player state subscriber observes the exact pause before unmount.
export async function armSwitchWitness(page) {
  await page.evaluate(() => {
    if (!window.__compactReadStudyState) throw new Error('Switch witnesses require a diagnostic context');
    if (window.__compactSwitchWitness) throw new Error('A switch witness is already armed');
    const app = document.querySelector('auth-flow-studio');
    const witness = {before:window.__compactReadStudyState(),paused:null,events:0};
    witness.unsubscribe = app.player.subscribe(event => {
      if (event.type === 'state' && event.status === 'paused') {
        witness.events++;
        if (!witness.paused) witness.paused = window.__compactReadStudyState();
      }
    });
    window.__compactSwitchWitness = witness;
  });
}
export async function finishSwitchWitness(page) {
  const result = await page.evaluate(() => {
    const witness = window.__compactSwitchWitness;
    if (!witness) throw new Error('No armed switch witness');
    witness.unsubscribe(); delete window.__compactSwitchWitness;
    return {before:witness.before,paused:witness.paused,events:witness.events,after:window.__compactReadStudyState()};
  });
  assert.equal(result.events,1,'Exactly one actual postpause player state event');
  assert.ok(result.paused,'Exact postpause snapshot captured');
  assert.deepEqual(continuityProjection(result.after),continuityProjection(result.paused),'Exact diagnostic postpause switch continuity');
  result.status = 'proved-in-separate-instrumented-session';
  return result;
}
