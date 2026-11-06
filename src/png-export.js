import { capturePngSnapshot, encodePngSnapshot, PNG_RENDER_LIMITS } from './png-renderer.js';
import { Localizer } from './localization.js';
import { PNG_EXPORT_BINDINGS } from './localization-png.js';

const pngMessages = new Map(PNG_EXPORT_BINDINGS.map(binding => [binding.key, binding.english]));
const pngEscape = value => String(value).replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const pngPadding = 24, pngGap = 16;

export function pngStepSelection(app, queue = app.studyQueue()) {
  const row = queue.rows[queue.position];
  const sourceIndex = row?.sourceIndex ?? app.steps.findIndex(step => step.id === (row?.sourceStepId || row?.id));
  if (queue.empty || queue.initial || !row || sourceIndex < 0) return null;
  return {queue, row, sourceIndex};
}

export function pngExportFilename(scenarioId, sourceIndex) {
  const safe = String(scenarioId || 'scenario').replace(/[^a-z0-9_-]+/gi, '-').replace(/^-+|-+$/g, '').slice(0, 64) || 'scenario';
  return 'auth-flow-studio-' + safe + '-step-' + (sourceIndex + 1) + '.png';
}

function pngVisible(element) {
  if (!element?.isConnected || !element.getClientRects().length) return false;
  for (let node = element; node; node = node.parentElement) {
    const style = node.ownerDocument.defaultView.getComputedStyle(node);
    if (node.hidden || style.display === 'none' || style.visibility === 'hidden' || style.visibility === 'collapse') return false;
    const parent = node.parentElement;
    if (parent?.localName === 'details' && !parent.open && node.localName !== 'summary') return false;
  }
  return true;
}

function pngLayer(element, exclude = '') {
  if (!pngVisible(element)) return null;
  const rect = element.getBoundingClientRect();
  return {element, width: Math.ceil(Math.max(rect.width, element.scrollWidth || 0)), height: Math.ceil(Math.max(rect.height, element.scrollHeight || 0)), expand: true, exclude};
}

function pngGraphBounds(graph) {
  const rect = graph.getBoundingClientRect();
  let left = 0, top = 0, right = Math.max(rect.width, graph.scrollWidth), bottom = Math.max(rect.height, graph.scrollHeight);
  const descendants = graph.querySelectorAll('*');
  if (descendants.length > PNG_RENDER_LIMITS.maxNodes) throw Object.assign(new Error('The graph is too complex to export.'), {code: 'size'});
  for (const node of descendants) {
    if (!pngVisible(node) || node.closest('defs')) continue;
    const bounds = node.getBoundingClientRect();
    left = Math.min(left, bounds.left - rect.left); top = Math.min(top, bounds.top - rect.top);
    right = Math.max(right, bounds.right - rect.left); bottom = Math.max(bottom, bounds.bottom - rect.top);
  }
  left = Math.floor(left); top = Math.floor(top);
  return {left, top, width: Math.ceil(right) - left, height: Math.ceil(bottom) - top, rootWidth: rect.width, rootHeight: rect.height};
}

/** The only temporary live node is an offscreen caption. No player, layout,
 * selection, scroll, focus, draft or disclosure writes occur during capture.
 */
export function captureStudyPng(app, selection) {
  const compact = app.presentationMode === 'compact', layers = [];
  const card = compact ? pngLayer(app.querySelector('.compact-current'), '[data-compact-action],.compact-copy') : null;
  const graph = compact ? null : app.querySelector('#graph');
  if (compact ? !card : !pngVisible(graph)) throw Object.assign(new Error('The current study surface is unavailable.'), {code: 'content'});
  const bounds = graph ? pngGraphBounds(graph) : null;
  const info = compact
    ? ['.compact-outcome','[data-compact-disclosure="data"][open]','#protocol-state-panel[open]','#held-inspector','#compact-field-definition'].map(selector => pngLayer(app.querySelector(selector), '.compact-copy,[data-compact-action],input,textarea,select')).filter(Boolean)
    : ['#step-attributes-external','#held-active-message','#lesson-decisions','#windows-remote-evidence','#pam-configuration-panel','#lifetime-strip','#held-inspector'].map(selector => pngLayer(app.querySelector(selector), '.replay-button,.held-related,.held-summary-control,input,textarea,select')).filter(Boolean);
  const inspector = compact ? null : pngLayer(app.querySelector('#inspector'), '.replay-button,.inspector-title,.inspector-summary,input,textarea,select');
  const leftWidth = Math.max(compact ? card.width : bounds.width, ...info.map(layer => layer.width));
  const width = Math.ceil(pngPadding * 2 + leftWidth + (inspector ? pngGap + inspector.width : 0));
  const caption = app.ownerDocument.createElement('header');
  caption.className = 'png-export-caption';
  caption.style.width = (width - pngPadding * 2) + 'px';
  const addCaption = (tag, source) => {
    if (!source || !pngVisible(source) || !source.textContent.trim()) return;
    const node = app.ownerDocument.createElement(tag);
    for (const child of source.childNodes) node.appendChild(child.cloneNode(true));
    for (const copy of node.querySelectorAll('[id]')) copy.removeAttribute('id');
    caption.appendChild(node);
  };
  addCaption('h1', app.querySelector('#scenario-title'));
  addCaption('p', app.querySelector('#current-lesson-case'));
  if (!compact) {
    addCaption('h2', app.querySelector('.timeline-step.is-current .step-title'));
    addCaption('p', app.querySelector('#story p'));
  }
  app.refs.studio.appendChild(caption);
  try {
    const captionHeight = Math.ceil(caption.getBoundingClientRect().height);
    layers.push({element: caption, x: pngPadding, y: pngPadding, width: width - pngPadding * 2, height: captionHeight});
    const bodyY = pngPadding + captionHeight + pngGap;
    let bottom = bodyY;
    if (compact) {
      layers.push({...card, x: pngPadding, y: bodyY}); bottom += card.height;
    } else {
      layers.push({element: graph, x: pngPadding - bounds.left, y: bodyY - bounds.top, width: bounds.rootWidth, height: bounds.rootHeight});
      bottom += bounds.height;
      if (inspector) layers.push({...inspector, x: pngPadding + leftWidth + pngGap, y: bodyY});
    }
    for (const layer of info) {
      layers.push({...layer, x: pngPadding, y: bottom + pngGap}); bottom += pngGap + layer.height;
    }
    bottom = Math.max(bottom, inspector ? bodyY + inspector.height : 0);
    const background = app.ownerDocument.defaultView.getComputedStyle(app.refs.studio).getPropertyValue('--panel').trim();
    return capturePngSnapshot({width, height: Math.ceil(bottom + pngPadding), background, layers});
  } finally {
    caption.remove();
  }
}

/** One job per controller, including across presentation and locale remounts. */
export class PngExporter {
  constructor(app, {capture = captureStudyPng, encode = encodePngSnapshot, download} = {}) {
    this.app = app; this.capture = capture; this.encode = encode;
    this.download = download || ((blob, filename) => this.requestDownload(blob, filename));
    this.job = null; this.notice = null; this.downloadURL = null; this.revokeTimer = null; this.disposed = false;
  }
  text(name) {
    const key = 'ui.png-export.' + name;
    return this.app.localizer.text(key, pngMessages.get(key));
  }
  controlsHtml() {
    return '<div class="png-export-control"><button type="button" class="button quiet" id="save-step-png" data-png-export aria-disabled="true" aria-describedby="png-export-status">' + pngEscape(this.text('save')) + '</button><span id="png-export-status" class="png-export-status" role="status" aria-live="polite" aria-atomic="true"></span></div>';
  }
  unavailable(selection = pngStepSelection(this.app)) {
    if (!selection) return 'no-step';
    return ['paused','complete'].includes(selection.queue.playerSnapshot.status) ? null : 'pause';
  }
  update() {
    if (this.disposed) return;
    const button = this.app.querySelector('#save-step-png'), status = this.app.querySelector('#png-export-status');
    if (!button || !status) return;
    const unavailable = this.unavailable(), key = this.job ? 'busy' : unavailable || this.notice;
    button.setAttribute('aria-disabled', String(!!this.job || !!unavailable));
    button.setAttribute('aria-busy', String(!!this.job));
    const text = key ? this.text(key) : '';
    if (status.textContent !== text) status.textContent = text;
    const language = key ? this.app.localizer.language('ui.png-export.' + key) : this.app.localizer.locale;
    status.setAttribute('lang', language); status.setAttribute('dir', Localizer.metadata(language).direction);
  }
  stamp(selection) {
    const app = this.app, playback = selection.queue.playerSnapshot;
    return [app.labScenarioId, app.lessonVariant, app.lessonSubfixture, app.runtimeEnvironment.revision, app.presentationMode, app.theme,
      app.localizer.revision, app.pendingLocale, app.localePreparation, app.heldView.contextId, app.heldView.actorId, app.heldView.selection?.holdingId,
      app.attributeSelection, app.objectTraceSelection, app.player.queue, selection.row, selection.queue.position, selection.sourceIndex,
      playback.kind, playback.status, playback.stepElapsed, JSON.stringify(selection.queue.cursor)];
  }
  unchanged(stamp) {
    if (this.disposed) return false;
    const selection = pngStepSelection(this.app);
    if (this.unavailable(selection)) return false;
    return this.stamp(selection).every((value, index) => value === stamp[index]);
  }
  async save() {
    if (this.disposed || this.job) return false;
    const selection = pngStepSelection(this.app), unavailable = this.unavailable(selection);
    if (unavailable) { this.notice = unavailable; this.update(); return false; }
    const job = {stamp: this.stamp(selection), filename: pngExportFilename(this.app.baseLabModel?.id || this.app.labScenarioId, selection.sourceIndex)};
    this.job = job; this.update();
    try {
      const snapshot = this.capture(this.app, selection);
      const blob = await this.encode(snapshot);
      if (!this.unchanged(job.stamp)) { this.notice = 'canceled'; return false; }
      this.download(blob, job.filename); this.notice = 'requested'; return true;
    } catch (error) {
      this.notice = this.unchanged(job.stamp) ? error.code === 'size' ? 'too-large' : 'failed' : 'canceled';
      return false;
    } finally {
      if (this.job === job) this.job = null;
      this.update();
    }
  }
  releaseDownload() {
    clearTimeout(this.revokeTimer); this.revokeTimer = null;
    if (this.downloadURL) URL.revokeObjectURL(this.downloadURL);
    this.downloadURL = null;
  }
  requestDownload(blob, filename) {
    this.releaseDownload();
    const anchor = this.app.ownerDocument.createElement('a');
    this.downloadURL = URL.createObjectURL(blob); anchor.href = this.downloadURL; anchor.download = filename; anchor.hidden = true;
    this.app.ownerDocument.body.appendChild(anchor);
    try {
      anchor.click();
      this.revokeTimer = setTimeout(() => this.releaseDownload(), 1000);
    } catch (error) {
      this.releaseDownload(); throw error;
    } finally {
      anchor.remove();
    }
  }
  dispose() { this.disposed = true; this.releaseDownload(); }
}
