import { channelCategory } from './layout.js';

const compactEscape = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const compactValue = value => typeof value === 'string' ? value : JSON.stringify(value, null, 2) ?? '';

/** Read the existing session only. Queue positions are never source-event indices. */
export function compactReadProjection(app, event = app.player.snapshot(), snapshot = app.heldView.snapshot(event)) {
  const queue = app.studyQueue(), held = snapshot, rows = queue.rows;
  const position = queue.position, row = rows[Math.max(0, position)] || null;
  const sourceIndex = row ? (row.sourceIndex ?? app.steps.findIndex(step => step.id === (row.sourceStepId || row.id))) : -1;
  const authored = sourceIndex >= 0 ? app.steps[sourceIndex] : row;
  const initial = !!queue.initial;
  const rowComplete = !initial && !!row && !!queue.rowComplete[position];
  const sourceComplete = !!queue.sourceComplete;
  const finalRow = rowComplete && position === rows.length - 1;
  const from = row ? app.studyActor(row.from) : null, to = row ? app.studyActor(row.to) : null;
  const category = channelCategory(row?.channel), channel = row?.channel || '';
  const operation = !row ? 'No action in this scope' : row.from === row.to ? 'Local processing' : category === 'ipc' ? 'Local IPC' : /internal/i.test(channel) ? 'Internal exchange between logical components' : category === 'local' ? 'Local exchange between logical participants' : category === 'human' ? 'Human interaction' : category === 'passkey' ? 'Authenticator interaction' : category === 'unknown' ? 'Exchange - transport not classified' : 'Network transfer';
  const profile = app.labModel?.profile;
  const summary = row ? (profile && app.learningDetail === 'journey' ? row.beginnerSummary || row.summary : row.summary) : '';
  const actionObservations = held.observations.filter(item => item.cursor?.eventIndex === held.cursor.eventIndex);
  const sourcePosition = held.cursor.eventIndex < 0 ? 'Before step 1' : 'Source event ' + (held.cursor.eventIndex + 1) + ' / ' + app.steps.length + ' - ' + held.cursor.milestone;
  const progress = queue.empty ? 'No steps in this scope' : initial ? 'Before the first row - ' + rows.length + ' rows' : 'Row ' + (position + 1) + ' of ' + rows.length;
  const playback = queue.playback || event.status || app.player.status;
  const playLabel = playback === 'playing' ? 'Pause' : finalRow ? 'Replay' : initial ? 'Play' : 'Resume';
  return {queue, held, rows, row, step:row, action:row, authored, position, sourceIndex, sourcePosition, initial, rowComplete, sourceComplete, from, to, operation, summary, actionObservations, progress, playback, playLabel,
    cursor:held.cursor, protocolClock:held.protocolClock, state:held.state, currentHoldings:held.holdings, coverage:held.coverage, observations:held.observations, authority:held.authority,
    previousDisabled: queue.empty || initial || position < 0,
    nextDisabled: queue.empty || finalRow,
    previousIndex: position - 1,
    nextIndex: initial ? 0 : rowComplete ? position + 1 : Math.max(0, position)};
}

/** The reader owns its body and listeners, never the shared shell or player. */
export class CompactView {
  constructor(app) {
    this.app = app;
    this.state = {disclosures: new Map(), focus: null};
    this.fieldBatchSize = 40;
    this.fieldBrowser = {scope:'current',limit:this.fieldBatchSize,query:'',context:null};
    this.listeners = [];
    this.copyValues = new Map();
    this.copySerial = 0;
  }
  mount(host) {
    this.host = host;
    host.innerHTML = `<article class="compact-study" aria-label="Compact lesson reader">
      <section class="compact-context" aria-labelledby="scenario-title">
        <p class="compact-kicker" id="compact-family"></p><h1 id="scenario-title"></h1>
        <p id="scenario-description"></p><p id="current-lesson-case" hidden></p>
        <h2 class="compact-purpose" id="learning-question"></h2><p id="learning-start"></p><div id="learning-boundary"></div>
        <p id="compact-profile"></p><p id="compact-environment-status"></p>
        <div class="compact-actions"><button class="button quiet" data-compact-action="case">Change case</button><button class="button quiet" data-compact-action="find">Find lesson</button><button class="button quiet" id="copy-lesson-link" data-compact-action="copy-link">Copy lesson link</button></div>
        <label id="lesson-link-manual" hidden>Copy the named lesson/case link (comparison controls use defaults)<input id="lesson-link-value" type="text" readonly aria-label="Named lesson and case link"></label>
        <section id="lesson-inputs" class="lesson-inputs" aria-label="Selected lesson profile and case" hidden></section>
      </section>
      <section class="compact-current" aria-labelledby="compact-current-title">
        <p class="compact-kicker" id="compact-position"></p><p id="compact-scope"></p>
        <button class="button quiet" data-compact-action="return" hidden>Return to journey</button>
        <button class="button quiet" data-compact-action="field-definition" hidden>Back to selected field definition</button>
        <h2 id="compact-current-title" tabindex="-1" aria-describedby="compact-scope compact-position"></h2>
        <p class="compact-operation" id="compact-operation"></p><p id="compact-actors"></p>
        <h3>Described action</h3><p id="compact-action-summary"></p><p id="compact-action-detail"></p>
        <section class="compact-observed" aria-labelledby="compact-result-title"><h3 id="compact-result-title">Observed at this prefix</h3><p id="compact-result"></p><div id="compact-observations"></div></section>
      </section>
      <section class="compact-playback" aria-label="Study playback controls"><p id="compact-playback-status"></p><div class="compact-playback-buttons"><button class="button quiet" data-compact-action="previous">Previous</button><button class="button primary" id="play" data-compact-action="play">Play</button><button class="button quiet" data-compact-action="next">Next</button></div><label class="compact-speed" for="compact-speed">Playback speed <select id="compact-speed"><option value="0">0 - paused speed</option><option value="0.5">0.5x</option><option value="1">1x</option><option value="1.5">1.5x</option><option value="2">2x</option><option value="3">3x</option></select></label><p class="compact-clock-note">Playback time is presentation time, not protocol time.</p></section>
      <section class="compact-outcome" aria-label="Current decisions, failures and qualifications">
        <p id="compact-qualification"></p><section id="lesson-decisions" class="lesson-decisions" aria-label="Current authored decisions" hidden></section>
        <section id="windows-remote-evidence" class="windows-remote-evidence" aria-label="Target policy and before-after authorization context" hidden></section>
        <section id="pam-configuration-panel" class="pam-configuration-panel" aria-label="PAM configuration and current evaluation" hidden></section>
        <section id="lifetime-strip" class="lifetime-strip" aria-label="Independent protocol and credential lifetimes" hidden></section>
      </section>
      <details class="compact-disclosure" data-compact-disclosure="data"><summary>Data and checks for this action</summary><div id="compact-data"></div></details>
      <details class="compact-disclosure protocol-state-panel" id="protocol-state-panel" data-compact-disclosure="state" hidden>
        <summary><strong>Current state and exact field-instance history</strong><span id="protocol-state-summary"></span></summary>
        <p>Current state follows the canonical source prefix. The cumulative field-instance ledger is history, not current possession. Playback speed does not change protocol time. Private keys and opaque ciphertext are not decrypted by this lab.</p><h3>Field-instance history</h3><div id="protocol-instance-list"></div><h3>Current protocol state</h3><pre id="protocol-state-value"></pre>
      </details>
      <details class="compact-disclosure" data-compact-disclosure="holdings"><summary>Participants, current holdings and exact object history</summary>
        <section id="held-objects" class="compact-holdings" aria-label="Current logical-owner inventory"></section>
        <section id="held-inspector" class="held-inspector" aria-label="Permission-scoped exact object inspector" hidden></section>
      </details>
      <details class="compact-disclosure" data-compact-disclosure="fields"><summary>Field definitions and paths</summary>
        <section id="compact-field-definition" role="region" tabindex="-1" aria-label="Selected field definition" hidden></section>
        <section id="attribute-index" class="compact-field-index" aria-label="Field index" hidden><label for="attribute-search">Search field names and purpose across all lessons</label><input id="attribute-search" type="search" autocomplete="off"><div class="compact-actions" role="group" aria-label="Field browsing scope"><button class="button quiet" id="compact-field-scope-current" data-compact-field-scope="current" aria-pressed="true">Current lesson fields</button><button class="button quiet" id="compact-field-scope-global" data-compact-field-scope="global" aria-pressed="false">All global fields</button></div><div id="attribute-topics"></div><p id="attribute-index-meta" role="status" aria-live="polite"></p><div id="attribute-index-list"></div><button class="button quiet" id="compact-field-more" data-compact-field-more hidden>Show more fields</button><p id="attribute-index-empty" hidden>No matching fields.</p></section>
      </details>
      <details class="compact-disclosure" data-compact-disclosure="configuration"><summary>Current configuration and assumptions</summary><div id="compact-configuration"></div><button class="button quiet" data-compact-action="configuration">Edit configuration in Full</button></details>
      <details class="compact-disclosure lesson-reference" id="lesson-reference" data-compact-disclosure="sources" hidden><summary>Profile, protocol detail and primary sources</summary>
        <div id="lab-support" class="lab-support" hidden></div><section id="learning-profile" class="learning-profile" aria-label="Selected teaching profile and completion boundary" hidden><div id="learning-profile-content"></div>
          <div class="learning-detail-controls" role="group" aria-label="Lesson detail"><button class="button quiet" id="learning-detail-journey" data-learning-detail="journey">Journey</button><button class="button quiet" id="learning-detail-fields" data-learning-detail="fields">Fields</button><button class="button quiet" id="learning-detail-crypto" data-learning-detail="crypto">Cryptographic detail</button></div><div id="learning-profile-crypto" hidden></div><div id="related-journeys" class="related-journeys" aria-label="Compare related journeys" hidden></div>
        </section><details id="windows-security-comparison" class="windows-security-comparison" hidden><summary>Compare Windows security boundaries</summary><p>Each link opens its own configured lesson. No credential, token or session is transferred.</p><div id="windows-security-comparison-rows"></div></details>
      </details>
      <details class="compact-disclosure" data-compact-disclosure="overview"><summary>Steps in this scope and Full diagram</summary><p id="compact-queue-label"></p><div id="lesson-chapters" class="lesson-chapters" hidden></div><ol id="compact-queue" class="compact-queue"></ol><button class="button quiet" data-compact-action="diagram">Open Full diagram</button></details>
    </article>`;
    this.root = host.querySelector('.compact-study');
    const notification = this.app.refs.toast;
    this.notification = {node:notification,parent:notification.parentElement,nextSibling:notification.nextSibling};
    this.root.querySelector('.compact-playback').appendChild(notification);
    this.nodes = new Map([...this.root.querySelectorAll('[id]')].map(node => [node.id, node]));
    const commands = {play:'play',next:'next',previous:'previous',diagram:'full-diagram',configuration:'full-configuration',return:'return-journey'};
    for (const control of this.root.querySelectorAll('[data-compact-action]')) if (commands[control.dataset.compactAction]) control.dataset.compactCommand = commands[control.dataset.compactAction];
    this.listen('click', event => this.onClick(event));
    this.listen('change', event => this.onChange(event));
    this.listen('input', event => this.onInput(event));
    this.listen('toggle', event => this.onToggle(event), true);
    this.listen('focusin', event => this.onFocus(event));
    this.listen('keydown', event => this.onKey(event));
    this.restoreDisclosures();
    this.node('attribute-index').hidden = !this.root.querySelector('[data-compact-disclosure="fields"]').hasAttribute('open');
  }
  listen(type, listener, capture = false) {
    this.root.addEventListener(type, listener, capture);
    this.listeners.push([type, listener, capture]);
  }
  node(id) { return this.nodes.get(id); }
  text(id, text) {
    const node = this.node(id), value = String(text ?? '');
    if (node.textContent !== value) node.textContent = value;
  }
  focusIdentity(node) {
    if (!node || !this.root.contains(node)) return null;
    if (node.hasAttribute('data-held-help-close')) return {help:'close'};
    if (node.hasAttribute('data-held-help')) return {help:'trigger'};
    if (node.hasAttribute('data-compact-copy')) {
      const region = node.closest('[id]');
      if (region) return {copy:{region:region.id,index:[...region.querySelectorAll('[data-compact-copy]')].indexOf(node)}};
    }
    const attributes = ['id','data-compact-action','data-compact-row','data-compact-field-trace','data-holding-id','data-held-action','data-held-actor','data-index-attribute','data-trace-topic','data-attribute','data-learning-detail','data-instance-history'];
    for (const attribute of attributes) if (node.hasAttribute(attribute)) return {attribute, value:node.getAttribute(attribute)};
    if (node.tagName === 'SUMMARY') return {summary:this.disclosureIdentity(node.parentElement)};
    return null;
  }
  findFocus(identity) {
    if (identity.help) {
      const inspector = this.node('held-inspector');
      const target = (identity.help === 'close' && inspector.querySelector('[data-held-help-close]')) || inspector.querySelector('[data-held-help]');
      if (!target || target.closest('[hidden]')) return null;
      for (let parent = target.parentElement; parent && parent !== this.root; parent = parent.parentElement) if (parent.tagName === 'DETAILS' && !parent.hasAttribute('open')) return null;
      return target;
    }
    if (identity.copy) return this.node(identity.copy.region)?.querySelectorAll('[data-compact-copy]')[identity.copy.index];
    if (identity.summary) return [...this.root.querySelectorAll('details')].find(node => this.disclosureIdentity(node) === identity.summary)?.querySelector('summary');
    return [...this.root.querySelectorAll('[' + identity.attribute + ']')].find(node => node.getAttribute(identity.attribute) === identity.value);
  }
  setHtml(node, html) {
    if (node.compactHtml === html) return;
    const active = node.contains(document.activeElement) ? this.focusIdentity(document.activeElement) : null;
    const source = html;
    if (html.includes('<svg')) {
      const fragment = document.createElement('div'); fragment.innerHTML = html;
      for (const icon of fragment.querySelectorAll('svg')) icon.parentElement.removeChild(icon);
      html = fragment.innerHTML;
    }
    node.innerHTML = html; node.compactHtml = source;
    this.restoreDisclosures(node);
    if (active) this.findFocus(active)?.focus({preventScroll:true});
  }
  render(reason = 'state', event = this.app.player.snapshot()) {
    if (!this.root) return;
    const app = this.app, projection = compactReadProjection(app, event);
    this.projection = projection;
    const {queue, held, row, position} = projection;
    const key = JSON.stringify([app.heldView.contextId, held.cursor, queue.kind, position, projection.rowComplete, projection.sourceComplete, projection.playback, queue.empty, app.learningDetail, app.lessonVariant, app.lessonSubfixture, app.runtimeEnvironment.revision, app.heldView.selection?.holdingId, app.heldView.actorId, app.heldView.helpOpen]);
    this.renderPlayback(projection);
    if (key === this.semanticKey && reason === 'player') return;
    this.semanticKey = key;
    this.text('compact-family', [app.labModel?.workspace || app.workspace || 'Core', app.labModel?.family || app.labModel?.protocol || app.applicationProtocol].filter(Boolean).join(' - '));
    this.text('compact-position', projection.progress + ' - ' + projection.sourcePosition);
    this.text('compact-scope', 'Active scope: ' + queue.label);
    this.root.querySelector('[data-compact-action="return"]').hidden = !queue.scoped;
    this.text('compact-current-title', row?.title || 'No matching steps in this scope');
    this.text('compact-operation', projection.operation + (row?.protocolLabel || row?.channel ? ' - ' + (row.protocolLabel || row.channel) : ''));
    this.text('compact-actors', row ? row.from === row.to ? (projection.from?.name || row.from) + ' (' + row.from + ')' : (projection.from?.name || row.from) + ' (' + row.from + ') → ' + (projection.to?.name || row.to) + ' (' + row.to + ')' : '');
    this.text('compact-action-summary', projection.summary);
    this.text('compact-action-detail', app.learningDetail === 'journey' && app.labModel?.profile ? '' : row?.protocolDetail || row?.detail || projection.authored?.protocolDetail || projection.authored?.detail || '');
    this.text('compact-result', queue.empty ? 'No authored action matches this investigation. The canonical source prefix is retained; no outcome is inferred.' : held.cursor.eventIndex < 0 ? 'Before step 1. The described action has not been performed; any initial-history row represents configured starting state only.' : projection.initial ? 'Before the first row in this active scope. The described action has not yet been performed in this queue.' : projection.rowComplete ? 'This queue row has reached its mapped end boundary. Completion of this row does not imply authentication, admission or any later result.' : 'This action has not reached its mapped end boundary. Only evidence recorded at this canonical prefix is observed; later effects are not included.');
    this.setHtml(this.node('compact-observations'), projection.actionObservations.length ? '<ul>' + projection.actionObservations.map(item => '<li><strong>' + compactEscape(app.studyActor(item.actorId)?.name || item.actorId) + ' - ' + compactEscape(item.kind) + ': ' + compactEscape(item.result) + '</strong>' + (item.detail ? '<p>' + compactEscape(item.detail) + '</p>' : '') + '</li>').join('') + '</ul>' : '<p>No additional authored observation is recorded for this source event at the current prefix. See the current decision evidence below.</p>');
    this.renderContext();
    this.renderQueue(projection);
    this.renderData(projection);
    this.renderHoldings(projection);
    this.renderFieldDefinition();
    const focus = this.focusIdentity(document.activeElement);
    app.renderCompactEvidence();
    this.restoreDisclosures();
    this.decorateTables();
    if (focus && !this.root.contains(document.activeElement)) this.findFocus(focus)?.focus({preventScroll:true});
    this.addCopyControls();
    const announcementKey = JSON.stringify([app.heldView.contextId,held.cursor,queue.kind,position]);
    if (reason === 'player' && announcementKey !== this.announcementKey && !app.suppressStudyAnnouncement) app.refs['held-announcement'].textContent = projection.progress + '. ' + projection.sourcePosition + (row ? '. ' + row.title : '. No matching action.');
    this.announcementKey = announcementKey;
    if (['mount','switch'].includes(reason) && this.state.focus) this.findFocus(this.state.focus)?.focus({preventScroll:true});
  }
  onPlayer(event) { this.render('player', event); }
  renderPlayback(projection) {
    const play = this.root.querySelector('[data-compact-action="play"]');
    if (play.textContent !== projection.playLabel) play.textContent = projection.playLabel;
    play.disabled = projection.queue.empty;
    this.root.querySelector('[data-compact-action="previous"]').disabled = projection.previousDisabled;
    this.root.querySelector('[data-compact-action="next"]').disabled = projection.nextDisabled;
    this.text('compact-playback-status', (projection.queue.empty ? 'No matching rows' : projection.initial ? 'Before first row' : 'Row ' + (projection.position + 1) + ' / ' + projection.rows.length) + ' - ' + projection.playback);
    const speed = this.node('compact-speed'), value = String(this.app.player.speed);
    if (![...speed.querySelectorAll('option')].some(option => option.value === value)) {
      const option = document.createElement('option'); option.value = value; option.textContent = value + 'x'; speed.appendChild(option);
    }
    if (speed.value !== value) speed.value = value;
  }
  renderContext() {
    const app = this.app, model = app.labModel, profile = model?.profile, environment = app.runtimeEnvironment;
    this.text('compact-profile', profile ? [profile.name,profile.version,profile.publicationStatus,profile.supportStatus].filter(Boolean).join(' - ') : 'Current Core configuration');
    this.text('compact-qualification', [model?.status,model?.supportNote,profile?.implementation].filter(Boolean).join(' - '));
    const draftChanged = JSON.stringify(environment.draft) !== JSON.stringify(environment.applied);
    this.text('compact-environment-status', (environment.active ? 'Custom context applied' : 'Using example context') + ' - revision ' + environment.revision + (draftChanged ? '. Unapplied configuration draft retained; playback uses the applied context.' : '. No unapplied context changes.'));
    const configuration = app.protocolConfig();
    const rows = Object.entries(configuration).map(([key,value]) => '<dt>' + compactEscape(key) + '</dt><dd><code>' + compactEscape(compactValue(value)) + '</code></dd>').join('');
    const provider = app.providerProfile;
    this.setHtml(this.node('compact-configuration'), '<h3>Applied Core settings</h3><dl>' + rows + '</dl>' + (provider && app.upstream === 'external' ? '<h3>Provider profile</h3><p>' + compactEscape(provider.title || provider.id) + '</p>' : '') + '<h3>Applied context overrides</h3><pre>' + compactEscape(compactValue(environment.applied)) + '</pre><h3>Retained draft - not applied to playback</h3><pre>' + compactEscape(compactValue(environment.draft)) + '</pre>' + (profile?.assumptions?.length || model?.prerequisites?.length ? '<h3>Essential assumptions</h3><ul>' + [...new Set([...(model?.prerequisites || []),...(profile?.assumptions || [])])].map(item => '<li>' + compactEscape(item) + '</li>').join('') + '</ul>' : ''));
  }
  renderQueue(projection) {
    this.text('compact-queue-label', projection.queue.label + '. Selecting a row inspects its exact mapped boundary without starting playback.');
    const signature = JSON.stringify([this.app.heldView.contextId, projection.queue.kind, projection.rows.map(row => [row.id,row.title,row.sourceIndex,row.sourceStepId,row.heldCursorEnd])]);
    if (signature !== this.queueSignature) {
      this.queueSignature = signature;
      this.setHtml(this.node('compact-queue'), projection.rows.map((row,index) => '<li><button class="compact-queue-row" data-compact-row="' + index + '"><span>Row ' + (index + 1) + '</span><strong>' + compactEscape(row.title) + '</strong><span>' + compactEscape(row.sourceIndex === -1 || row.heldCursorEnd?.eventIndex === -1 ? 'Initial source boundary' : 'Source event ' + ((row.sourceIndex ?? this.app.steps.findIndex(step => step.id === (row.sourceStepId || row.id))) + 1)) + '</span></button></li>').join('') || '<li>No matching rows. Return to journey to leave this scope.</li>');
      for (const button of this.node('compact-queue').querySelectorAll('[data-compact-row]')) button.dataset.compactStepIndex = button.dataset.compactRow;
    }
    for (const button of this.node('compact-queue').querySelectorAll('[data-compact-row]')) {
      const current = Number(button.dataset.compactRow) === projection.position && !projection.initial;
      if (current) button.setAttribute('aria-current','step'); else button.removeAttribute('aria-current');
    }
  }
  renderData(projection) {
    const node = this.node('compact-data');
    if (!projection.row) { this.setHtml(node,'<p>No matching action in this scope.</p>'); return; }
    const template = document.createElement('div');
    template.innerHTML = this.app.stepHtml(projection.row, projection.position);
    for (const element of template.querySelectorAll('.inspector-kicker,.inspector-title,.inspector-summary,.route-row,.channel-badge,.step-description,.replay-button,svg')) element.parentElement.removeChild(element);
    if (!projection.sourceComplete) {
      const checks = template.querySelector('.check-list'), fields = template.querySelector('.attribute-list');
      this.setHtml(node, '<p>The source action has not completed at this prefix. No future payload or result is shown here. Inspect permission-scoped current holdings for values already available.</p>' + (checks ? '<h3>Authored checks - not a claim they passed</h3>' + checks.outerHTML : '') + (fields ? '<h3>Field definitions</h3>' + fields.outerHTML : ''));
    } else this.setHtml(node, template.innerHTML);
  }
  renderHoldings(projection) {
    const app = this.app, held = projection.held, compiled = app.heldView.compiled();
    const artifacts = new Map(held.artifacts.map(item => [item.artifactId,item]));
    const actors = compiled.actors;
    const html = '<h3>Current holdings - not cumulative history</h3><p>' + compactEscape(projection.sourcePosition) + ' - protocol clock ' + compactEscape(held.protocolClock) + '. Possession is not acceptance or authority.</p>' + actors.map(id => {
      const actor = app.studyActor(id), coverage = held.coverage.find(item => item.actorId === id), holdings = held.holdings.filter(item => item.actorId === id);
      return '<details class="compact-owner" data-compact-owner="' + compactEscape(id) + '"' + (app.heldView.expanded.has(id) ? ' open' : '') + '><summary>' + compactEscape(actor?.name || id) + ' (' + compactEscape(id) + ') - ' + holdings.length + ' known holdings - ' + compactEscape(coverage?.status || 'not-modeled') + '</summary><p>' + compactEscape(actor?.role || '') + '</p>' + app.actorContextHtml(id) + '<p>Coverage: ' + compactEscape(coverage?.status || 'not-modeled') + '. Stores: ' + compactEscape((coverage?.stores || []).join(', ') || 'not declared') + '. ' + compactEscape((coverage?.gaps || []).map(gap => gap.reason).join(' ')) + '</p>' + (holdings.length ? '<ul class="compact-holding-list">' + holdings.map(holding => {
        const artifact = artifacts.get(holding.artifactId), expired = artifact?.expiresAt != null && held.protocolClock >= artifact.expiresAt;
        return '<li><button class="compact-holding" data-holding-id="' + compactEscape(holding.holdingId) + '" aria-pressed="' + (app.heldView.selection?.holdingId === holding.holdingId) + '"><strong>' + compactEscape(artifact?.label || holding.artifactId) + '</strong><span>' + compactEscape(holding.store) + ' - ' + compactEscape(holding.representationId) + ' - ' + compactEscape(expired ? 'Expired - still held' : holding.retention) + '</span><code>' + compactEscape(holding.holdingId) + '</code></button></li>';
      }).join('') + '</ul>' : '<p>' + (coverage?.status === 'complete' ? 'No currently held objects.' : 'No known holdings. This does not establish an empty inventory.') + '</p>') + '</details>';
    }).join('');
    this.setHtml(this.node('held-objects'), html);
    const inspector = this.node('held-inspector'); inspector.hidden = !app.heldView.selection;
    if (app.heldView.selection) {
      const moved = held.holdings.find(item => item.holdingId === app.heldView.selection.holdingId || item.actorId === app.heldView.selection.actorId && item.artifactId === app.heldView.selection.artifactId && item.representationId === app.heldView.selection.representationId && item.ordinal === app.heldView.selection.ordinal);
      if (moved) app.heldView.selection = {...app.heldView.selection,...moved};
      this.setHtml(inspector, app.heldView.inspectionHtml(held));
    }
  }
  disclosureIdentity(details) {
    if (details.dataset.compactDisclosure) return 'reader:' + details.dataset.compactDisclosure;
    if (details.dataset.compactOwner) return 'owner:' + details.dataset.compactOwner;
    for (const key of ['instanceHistory','pamDisclosure','dnssecHopId','remoteComparison']) if (details.dataset[key] != null) return key + ':' + details.dataset[key];
    if (details.id) return 'id:' + details.id;
    const parent = details.parentElement.closest('details');
    return (parent ? this.disclosureIdentity(parent) : 'section:' + (details.closest('[id]')?.id || 'reader')) + '/summary:' + (details.querySelector('summary')?.textContent || '').trim();
  }
  restoreDisclosures(root = this.root) {
    for (const details of root.querySelectorAll('details')) {
      const key = this.disclosureIdentity(details);
      if (this.state.disclosures.has(key)) {
        const open = this.state.disclosures.get(key);
        if (details.hasAttribute('open') !== open) open ? details.setAttribute('open','') : details.removeAttribute('open');
      } else {
        this.state.disclosures.set(key,details.hasAttribute('open'));
      }
    }
  }
  addCopyControls() {
    for (const node of this.root.querySelectorAll('pre,code')) {
      let token = node.dataset.compactValue;
      const existing = token ? [...node.parentElement.querySelectorAll('[data-compact-copy]')].find(button => button.dataset.compactCopy === token) : null;
      const value = node.textContent;
      if (node.parentElement.closest('pre,button,summary') || !value || value === 'Not readable by this holder') { if (existing) existing.parentElement.removeChild(existing); continue; }
      if (existing) { this.copyValues.set(token,value); continue; }
      token = String(++this.copySerial); node.dataset.compactValue = token;
      const button = document.createElement('button');
      this.copyValues.set(token,value); button.setAttribute('type','button'); button.setAttribute('class','button quiet compact-copy');
      button.dataset.compactCopy = token; button.textContent = 'Copy exact value';
      node.parentElement.appendChild(button);
    }
    const live = new Set([...this.root.querySelectorAll('[data-compact-copy]')].map(node => node.dataset.compactCopy));
    for (const token of this.copyValues.keys()) if (!live.has(token)) this.copyValues.delete(token);
  }
  decorateTables() {
    for (const icon of this.root.querySelectorAll('svg')) icon.parentElement.removeChild(icon);
    for (const region of this.root.querySelectorAll('.instance-table-scroll')) {
      region.setAttribute('role','region'); region.setAttribute('tabindex','0');
      if (!region.hasAttribute('aria-label') && !region.hasAttribute('aria-labelledby')) region.setAttribute('aria-label',region.querySelector('caption')?.textContent || 'Detailed protocol evidence comparison');
    }
  }
  pause() { if (this.app.player.status === 'playing') this.app.pauseForStudy(); }
  revealCurrentCard() {
    if (typeof window.getComputedStyle !== 'function') return;
    const card = this.root.querySelector('.compact-current');
    const rect = card.getBoundingClientRect(), bottom = window.innerHeight;
    let delta = rect.top < 0 || rect.bottom > bottom ? rect.top : 0;
    const focused = document.activeElement;
    if (this.root.contains(focused)) {
      const focus = focused.getBoundingClientRect(), minimum = focus.bottom - bottom + 8, maximum = focus.top - 8;
      // A normal-flow control must remain visible even when a tall card cannot
      // fit beside it. Scroll only within the range that preserves its outline.
      delta = minimum <= maximum ? Math.min(maximum,Math.max(minimum,delta)) : 0;
    }
    if (Math.abs(delta) > .5) window.scrollBy({top:delta,behavior:'auto'});
  }
  focusCurrentAction() {
    this.node('compact-current-title').focus({preventScroll:true});
    this.root.querySelector('.compact-current').scrollIntoView({block:'start',behavior:'auto'});
  }
  onClick(event) {
    const control = event.target.closest('button,summary,a'); if (!control || !this.root.contains(control)) return;
    if (control.tagName === 'SUMMARY') { if (!control.parentElement.hasAttribute('open')) this.pause(); return; }
    if (control.tagName === 'A') { this.pause(); return; }
    const app = this.app, action = control.dataset.compactAction;
    if (action === 'play') { app.player.status === 'playing' ? app.pauseForStudy() : app.playCompact(); return; }
    if (action) {
      if (['previous','next'].includes(action)) {
        this.pause(); const projection = compactReadProjection(app);
        app.inspectQueueBoundary(action === 'previous' ? projection.previousIndex : projection.nextIndex, 'end');
        if (control.disabled) this.node('play').focus({preventScroll:true});
        this.revealCurrentCard();
      }
      else if (action === 'return') { app.returnToJourney(); this.focusCurrentAction(); }
      else if (action === 'field-definition' && this.selectedField) this.showField(this.selectedField);
      else if (action === 'diagram' || action === 'configuration') app.switchPresentation('full',{target:action === 'diagram' ? 'diagram' : 'configuration'});
      else if (action === 'copy-link') { this.pause(); app.copyLessonLink(); }
      else if (action === 'case') { this.pause(); const input = this.node('lesson-inputs').querySelector('select'); if (input) input.focus(); else app.querySelector('#lab-scenario-search')?.focus(); }
      else if (action === 'find') { this.pause(); app.querySelector('#lab-scenario-search')?.focus(); }
      return;
    }
    if (control.dataset.compactCopy) { const text = this.copyValues.get(control.dataset.compactCopy); this.pause(); app.copyExactValue(text,control); return; }
    if (control.hasAttribute('data-compact-row')) { this.pause(); app.inspectQueueBoundary(Number(control.dataset.compactRow),'end'); this.revealCurrentCard(); return; }
    this.pause();
    if (control.dataset.compactFieldScope) {
      this.fieldBrowser.scope = control.dataset.compactFieldScope; this.fieldBrowser.limit = this.fieldBatchSize;
      if (this.fieldBrowser.scope === 'current') app.attributeQuery = '';
      app.renderAttributeIndex(); this.decorateTables(); this.addCopyControls(); return;
    }
    if (control.hasAttribute('data-compact-field-more')) {
      const previous = this.fieldBrowser.limit; this.fieldBrowser.limit += this.fieldBatchSize;
      app.renderAttributeIndex(); this.decorateTables(); this.addCopyControls();
      const firstNew = this.node('attribute-index-list').querySelectorAll('[data-index-attribute]')[previous];
      if (firstNew) { firstNew.focus({preventScroll:true}); firstNew.scrollIntoView({block:'nearest',behavior:'auto'}); } return;
    }
    if (control.dataset.holdingId) {
      const holding = app.heldView.snapshot().holdings.find(item => item.holdingId === control.dataset.holdingId);
      if (holding) { app.heldView.select(holding); this.render('selection'); } return;
    }
    if (control.hasAttribute('data-held-trace')) { app.enterObjectTrace(control.dataset.heldTrace); return; }
    if (control.hasAttribute('data-held-exit') || control.hasAttribute('data-clear-trace')) { app.returnToJourney(); return; }
    if (control.hasAttribute('data-held-help') || control.hasAttribute('data-held-help-close')) { this.setHelpOpen(control.hasAttribute('data-held-help') && !app.heldView.helpOpen); return; }
    if (control.dataset.heldRelated) {
      const holding = app.heldView.snapshot().holdings.find(item => item.artifactId === control.dataset.heldRelated && item.actorId === app.heldView.selection?.actorId);
      if (holding) { app.heldView.select(holding); this.render('selection'); } return;
    }
    const field = control.dataset.attribute || control.dataset.indexAttribute;
    if (field) { this.showField(field); return; }
    if (control.dataset.compactFieldTrace) { app.enterFieldTrace(control.dataset.compactFieldTrace); this.focusCurrentAction(); return; }
    if (control.dataset.traceTopic) { app.enterFieldTrace(control.dataset.traceTopic); this.focusCurrentAction(); return; }
    if (control.dataset.learningDetail) { app.setLearningDetail(control.dataset.learningDetail); this.render('detail'); return; }
    if (control.dataset.lessonChapter) {
      const chapter = app.labModel?.chapters?.find(item => item.id === control.dataset.lessonChapter);
      if (!chapter?.stepIds.length) return;
      if (app.studyQueue().scoped) app.returnToJourney();
      const index = app.studyQueue().rows.findIndex(row => chapter.stepIds.includes(row.sourceStepId || row.id));
      if (index >= 0) { app.inspectQueueBoundary(index,'end'); this.revealCurrentCard(); }
    }
  }
  renderFieldDefinition() {
    const target = this.node('compact-field-definition'),back = this.root.querySelector('[data-compact-action="field-definition"]');
    target.hidden = !this.selectedField; back.hidden = !this.selectedField;
    if (!this.selectedField) return;
    target.setAttribute('aria-label',this.app.definition(this.selectedField).name+' field definition');
    this.setHtml(target, this.app.attributeHtml(this.selectedField,true) + '<button class="button quiet" data-compact-field-trace="' + compactEscape(this.selectedField) + '">Follow this field path</button>');
    back.textContent = 'Back to '+this.app.definition(this.selectedField).name+' definition';
  }
  showField(id) {
    this.pause(); this.selectedField = id; this.renderFieldDefinition();
    const details = this.root.querySelector('[data-compact-disclosure="fields"]'); details.setAttribute('open','');
    this.state.disclosures.set(this.disclosureIdentity(details),true);
    this.node('attribute-index').hidden = false; this.app.renderAttributeIndex();
    const target = this.node('compact-field-definition'); target.focus({preventScroll:true});
    target.scrollIntoView({block:'start',behavior:'auto'}); this.decorateTables(); this.addCopyControls();
  }
  onChange(event) {
    const control = event.target, app = this.app;
    if (control.id === 'compact-speed') { app.player.setSpeed(Number(control.value)); this.render('speed'); return; }
    if (!control.closest('#lesson-inputs')) return;
    this.pause();
    const identity = this.focusIdentity(control);
    if (control.id === 'lesson-case') app.selectLessonVariant(control.value);
    else if (control.id === 'lesson-subfixture') app.selectLessonSubfixture(control.value);
    else if (control.dataset.profileControl) {
      const profile = app.labModel?.profileControls?.find(item => item.id === control.dataset.profileControl), option = profile?.options.find(item => item.value === control.value);
      if (option) app.selectLabScenario(option.scenarioId || app.labScenarioId,{variant:option.variantId || 'default'});
    }
    if (identity) this.findFocus(identity)?.focus({preventScroll:true});
  }
  onInput(event) {
    if (event.target.id !== 'attribute-search') return;
    this.pause(); this.app.attributeQuery = event.target.value; this.app.renderAttributeIndex(); this.decorateTables(); this.addCopyControls();
  }
  onToggle(event) {
    const details = event.target;
    if (details.tagName !== 'DETAILS') return;
    const key = this.disclosureIdentity(details), previous = this.state.disclosures.get(key), open = details.hasAttribute('open');
    this.state.disclosures.set(key,open);
    if (details.dataset.compactOwner) {
      const id = details.dataset.compactOwner;
      if (open) { this.app.heldView.actorId = id; this.app.heldView.expanded.add(id); } else this.app.heldView.expanded.delete(id);
    }
    if (open && previous !== true) this.pause();
    if (details.dataset.compactDisclosure === 'fields') this.node('attribute-index').hidden = !open;
    if (details.id === 'protocol-state-panel' || details.dataset.compactDisclosure === 'fields' || details.dataset.instanceHistory) {
      if (details.dataset.instanceHistory) this.app.renderProtocolInstanceHistory(details); else this.app.renderCompactEvidence();
      this.decorateTables();
      this.addCopyControls();
    }
  }
  onFocus(event) {
    this.state.focus = this.focusIdentity(event.target);
    if (event.target.matches('input,select,textarea,[contenteditable="true"]')) this.pause();
  }
  setHelpOpen(open) {
    this.app.heldView.helpOpen = open;
    this.render('selection');
    const target = this.findFocus({help:open ? 'close' : 'trigger'});
    target?.focus({preventScroll:true});
    target?.scrollIntoView({block:'nearest',behavior:'auto'});
  }
  onKey(event) {
    if (event.key !== 'Escape') return;
    if (this.app.heldView.helpOpen && event.target.closest('[data-compact-disclosure="holdings"]')) {
      this.setHelpOpen(false);
      event.preventDefault();
      event.stopPropagation();
      return;
    }
    const details = event.target.closest('details[open]'); if (!details) return;
    details.removeAttribute('open'); details.querySelector('summary')?.focus({preventScroll:true}); event.preventDefault();
  }
  unmount() {
    if (!this.root) return;
    this.state.focus = this.focusIdentity(document.activeElement) || this.state.focus;
    for (const details of this.root.querySelectorAll('details')) this.state.disclosures.set(this.disclosureIdentity(details),details.hasAttribute('open'));
    this.notification.parent.insertBefore(this.notification.node,this.notification.nextSibling);
    this.notification = null;
    for (const [type, listener, capture] of this.listeners) this.root.removeEventListener(type,listener,capture);
    this.listeners.length = 0; this.copyValues.clear(); this.nodes.clear();
    this.root = null; this.host = null; this.projection = null; this.semanticKey = null; this.queueSignature = null;
  }
}
