const html = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const valueText = value => typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value ?? '');
const protectedHtml = value => `<bdi dir="ltr" translate="no">${html(value)}</bdi>`;
const rawAttribute = value => html(JSON.stringify(String(value ?? '')));

/** Pure HTML over an already permission-scoped current or previously viewed report. */
export function heldInspectionHtml(data, {contextId, helpOpen = false, objectTraceSelection = null, localization, sourceSteps = [], context:sourceContext = {}} = {}) {
  if (!data) return '';
  const {selection, holding, status, artifact, fields, observations, authority, related, protocolClock} = data;
  const t = (key, source, params = {}) => {
    const english = source.replace(/\{(\w+)\}/g, (_, name) => params[name] ?? `{${name}}`);
    return localization ? localization.html(key, english, params) : html(english);
  };
  const text = (key, source) => localization ? localization.text(key, source) : source;
  const context = {...sourceContext, contextId, artifactId:selection.artifactId, actorId:selection.actorId};
  const explain = (owner, field, source, extra = {}) => !source ? '' : localization ? localization.explainHtml(owner, field, source, {...context, ...extra}) : html(source);
  const action = name => html(JSON.stringify([contextId, selection.artifactId, selection.actorId, name]));
  return `
      <h2>${t('held.inspector.title', 'Exact object inspector')}</h2><h3>${artifact?.label ? explain('artifact:' + selection.artifactId, 'label', artifact.label) : protectedHtml(selection.artifactId)}</h3>
      <p class="held-detached-status">${explain('artifact:' + selection.artifactId, 'holdingStatus', status)}${holding?'':t('held.inspector.historical', ' - previously viewed historical snapshot, not current possession')}</p>
      <dl><dt>${t('held.inspector.artifactId', 'Exact artifact ID')}</dt><dd><code data-copy-raw-json="${rawAttribute(selection.artifactId)}" dir="ltr" translate="no">${html(selection.artifactId)}</code></dd>
      <dt>${t('held.inspector.holdingId', 'Exact holding ID')}</dt><dd><code data-copy-raw-json="${rawAttribute(selection.holdingId)}" dir="ltr" translate="no">${html(selection.holdingId)}</code></dd>
      <dt>${t('held.inspector.creator', 'Creator')}</dt><dd>${protectedHtml(artifact?.creator)}</dd><dt>${t('held.inspector.holder', 'Logical holder')}</dt><dd>${protectedHtml(selection.actorId)}</dd>
      <dt>${t('held.inspector.acquiredAt', 'Acquisition cursor')}</dt><dd>${protectedHtml(valueText(selection.acquiredAt))}</dd>
      <dt>${t('held.inspector.storage', 'Store / retention / representation')}</dt><dd>${protectedHtml(selection.store)} / ${protectedHtml(selection.retention)} / ${protectedHtml(selection.representationId)}</dd>
      ${artifact?.expiresAt!=null?`<dt>${t('held.inspector.expiry', 'Expiry at protocol clock')}</dt><dd>${protectedHtml(artifact.expiresAt)}${protocolClock>=artifact.expiresAt?t('held.inspector.expired', ' - expired, possession unchanged'):''}</dd>`:''}</dl>
      <p>${explain('artifact:' + selection.artifactId, 'details', artifact?.details)}</p>
      <h3>${t('held.inspector.fields', 'Permission-scoped fields for {actor}', {actor:selection.actorId})}</h3>
      ${fields.length?'<dl>'+fields.map(field=>`<dt>${protectedHtml(field.name||field.attributeId)}</dt><dd><pre dir="ltr" translate="no" ${field.readable?`data-copy-raw-json="${rawAttribute(valueText(field.value))}"`:'data-copy-disabled="unreadable"'}>${field.readable?html(valueText(field.value)):`<span class="locale-prose" translate="yes">${t('held.inspector.unreadable', 'Not readable by this holder')}</span>`}</pre></dd>`).join('')+'</dl>':`<p>${t('held.inspector.noFields', 'No readable fields in this representation. Opaque possession is not decryption.')}</p>`}
      <h3>${t('held.inspector.checks', 'Checks, request acceptance and knowledge of {actor}', {actor:selection.actorId})}</h3>
      ${observations.length?observations.map(item=>`<p><strong>${protectedHtml(item.actorId)} · ${protectedHtml(item.kind)} · ${protectedHtml(item.result)}</strong><br>${t('held.inspector.requestLabel', 'Request ')}${item.requestId?protectedHtml(item.requestId):t('held.inspector.unspecified', 'not specified')} · ${t('held.inspector.endpointLabel', 'endpoint ')}${item.endpoint?protectedHtml(item.endpoint):t('held.inspector.unspecified', 'not specified')} · ${t('held.inspector.policyLabel', 'policy ')}${item.policy?protectedHtml(item.policy):t('held.inspector.unspecified', 'not specified')}<br>${explain('observation:' + JSON.stringify([item.sourceEventId ?? item.eventId ?? sourceSteps[item.cursor?.eventIndex]?.id ?? item.cursor?.eventIndex, item.actorId, item.kind, item.requestId]), 'detail', item.detail, {observation:item})}</p>`).join(''):`<p>${t('held.inspector.noObservations', 'No authored observation for this holder at this cursor.')}</p>`}
      <h3>${t('held.inspector.authority', 'Authority state - not automatic holder knowledge')}</h3>
      ${authority.length?authority.map(item=>`<p>${protectedHtml(item.authorityId)} · ${protectedHtml(item.status)} · ${explain('authority:' + item.authorityId, 'detail', item.detail, {authority:item})}</p>`).join(''):`<p>${t('held.inspector.noAuthority', 'No authored authority change at this cursor.')}</p>`}
      <h3>${t('held.inspector.related', 'Related exact IDs')}</h3>
      ${related.map(item=>item.held?`<button class="held-related" data-held-action="${action('related:'+item.id)}" data-held-related="${html(item.id)}">${protectedHtml(item.id)}</button>`:`<p><code dir="ltr" translate="no" data-copy-raw-json="${rawAttribute(item.id)}">${html(item.id)}</code>${t('held.inspector.notHeld', ' - not held by this logical actor at this cursor')}</p>`).join('')||`<p>${t('held.inspector.noneRelated', 'None declared.')}</p>`}
      <button class="held-summary-control" data-held-action="${action('trace')}" data-held-trace="${html(selection.artifactId)}">${t('held.inspector.replay', 'Replay exact object history')}</button>
      <button class="held-summary-control" data-held-action="${action('help')}" data-held-help aria-expanded="${!!helpOpen}">${t('held.inspector.help', 'Inventory help')}</button>
      ${helpOpen?`<section class="held-help" role="dialog" aria-label="${html(text('held.inspector.help', 'Inventory help'))}"><p>${t('held.inspector.helpBody', 'Holding means possession of this representation in the named logical store. Receipt, local checks, request acceptance and issuer authority are separate authored observations. A detached snapshot is only previously viewed history. Replay follows this exact artifact, not every field with the same name.')}</p><button class="held-summary-control" data-held-action="${action('help-close')}" data-held-help-close>${t('held.inspector.closeHelp', 'Close help')}</button></section>`:''}
      ${objectTraceSelection?`<button class="held-summary-control" data-held-action="exit" data-held-exit>${t('held.inspector.return', 'Return to full journey')}</button>`:''}
      <p>${t('held.inspector.historyBoundary', 'History is not current possession. Exact replay uses the same canonical source prefix, not an attribute alias.')}</p>`;
}
