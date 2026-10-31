const html = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const valueText = value => typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value ?? '');

/** Pure HTML over an already permission-scoped current or previously viewed report. */
export function heldInspectionHtml(data, {contextId, helpOpen = false, objectTraceSelection = null} = {}) {
  if (!data) return '';
  const {selection, holding, status, artifact, fields, observations, authority, related, protocolClock} = data;
  const action = name => html(JSON.stringify([contextId, selection.artifactId, selection.actorId, name]));
  return `
      <h2>Exact object inspector</h2><h3>${html(artifact?.label||selection.artifactId)}</h3>
      <p class="held-detached-status">${status}${holding?'':' - previously viewed historical snapshot, not current possession'}</p>
      <dl><dt>Exact artifact ID</dt><dd><code>${html(selection.artifactId)}</code></dd>
      <dt>Exact holding ID</dt><dd><code>${html(selection.holdingId)}</code></dd>
      <dt>Creator</dt><dd>${html(artifact?.creator)}</dd><dt>Logical holder</dt><dd>${html(selection.actorId)}</dd>
      <dt>Acquisition cursor</dt><dd>${html(valueText(selection.acquiredAt))}</dd>
      <dt>Store / retention / representation</dt><dd>${html(selection.store)} / ${html(selection.retention)} / ${html(selection.representationId)}</dd>
      ${artifact?.expiresAt!=null?`<dt>Expiry at protocol clock</dt><dd>${html(artifact.expiresAt)}${protocolClock>=artifact.expiresAt?' - expired, possession unchanged':''}</dd>`:''}</dl>
      <p>${html(artifact?.details||'')}</p>
      <h3>Permission-scoped fields for ${html(selection.actorId)}</h3>
      ${fields.length?'<dl>'+fields.map(field=>`<dt>${html(field.name||field.attributeId)}</dt><dd><pre>${field.readable?html(valueText(field.value)):'Not readable by this holder'}</pre></dd>`).join('')+'</dl>':'<p>No readable fields in this representation. Opaque possession is not decryption.</p>'}
      <h3>Checks, request acceptance and knowledge of ${html(selection.actorId)}</h3>
      ${observations.length?observations.map(item=>`<p><strong>${html(item.actorId)} · ${html(item.kind)} · ${html(item.result)}</strong><br>Request ${html(item.requestId||'not specified')} · endpoint ${html(item.endpoint||'not specified')} · policy ${html(item.policy||'not specified')}<br>${html(item.detail||'')}</p>`).join(''):'<p>No authored observation for this holder at this cursor.</p>'}
      <h3>Authority state - not automatic holder knowledge</h3>
      ${authority.length?authority.map(item=>`<p>${html(item.authorityId)} · ${html(item.status)} · ${html(item.detail||'')}</p>`).join(''):'<p>No authored authority change at this cursor.</p>'}
      <h3>Related exact IDs</h3>
      ${related.map(item=>item.held?`<button class="held-related" data-held-action="${action('related:'+item.id)}" data-held-related="${html(item.id)}">${html(item.id)}</button>`:`<p><code>${html(item.id)}</code> - not held by this logical actor at this cursor</p>`).join('')||'<p>None declared.</p>'}
      <button class="held-summary-control" data-held-action="${action('trace')}" data-held-trace="${html(selection.artifactId)}">Replay exact object history</button>
      <button class="held-summary-control" data-held-action="${action('help')}" data-held-help aria-expanded="${!!helpOpen}">Inventory help</button>
      ${helpOpen?`<section class="held-help" role="dialog" aria-label="Inventory help"><p>Holding means possession of this representation in the named logical store. Receipt, local checks, request acceptance and issuer authority are separate authored observations. A detached snapshot is only previously viewed history. Replay follows this exact artifact, not every field with the same name.</p><button class="held-summary-control" data-held-action="${action('help-close')}" data-held-help-close>Close help</button></section>`:''}
      ${objectTraceSelection?'<button class="held-summary-control" data-held-action="exit" data-held-exit>Return to full journey</button>':''}
      <p>History is not current possession. Exact replay uses the same canonical source prefix, not an attribute alias.</p>`;
}
