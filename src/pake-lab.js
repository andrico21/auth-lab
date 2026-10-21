import { labAttribute, labP, labStep, labScenario } from './lab-common.js';

const pakeRetrieved = '2026-10-21';
const pakeRfc2 = 'https://www.rfc-editor.org/rfc/rfc9382';
const pakeRfcPlus = 'https://www.rfc-editor.org/rfc/rfc9383';
export const PAKELAB_SOURCES = [
  { id: 'pake_rfc9382', name: 'SPAKE2 - RFC 9382', standard: 'RFC 9382', section: '3, 4, 6, 7, Appendix B first vector', url: pakeRfc2, revision: 'September 2023', retrieved: pakeRetrieved, errata: 'RFC Editor lookup: no matching errata found on 2026-10-21' },
  { id: 'pake_rfc9383', name: 'SPAKE2+ - RFC 9383', standard: 'RFC 9383', section: '1, 3.2-3.4, 4, 6, Appendix C first vector', url: pakeRfcPlus, revision: 'September 2023', retrieved: pakeRetrieved, errata: 'RFC Editor lookup: no matching errata found on 2026-10-21' },
];
const pakeAttributeSpecs = {
  input: ['Synthetic password input', 'A protected teaching-only password-input handle. Official vectors supply password-equivalent scalars directly and omit their password mapping.', 'Local participant', 'Explain password ownership without collecting credentials', 'Synthetic input handle; no real password'],
  w: ['SPAKE2 password-equivalent w', 'The balanced PAKE requires each endpoint to possess its own provisioned password-equivalent scalar.', 'Out-of-band provisioning', 'Mask a public group share and bind the secret transcript', 'Symbolic official vector w'],
  w0: ['SPAKE2+ w0', 'A password-derived scalar stored at the verifier along with L. The vector supplies it directly, not a password/PBKDF recipe.', 'Prover registration or invocation', 'Mask shares and bind the transcript', 'Symbolic official vector w0'],
  w1: ['SPAKE2+ w1', 'Prover-only password-derived scalar. The verifier stores L=w1*P instead, never w1.', 'Prover local input', 'Compute the augmented shared value V', 'Symbolic official vector w1'],
  L: ['SPAKE2+ registration record L', 'Public group element L=w1*P, stored with w0 in a protected verifier record. A record disclosure is not harmless.', 'Prover registration', 'Allow verifier computation without holding w1/password', 'Symbolic official vector L'],
  x: ['First endpoint private scalar x', 'Ephemeral private scalar belonging only to A or the prover. Never sent or exposed to the peer.', 'First endpoint local generation', 'Fresh exchange contribution', 'Symbolic official vector x'],
  y: ['Second endpoint private scalar y', 'Ephemeral private scalar belonging only to B or the verifier. Never sent or exposed to the peer.', 'Second endpoint local generation', 'Fresh exchange contribution', 'Symbolic official vector y'],
  shareA: ['First public share pA / shareP', 'Masked P-256 group element, not the password or private scalar. Receipt and group validation are separate events.', 'A or prover', 'Public contribution to PAKE', 'Symbolic official vector pA or shareP'],
  shareB: ['Second public share pB / shareV', 'Masked P-256 group element. The receiver must check group membership before deriving a candidate.', 'B or verifier', 'Public contribution to PAKE', 'Symbolic official vector pB or shareV'],
  groupSecret: ['Local group secret K / Z,V', 'Secret group computation, separately held by each endpoint; not a protocol packet or exported application key.', 'Each endpoint local computation', 'Input to the secret transcript', 'Symbolic local K or Z,V'],
  transcript: ['Secret transcript TT', 'Length-prefixed transcript includes local secret material; it must never be projected as a public packet.', 'Each endpoint local computation', 'Bind identities, public shares and secret inputs to the key schedule', 'Symbolic local TT'],
  identityA: ['First participant transcript identity', 'Exact identity bound locally into the secret transcript: A=server for SPAKE2, idProver=client for SPAKE2+.', 'Pinned profile', 'Prevent unknown key-share and identity confusion', 'server or client as specified by the exact vector'],
  identityB: ['Second participant transcript identity', 'Exact identity bound locally into the secret transcript: B=client for SPAKE2, idVerifier=server for SPAKE2+. The controlled balanced mismatch changes only A local B identity.', 'Pinned profile', 'Expose the exact controlled identity disagreement', 'client; controlled mismatch client-altered'],
  context: ['SPAKE2+ transcript Context', 'Application/profile customization string bound into the secret augmented transcript. A controlled mismatch appends the literal text altered at the prover only.', 'Pinned profile', 'Prevent cross-protocol and context confusion', 'SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors'],
  schedule: ['Confirmation-only key schedule', 'SPAKE2 Ka,KcA,KcB or SPAKE2+ K_main,K_confirmP,K_confirmV. These keys stay local and are discarded after execution.', 'Each endpoint local computation', 'Derivation and confirmation only, never application use', 'Symbolic endpoint-local confirmation material'],
  key: ['Derived output Ke / K_shared', 'A derived candidate is not authenticated until the endpoint verifies peer confirmation and sends its own required confirmation in this profile.', 'Each endpoint local computation', 'Retain only after local confirmation; no authorization grant', 'Symbolic local output key'],
  confirmA: ['A / prover confirmation', 'Public MAC tag. SPAKE2 A sends first over secret TT; SPAKE2+ prover sends only after verifying confirmV, over shareV.', 'A or prover', 'Prove possession of the correct candidate key schedule', 'Symbolic official vector cA or confirmP'],
  confirmB: ['B / verifier confirmation', 'Public MAC tag. SPAKE2 B responds after verifying cA; SPAKE2+ verifier sends first over shareP. MAC keys stay secret.', 'B or verifier', 'Endpoint-specific key confirmation', 'Symbolic official vector cB or confirmV'],
  enrollment: ['Teaching-only enrollment envelope', 'Opaque authenticated confidential out-of-band administrative provisioning. RFC 9383 specifies record computation, not this chosen transport.', 'Prover registration', 'Provision only w0,L at the verifier', 'Opaque teaching setup envelope'],
  status: ['Endpoint decision', 'Candidate, peer-confirmed and application-usable are distinct local states. PAKE completion does not grant application authorization.', 'Local checking endpoint', 'Show whose knowledge actually changed', 'Local decision; no global success inference'],
};
export const PAKELAB_ATTRIBUTES = Object.fromEntries(Object.entries(pakeAttributeSpecs).map(([key, spec]) => ['pake_' + key, labAttribute(...spec, 'RFC 9382 / RFC 9383', key === 'w' ? pakeRfc2 : pakeRfcPlus)]));

function pakeProfile(plus) {
  const vector = plus ? 'rfc9383-C-1-p256-sha256' : 'rfc9382-B-1-p256-sha256';
  return {
    id: plus ? 'pake-rfc9383-p256-sha256-v1' : 'pake-rfc9382-p256-sha256-v1',
    name: plus ? 'SPAKE2+' : 'SPAKE2', version: '1.0.0',
    implementation: 'Standards-based teaching profile; no live implementation or product-support claim',
    publicationStatus: plus ? 'RFC 9383 · Independent Submission / Informational' : 'RFC 9382 · IRTF Informational',
    supportStatus: 'standards-based teaching profile; not an AD DS, Keycloak or browser feature',
    algorithms: { group: 'P-256', cofactor: 1, pointEncoding: 'Uncompressed SEC1', fixedPoints: 'RFC fixed M and N', hash: 'SHA-256', kdf: 'HKDF-SHA256', mac: 'HMAC-SHA256', vector,
      identities: plus ? { idProver: 'client', idVerifier: 'server' } : { A: 'server', B: 'client' },
      context: plus ? 'SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors' : '',
      framing: 'uint64 little-endian byte lengths; fixed-width 32-byte big-endian scalars',
      keySchedule: plus ? 'K_main=SHA256(TT); HKDF nil salt, ConfirmationKeys -> two 32-byte keys; SharedKey -> 32-byte K_shared' : 'Ke||Ka=SHA256(TT), 16 bytes each; HKDF nil salt, ConfirmationKeys||empty AAD -> two 16-byte keys',
      confirmation: plus ? 'confirmV=HMAC(K_confirmV,shareP); confirmP=HMAC(K_confirmP,shareV)' : 'cA=HMAC(KcA,TT); cB=HMAC(KcB,TT)',
    },
    transports: ['Abstract ordered public teaching transport; no standardized transport binding claimed', ...(plus ? ['Teaching-only authenticated confidential out-of-band administrative enrollment'] : [])],
    assumptions: ['Immutable synthetic vector-reference fixtures; no runtime cryptography', 'RFC vector supplies password-equivalent inputs directly; password/PBKDF/MHF mapping is not specified by the vector', 'Roles, identities, group and transcript framing are pinned; no editable crypto context'],
    completion: 'Each endpoint verifies the peer confirmation and hands its own required confirmation to the transport before its output key is usable in this bounded profile. Local handoff is distinct from remote receipt/verification; a reciprocal sender can finish while its reply is in flight. No application authorization, ticket, cookie or OAuth token is implied.',
    sources: [PAKELAB_SOURCES[plus ? 1 : 0]],
    cryptoDetail: 'Symbolic references to the exact named official vector fields, not computed runtime bytes. Full curve/KDF/MAC validation is independent offline QA; no validation pass or live interoperability claim is inferred.',
  };
}

// This explicit ledger is authored alongside the source history. It is not
// reconstructed from prose, payloads or attribute operations by the held builder.
function pakeAuthor(id, plus, variant) {
  const first = plus ? 'pake-prover' : 'pake-a', second = plus ? 'pake-verifier' : 'pake-b';
  const profile = pakeProfile(plus), steps = [], objects = new Map(), holdings = new Map();
  const inventory = { artifacts: [], initial: [], events: {}, bindings: [], limitations: [profile.cryptoDetail, 'No application data, authorization, KDC, TGT, OAuth token or cookie is modeled.'] };
  const actors = {
    [first]: { name: plus ? 'Prover (client identity)' : 'A (server identity)', role: plus ? 'Password-holding prover' : 'First sender / M role', plainRole: 'Creates the first public share and checks the other participant locally', kind: 'client', art: 'pakePeer', color: '#5da9e9', position: { x: 250, y: 300 }, notes: [plus ? 'Owns password-input handle, w0,w1 and x; never gives w1 or x to verifier' : 'Owns a provisioned w and private x; official vector A identity is server'] },
    [second]: { name: plus ? 'Verifier (server identity)' : 'B (client identity)', role: plus ? 'Record-holding verifier' : 'Second sender / N role', plainRole: 'Creates the second public share and checks the other participant locally', kind: 'service', art: 'pakePeer', color: '#a78bfa', position: { x: 850, y: 300 }, notes: [plus ? 'Stores only w0,L; never receives password,w1 or x' : 'Owns a provisioned w and private y; official vector B identity is client'] },
  };
  if (variant === 'record-boundary') actors['pake-observer'] = { name: 'Observer / disclosed-record recipient', role: 'Passive recorder, later explicit record recipient', plainRole: 'Sees public traffic; gains a record only through the named teaching disclosure', kind: 'service', color: '#f59e0b', position: { x: 550, y: 610 }, notes: ['No password, private scalar, MAC key or shared session key', 'Record disclosure is teaching-only, not an ordinary network capability or exploit'] };
  const ref = name => 'Symbolic official vector reference: ' + profile.algorithms.vector + '/' + name;
  const field = (key, value) => ({ attributeId: 'pake_' + key, name: PAKELAB_ATTRIBUTES['pake_' + key].name, value });
  const state = (actor, key, value) => ({ op: 'put', path: 'sessions.pake.' + actor + '.' + key, value });
  const event = (stage, actor, title, summary, detail, effects = [], to = actor, protocolLabel = 'Local PAKE computation') => {
    const step = labStep(id + ':' + stage, title, actor, to, plus ? 'SPAKE2+' : 'SPAKE2', actor === to ? 'internal' : 'backchannel', summary, detail, [], [], [], []);
    Object.assign(step, { pakeStage: stage, eventType: actor === to ? 'local' : 'message', protocolLabel, beginnerSummary: summary, protocolDetail: detail, cryptoDetail: profile.cryptoDetail, protocolEffects: effects });
    steps.push(step); inventory.events[step.id] = { effects: [], messages: [] }; return step;
  };
  const at = (step, ...effects) => (step ? inventory.events[step.id].effects : inventory.initial).push(...effects);
  const occurrence = (step, object, actor, kind, representationId = 'local') => {
    if (!step) return;
    const rep = object.representations.find(item => item.representationId === representationId);
    for (const item of rep.fields) {
      const displayed = step.from === step.to || kind === 'send';
      if (displayed && !step.fields.includes(item.attributeId)) step.fields.push(item.attributeId);
      if (displayed && !step.payload.some(entry => entry.attributeId === item.attributeId && entry.value === item.value)) step.payload.push(labP(item.name, item.value, PAKELAB_ATTRIBUTES[item.attributeId].meaning, item.attributeId));
      step.attributeOperations.push({ attributeId: item.attributeId, kind, actorId: actor, instanceId: object.artifactId, creator: object.creator, holders: [actor], inspectors: [...(item.readableBy || rep.readableBy)], fieldPath: item.attributeId, representation: representationId, value: item.value, sourceEventId: step.id, exactValueRef: object.artifactId + '/' + representationId + '/' + item.attributeId, detail: step.detail });
    }
  };
  const acquire = (step, object, actor, store, representationId = 'local', retention = 'retained') => {
    const holdingId = [actor, object.artifactId, representationId, store].join('|');
    holdings.set(holdingId, { actor, object, store, representationId });
    at(step, { op: 'acquire', holdingId, artifactId: object.artifactId, actorId: actor, representationId, store, retention });
  };
  const release = (step, object, actor, store, representationId = 'local') => {
    const holdingId = [actor, object.artifactId, representationId, store].join('|');
    occurrence(step, object, actor, 'evict', representationId);
    at(step, { op: 'release', holdingId }); holdings.delete(holdingId);
  };
  const define = (step, key, type, label, actor, fields, { store = 'PAKE working state', publicValue = false, persistent = false, representations, representationId = publicValue ? 'wire' : 'local' } = {}) => {
    const object = { artifactId: id + ':' + key, generation: 1, type, label, creator: actor, representations: representations || [{ representationId, format: publicValue ? 'Public PAKE value; symbolic pinned fixture reference' : 'Endpoint-local symbolic fixture', readableBy: publicValue ? Object.keys(actors) : [actor], fields }] };
    for (const rep of object.representations) rep.fields = rep.fields.map(item => ({ ...item, readableBy: [...(item.readableBy || rep.readableBy)] }));
    objects.set(key, object); inventory.artifacts.push(object); at(step, { op: 'create', artifactId: object.artifactId });
    acquire(step, object, actor, store, representationId, persistent ? 'retained' : 'temporary');
    occurrence(step, object, actor, type === 'key' || type === 'key-material' ? 'derive' : 'create', representationId);
    return object;
  };
  const transmit = (stage, key, from, to, title, summary, detail, effects = [], representationId = 'wire', protocolLabel) => {
    const object = objects.get(key), step = event(stage, from, title, summary, detail, effects, to, protocolLabel || (plus ? 'SPAKE2+ public exchange' : 'SPAKE2 public exchange'));
    occurrence(step, object, from, 'send', representationId); occurrence(step, object, to, 'receive', representationId);
    acquire(step, object, to, 'PAKE message inbox', representationId, 'temporary');
    if (variant === 'record-boundary') {
      acquire(step, object, 'pake-observer', 'Observer public recording', representationId, 'retained');
      occurrence(step, object, 'pake-observer', 'receive', representationId);
      step.protocolEffects.push({ op: 'append', path: 'knowledge.pakeObserver.publicRecording', value: object.artifactId });
    }
    inventory.events[step.id].messages.push({ messageId: step.id + ':' + from + '->' + to, from, to, objects: [{ artifactId: object.artifactId, representationId }], start: 0, end: 1 });
    step.layers = [{ protocol: protocolLabel || (plus ? 'SPAKE2+' : 'SPAKE2'), transport: representationId === 'opaque-wire' ? 'Teaching-only out-of-band administrative provisioning' : 'Abstract ordered teaching transport', from, to, protection: representationId === 'opaque-wire' ? 'Assumed authenticated confidential enrollment; opaque wire envelope, separate intended-endpoint decoding' : 'Public share or public MAC tag; no password, scalar or MAC key transported', ...(representationId === 'opaque-wire' ? { keyRef: 'teaching-enrollment-channel (symbolic assumed trust)' } : {}) }];
    return step;
  };
  const cleanup = (actor, stage, summary, failed = false) => {
    const step = event(stage, actor, 'Dispose local temporary state', summary, failed ? 'Release only this endpoint invocation, candidate output, scalar, secret transcript, key schedule and message copies. Legitimate setup records persist. Remote cleanup is a different later event.' : 'Release only this endpoint invocation, scalar, secret transcript, key schedule and message copies. Legitimate setup and the confirmed output are retained.', [state(actor, 'temporaryDisposed', true), ...(failed ? [state(actor, 'candidate', false)] : [])]);
    for (const [holdingId, entry] of holdings) if (entry.actor === actor && entry.store !== 'PAKE setup' && (failed || entry.store !== 'PAKE output')) {
      occurrence(step, entry.object, actor, 'evict', entry.representationId); at(step, { op: 'release', holdingId }); holdings.delete(holdingId);
    }
    return step;
  };
  const observe = (step, key, actor, result, kind = 'verification') => at(step, { op: 'observe', artifactId: objects.get(key).artifactId, actorId: actor, kind, result });
  const bind = (actor, key, stateKey, store) => inventory.bindings.push({ path: 'sessions.pake.' + actor + '.' + stateKey, actorId: actor, artifactId: objects.get(key).artifactId, representationId: 'local', store, presentWhen: 'truthy' });
  return { id, plus, first, second, profile, steps, objects, inventory, actors, ref, field, state, event, at, occurrence, acquire, release, define, transmit, cleanup, observe, bind };
}

function pakeScenario(plus, variant = 'success') {
  const id = 'lab-pake-' + (plus ? 'spake2plus-' : 'spake2-') + variant;
  const failed = variant === 'password-mismatch' || variant === 'transcript-reject';
  const a = pakeAuthor(id, plus, variant), { first, second, profile, ref, field, state, event, define, transmit, occurrence, acquire, at, observe, cleanup, bind } = a;
  const changedField = variant === 'password-mismatch' ? (plus ? 'w0,w1' : 'w') : variant === 'transcript-reject' ? (plus ? 'Context' : 'B') : null;
  const controlId = profile.algorithms.vector + (variant === 'password-mismatch' ? '-password-mismatch' : '-transcript-mismatch');
  const controlledRef = (name, side) => failed ? 'Symbolic controlled fixture: ' + controlId + '/' + (plus ? (side === 'a' ? 'P' : 'V') : side.toUpperCase()) + '/' + name + ' (independent oracle: expansion-crypto/fixtures/synthetic.json#/' + (plus ? 'rfc9383' : 'rfc9382') + '/' + (variant === 'password-mismatch' ? 'passwordMismatch' : 'transcriptMismatch') + '/' + (plus ? (side === 'a' ? 'P' : 'V') : side.toUpperCase()) + ')' : ref(name);
  const inputRef = name => variant === 'password-mismatch' ? 'Symbolic controlled input: (' + ref(name) + ' + 1) mod P-256 group order' : ref(name);
  const variantDetail = variant === 'password-mismatch' ? 'Only the first endpoint invocation changes ' + changedField + ' by +1 modulo the group order; the legitimate setup record remains unchanged.' : variant === 'transcript-reject' ? (plus ? "Only prover Context appends ' altered'; verifier retains the official Context." : "Only A binds B='client-altered'; B retains B='client'.") : variant === 'record-boundary' ? 'Ordinary public recording and explicitly disclosed verifier record are different observer capabilities.' : 'Correct inputs and identical profile bindings; both endpoints confirm independently.';
  profile.assumptions.push(variantDetail);
  const pakeVariant = { kind: variant, changedField, detail: variantDetail, fixtureId: failed ? controlId : profile.algorithms.vector, rejector: failed ? (plus ? first : second) : null };
  const initialState = { sessions: { pake: Object.fromEntries([first, second].map(actor => [actor, { candidate: false, peerConfirmed: false, ownConfirmationSent: false, usable: false, temporaryDisposed: false, receivedShare: false, groupValidated: false, receivedConfirmation: false }])) }, credentials: { pake: plus ? { proverInput: true, verifierRecord: false } : { setupA: true, setupB: true } }, outcome: { pake: { status: 'not-started', applicationAuthorization: false } } };
  if (variant === 'record-boundary') initialState.knowledge = { pakeObserver: { publicRecording: [], recordDisclosed: false, passwordRecovered: false, sessionKeyKnown: false } };
  if (plus) {
    define(null, 'prover-input', 'password', 'Prover protected synthetic input handle', first, [field('input', 'Synthetic password-input handle; RFC vector supplies w0,w1 directly')], { store: 'PAKE setup', persistent: true });
    const reg = event('registration-derive', first, 'Prepare augmented registration', 'The prover computes the verifier record without giving away its password.', 'RFC 9383 section 3.2 computes w0,w1 and L=w1*P. The official vector supplies w0,w1 directly; no password/PBKDF mapping is invented.');
    occurrence(reg, a.objects.get('prover-input'), first, 'inspect');
    define(reg, 'registration-working', 'credential', 'Prover registration working values', first, [field('w0', ref('w0')), field('w1', ref('w1')), field('L', ref('L'))]);
    define(reg, 'enrollment-envelope', 'protected-message', 'Teaching-only confidential registration envelope', first, [], { representations: [
      { representationId: 'opaque-wire', format: 'Opaque teaching-only authenticated confidential setup envelope', readableBy: Object.keys(a.actors), fields: [field('enrollment', 'Opaque enrollment envelope; contents w0,L are protected; no standardized registration transport claimed')] },
      { representationId: 'prover-local', format: 'Prover enrollment plaintext before protection', readableBy: [first], fields: [field('w0', ref('w0')), field('L', ref('L'))] },
      { representationId: 'verifier-decoded', format: 'Decoded by intended verifier after teaching-only authenticated setup receipt', readableBy: [second], fields: [field('w0', ref('w0')), field('L', ref('L'))] },
    ], representationId: 'prover-local' });
    acquire(reg, a.objects.get('enrollment-envelope'), first, 'PAKE working state', 'opaque-wire', 'temporary');
    occurrence(reg, a.objects.get('enrollment-envelope'), first, 'create', 'opaque-wire');
    const enrollment = transmit('enroll-record', 'enrollment-envelope', first, second, 'Provision the verifier record', 'A chosen teaching-only confidential setup channel provisions w0 and L.', 'This is out-of-band authenticated administrative enrollment, not an RFC 9383 registration packet. The verifier never receives w1 or the password.', [{ op: 'put', path: 'credentials.pake.verifierRecord', value: true }], 'opaque-wire', 'Teaching-only confidential administrative setup');
    occurrence(enrollment, a.objects.get('enrollment-envelope'), second, 'receive', 'verifier-decoded');
    acquire(enrollment, a.objects.get('enrollment-envelope'), second, 'PAKE message inbox', 'verifier-decoded', 'temporary');
    define(enrollment, 'verifier-record', 'password-verifier', 'Persistent verifier record (w0,L)', second, [field('w0', ref('w0')), field('L', ref('L'))], { store: 'PAKE setup', persistent: true });
    a.inventory.bindings.push({ path: 'credentials.pake.verifierRecord', actorId: second, artifactId: a.objects.get('verifier-record').artifactId, representationId: 'local', store: 'PAKE setup', presentWhen: 'truthy' });
    const discard = event('registration-dispose', first, 'Dispose registration working values', 'Registration is complete; the verifier keeps its record, not a password.', 'The prover releases registration working values before a fresh online invocation. Its protected password-input handle remains.');
    for (const key of ['registration-working', 'enrollment-envelope']) {
      const obj = a.objects.get(key), rep = key === 'enrollment-envelope' ? 'prover-local' : 'local';
      a.release(discard, obj, first, 'PAKE working state', rep);
    }
    a.release(discard, a.objects.get('enrollment-envelope'), first, 'PAKE working state', 'opaque-wire');
  } else {
    define(null, 'setup-a', 'password-equivalent', 'A legitimate provisioned password-equivalent', first, [field('w', ref('w'))], { store: 'PAKE setup', persistent: true });
    define(null, 'setup-b', 'password-equivalent', 'B legitimate provisioned password-equivalent', second, [field('w', ref('w'))], { store: 'PAKE setup', persistent: true });
    for (const [stage, actor, key] of [['provision-a', first, 'setup-a'], ['provision-b', second, 'setup-b']]) {
      const setup = event(stage, actor, 'Inspect provisioned setup', 'Each participant starts with its own protected password-equivalent.', 'RFC 9382 requires agreed A/M and B/N roles and provisioned w. The vector supplies w directly and omits the MHF. No application session exists.');
      occurrence(setup, a.objects.get(key), actor, 'inspect');
    }
  }
  const prepA = event('prepare-a', first, plus ? 'Prover creates its public share' : 'A creates its public share', 'The first participant creates a fresh private contribution and a public masked share.', plus ? 'Prover derives invocation w0,w1 from its local input (symbolic vector references), selects private x and computes shareP=x*P+w0*M.' : 'A selects private x and computes pA=x*P+w*M. x and w remain local.');
  prepA.detail += ' ' + variantDetail; prepA.protocolDetail = prepA.detail;
  define(prepA, 'invocation-a', 'credential', 'First endpoint local invocation input', first, plus ? [field('w0', inputRef('w0')), field('w1', inputRef('w1'))] : [field('w', inputRef('w'))]);
  define(prepA, 'scalar-a', 'private-key', 'First endpoint private x', first, [field('x', ref('x'))]);
  define(prepA, 'share-a', 'public-key', plus ? 'Public shareP' : 'Public pA', first, [field('shareA', variant === 'password-mismatch' ? controlledRef(plus ? 'shareP=x*P+w0prime*M' : 'pA=x*P+wprime*M', 'a') : ref(plus ? 'shareP' : 'pA'))], { publicValue: true });
  transmit('send-a', 'share-a', first, second, 'Send the first public share', 'Only the public masked share crosses the network.', 'Whole-message receipt creates a public inbox copy, not a validated peer or candidate key.', [state(second, 'receivedShare', true)]);
  const checkB = event('validate-a', second, 'Validate the first public point', 'The receiver checks the point before doing secret arithmetic.', 'Check uncompressed SEC1 encoding, P-256 group membership and non-identity. Off-curve and identity inputs are separate offline validation cases.', [state(second, 'groupValidated', true)]);
  occurrence(checkB, a.objects.get('share-a'), second, 'verify', 'wire'); observe(checkB, 'share-a', second, 'accepted_group_member');
  const prepB = event('prepare-b', second, plus ? 'Verifier creates its public share' : 'B creates its public share', 'The second participant creates its own private contribution.', plus ? 'Verifier uses stored w0,L, selects private y and computes shareV=y*P+w0*N. It does not have w1 or the password.' : 'B selects private y and computes pB=y*P+w*N. Neither endpoint acquires the other scalar.');
  define(prepB, 'scalar-b', 'private-key', 'Second endpoint private y', second, [field('y', ref('y'))]);
  define(prepB, 'share-b', 'public-key', plus ? 'Public shareV' : 'Public pB', second, [field('shareB', ref(plus ? 'shareV' : 'pB'))], { publicValue: true });
  transmit('send-b', 'share-b', second, first, 'Send the second public share', 'The first participant receives a share, not an authenticated key.', 'Receipt is separate from the first participant\'s group check and derivation.', [state(first, 'receivedShare', true)]);
  const checkA = event('validate-b', first, 'Validate the second public point', 'The first participant checks the received point locally.', 'Reject invalid encoding, off-curve point, wrong subgroup or identity before computing a candidate.', [state(first, 'groupValidated', true)]);
  occurrence(checkA, a.objects.get('share-b'), first, 'verify', 'wire'); observe(checkA, 'share-b', first, 'accepted_group_member');
  for (const [actor, side] of [[first, 'a'], [second, 'b']]) {
    const derive = event('derive-' + side, actor, 'Derive a local candidate', 'Local computation creates candidate material, not peer confirmation.', plus ? 'Prover: Z=x*(shareV-w0*N), V=w1*(shareV-w0*N). Verifier: Z=y*(shareP-w0*M), V=y*L. Secret TT binds Context, identities, M,N,shares,Z,V,w0. SHA256(TT) then distinct HKDF labels derive confirmation keys and K_shared.' : 'A: K=x*(pB-w*N). B: K=y*(pA-w*M). Secret TT binds A=server,B=client,pA,pB,K,w with length prefixes. SHA256(TT)=Ke||Ka; HKDF(Ka) derives confirmation-only KcA,KcB.', [state(actor, 'candidate', true)]);
    const identities = [field('identityA', plus ? 'client' : 'server'), field('identityB', !plus && variant === 'transcript-reject' && side === 'a' ? 'client-altered' : plus ? 'server' : 'client')];
    if (plus) identities.unshift(field('context', profile.algorithms.context + (variant === 'transcript-reject' && side === 'a' ? ' altered' : '')));
    define(derive, 'schedule-' + side, 'key-material', 'Endpoint-local secret transcript and confirmation schedule', actor, [field('groupSecret', variant === 'password-mismatch' ? controlledRef(plus ? 'Z,V' : 'K', side) : ref(plus ? 'Z,V' : 'K')), ...identities, field('transcript', controlledRef('TT', side)), field('schedule', controlledRef(plus ? 'K_main,K_confirmP,K_confirmV' : 'Ka,KcA,KcB', side))]);
    define(derive, 'key-' + side, 'key', plus ? 'Local K_shared output (candidate until confirmed)' : 'Local Ke output (candidate until confirmed)', actor, [field('key', controlledRef(plus ? 'K_shared' : 'Ke', side))], { store: 'PAKE output', persistent: true });
    observe(derive, 'key-' + side, actor, 'unconfirmed_candidate_not_usable', 'knowledge');
    bind(actor, 'key-' + side, 'candidate', 'PAKE output');
  }
  const confirm = (side, actor) => {
    const create = event('create-confirm-' + side, actor, 'Compute a public confirmation tag', 'A confirmation tag can be public without revealing its MAC key.', plus ? (side === 'b' ? 'Verifier computes confirmV=HMAC(K_confirmV,shareP) and sends first.' : 'Only after verifying confirmV may the prover compute confirmP=HMAC(K_confirmP,shareV).') : (side === 'a' ? 'A computes cA=HMAC(KcA,TT) and sends first.' : 'After verifying cA, B computes cB=HMAC(KcB,TT).'));
    define(create, 'confirmation-' + side, 'confirmation', side === 'a' ? (plus ? 'Public confirmP' : 'Public cA') : (plus ? 'Public confirmV' : 'Public cB'), actor, [field(side === 'a' ? 'confirmA' : 'confirmB', controlledRef(plus ? (side === 'a' ? 'confirmP' : 'confirmV') : (side === 'a' ? 'cA' : 'cB'), side))], { publicValue: true });
  };
  const firstSide = plus ? 'b' : 'a', firstConfirmer = plus ? second : first, lastSide = plus ? 'a' : 'b', lastConfirmer = plus ? first : second;
  confirm(firstSide, firstConfirmer);
  const firstHandoff = event('handoff-confirm-' + firstSide, firstConfirmer, 'Hand the first confirmation to transport', 'Sending changes only the sender state; the peer has not received anything yet.', 'This bounded teaching profile separates local transport handoff from atomic remote receipt. A local send never proves remote delivery.', [state(firstConfirmer, 'ownConfirmationSent', true)]);
  occurrence(firstHandoff, a.objects.get('confirmation-' + firstSide), firstConfirmer, 'use', 'wire');
  observe(firstHandoff, 'confirmation-' + firstSide, firstConfirmer, 'local_transport_handoff_no_remote_receipt', 'knowledge');
  transmit('send-confirm-' + firstSide, 'confirmation-' + firstSide, firstConfirmer, lastConfirmer, 'Deliver the first confirmation', 'The receiver still needs a separate local verification.', 'The previously handed-off public tag arrives atomically. Delivery alone does not confirm either endpoint.', [state(lastConfirmer, 'receivedConfirmation', true)]);
  const verifyFirst = event('verify-confirm-' + firstSide, lastConfirmer, failed ? 'Reject the first confirmation locally' : 'Verify the first confirmation locally', failed ? 'This endpoint rejects a mismatched confirmation; no usable key or reciprocal tag is created.' : 'Only this checking endpoint becomes peer-confirmed; its own reply is still pending.', failed ? 'The local expected MAC does not equal the received tag. ' + variantDetail + ' The rejecting endpoint knows confirmation mismatch, not which private input or transcript field caused it. No RFC error packet is invented.' : 'Recompute the expected MAC using this endpoint secret schedule and compare. Peer confirmation is local; this profile still requires handing off the reciprocal confirmation before usability.', failed ? [state(lastConfirmer, 'failure', 'confirmation-mismatch'), { op: 'put', path: 'outcome.pake.status', value: 'confirmation-rejected' }] : [state(lastConfirmer, 'peerConfirmed', true)]);
  occurrence(verifyFirst, a.objects.get('confirmation-' + firstSide), lastConfirmer, 'verify', 'wire');
  observe(verifyFirst, 'confirmation-' + firstSide, lastConfirmer, failed ? 'rejected_confirmation_mismatch' : 'accepted_confirmation');
  if (failed) {
    observe(verifyFirst, 'key-' + lastSide, lastConfirmer, 'rejected_candidate_never_usable');
    cleanup(lastConfirmer, plus ? 'dispose-a' : 'dispose-b', 'The rejecting endpoint releases only its own temporary and candidate material; legitimate setup persists.', true);
    const timeout = event(plus ? 'timeout-b' : 'timeout-a', firstConfirmer, 'Local wait ends without a reciprocal confirmation', 'The waiting endpoint observes no valid response, not the peer private decision.', 'A bounded teaching wait policy ends this local invocation. This is not an RFC-defined error message and it does not retroactively explain the remote rejection.', [state(firstConfirmer, 'failure', 'local-wait-timeout')]);
    observe(timeout, 'key-' + firstSide, firstConfirmer, 'unconfirmed_candidate_local_timeout');
    cleanup(firstConfirmer, plus ? 'dispose-b' : 'dispose-a', 'The waiting endpoint independently releases its candidate and invocation state while retaining legitimate setup.', true);
  } else {
    observe(verifyFirst, 'key-' + lastSide, lastConfirmer, 'peer_confirmed_waiting_for_own_confirmation');
    confirm(lastSide, lastConfirmer);
    const reciprocalHandoff = event('handoff-confirm-' + lastSide, lastConfirmer, 'Hand the reciprocal confirmation to transport', 'The sender can finish locally while its confirmation is still in flight.', 'The sender has already verified the peer and now hands off its own required confirmation. Only the sender becomes usable; remote receipt and verification are separate later boundaries in this bounded teaching profile.', [state(lastConfirmer, 'ownConfirmationSent', true), state(lastConfirmer, 'usable', true)]);
    occurrence(reciprocalHandoff, a.objects.get('confirmation-' + lastSide), lastConfirmer, 'use', 'wire');
    observe(reciprocalHandoff, 'confirmation-' + lastSide, lastConfirmer, 'local_transport_handoff_no_remote_receipt', 'knowledge');
    observe(reciprocalHandoff, 'key-' + lastSide, lastConfirmer, 'usable_confirmed_output_no_authorization');
    transmit('send-confirm-' + lastSide, 'confirmation-' + lastSide, lastConfirmer, firstConfirmer, 'Deliver the reciprocal confirmation', 'The sender is already locally complete; the receiver must still verify.', 'The in-flight confirmation arrives. Only receiver receipt state changes at this boundary; receiving endpoint confirmation remains false until its local check.', [state(firstConfirmer, 'receivedConfirmation', true)]);
    const verifyLast = event('verify-confirm-' + lastSide, firstConfirmer, 'Verify the reciprocal confirmation locally', 'The final checking endpoint now has a confirmed usable output key.', 'Verify with this endpoint local MAC key. Both endpoint confirmations are now complete, but no application authorization or session is created.', [state(firstConfirmer, 'peerConfirmed', true), state(firstConfirmer, 'usable', true), { op: 'put', path: 'outcome.pake.status', value: 'confirmed-key-only' }]);
    occurrence(verifyLast, a.objects.get('confirmation-' + lastSide), firstConfirmer, 'verify', 'wire'); observe(verifyLast, 'confirmation-' + lastSide, firstConfirmer, 'accepted_confirmation');
    observe(verifyLast, 'key-' + firstSide, firstConfirmer, 'usable_confirmed_output_no_authorization');
    cleanup(first, 'dispose-a', 'The first endpoint keeps its confirmed output and legitimate setup only.');
    cleanup(second, 'dispose-b', 'The second endpoint keeps its confirmed output and legitimate setup only.');
  }
  if (variant === 'record-boundary') {
    const disclosure = event('disclose-record', second, 'Teaching-only verifier record disclosure', 'A new capability discloses the stored record; ordinary public recording did not reveal it.', 'This explicit teaching event copies (w0,L), not password,w1,x,y or session keys. A disclosed record enables verifier impersonation and offline password guessing when derivation parameters are available. Prover impersonation still requires password recovery/equivalent w1 or solving the discrete logarithm of L. This scalar-input vector profile does not define password/PBKDF parameters. No exploit, guess or password checker runs.', [{ op: 'put', path: 'knowledge.pakeObserver.recordDisclosed', value: true }], 'pake-observer', 'Teaching-only record disclosure, not a PAKE packet');
    const record = define(disclosure, 'record-disclosure', 'disclosed-record', 'Explicitly disclosed copy of (w0,L)', second, [], { representationId: 'disclosed-record', representations: [{ representationId: 'disclosed-record', format: 'Teaching-only readable record copy; not ordinary wire observation', readableBy: [second, 'pake-observer'], fields: [field('w0', ref('w0')), field('L', ref('L'))] }] });
    occurrence(disclosure, record, second, 'send', 'disclosed-record'); occurrence(disclosure, record, 'pake-observer', 'receive', 'disclosed-record');
    acquire(disclosure, record, 'pake-observer', 'Observer disclosed-record evidence', 'disclosed-record', 'retained');
    a.release(disclosure, record, second, 'PAKE working state', 'disclosed-record');
    a.inventory.events[disclosure.id].messages.push({ messageId: disclosure.id + ':teaching-disclosure', from: second, to: 'pake-observer', objects: [{ artifactId: record.artifactId, representationId: 'disclosed-record' }], start: 0, end: 1 });
    disclosure.layers = [{ protocol: 'Teaching-only record disclosure', transport: 'Explicit additional disclosure capability; not the PAKE transport', from: second, to: 'pake-observer', protection: 'Intentionally disclosed record copy only; no session-key or ephemeral-secret disclosure' }];
  }
  return labScenario({
    id, title: (plus ? 'SPAKE2+' : 'SPAKE2') + ' - ' + ({ success: plus ? 'registration and confirmed shared key' : 'two independent confirmations', 'password-mismatch': 'wrong input, failed confirmation', 'transcript-reject': plus ? 'Context mismatch rejected by prover' : 'B identity mismatch rejected by B', 'record-boundary': 'ordinary recording versus disclosed verifier record' }[variant]),
    summary: failed ? variantDetail + ' No endpoint gets a usable key; legitimate setup persists.' : variant === 'record-boundary' ? 'Separate an observer public recording from the consequences of explicitly disclosing (w0,L).' : plus ? 'An augmented record avoids storing the prover password, but derivation still needs explicit confirmation.' : 'Balanced PAKE creates a candidate before either participant has confirmed the other.',
    workspace: 'foundations', family: plus ? 'pake-spake2plus' : 'pake-spake2', protocol: plus ? 'SPAKE2+' : 'SPAKE2',
    category: 'PAKE foundations', status: 'reference', standard: profile.publicationStatus, source: plus ? pakeRfcPlus : pakeRfc2, supportNote: profile.supportStatus,
    learningObjective: 'Distinguish provisioning, candidate derivation, endpoint-local peer confirmation and usable output without implying application authorization.',
    prerequisites: plus ? ['Prover protected synthetic password-input handle', 'Teaching-only confidential authenticated enrollment', 'Agreed P-256 profile, client/server identities and exact Context'] : ['Both endpoints provisioned with w', 'Agreed A=server/M and B=client/N roles', 'Pinned P-256 official vector profile'],
    profile, initialState, pakeInventory: a.inventory, pakeVariant,
    relatedLessons: [
      { id: plus ? 'lab-pake-spake2-success' : 'lab-pake-spake2plus-success', title: plus ? 'Compare with balanced SPAKE2' : 'Compare with augmented SPAKE2+', summary: plus ? 'SPAKE2 provisions a password-equivalent at both peers and sends A confirmation first; it does not use an augmented verifier record.' : 'SPAKE2+ stores (w0,L), not the prover password/w1, at the verifier. Verifier confirms first; prover responds only after verification.' },
      { id: 'lab-pake-spake2plus-record-boundary', title: 'Compare ordinary recording with record disclosure', summary: 'Public shares and tags are different from a disclosed verifier record. Disclosure enables verifier impersonation and offline guessing; prover impersonation still requires password recovery.' },
      { id: 'lab-krb-spake-success', title: 'Compare with Kerberos SPAKE', summary: 'RFC 9588 is a separate Kerberos preauthentication profile that strengthens an AS reply key, not standalone SPAKE2/SPAKE2+ confirmation or an AD DS feature.' },
    ],
    keywords: ['PAKE', 'Foundations', 'key confirmation', 'balanced versus augmented PAKE', 'registration record', 'candidate key', profile.algorithms.vector],
    threatExplanation: variant === 'record-boundary' ? 'Ordinary public recording reveals shares and tags, not the verifier record. Disclosing (w0,L) enables verifier impersonation and offline password guessing if password-derivation parameters are available. Impersonation as the prover still requires password recovery/equivalent w1 or solving the discrete logarithm of L. Disclosure does not reveal old session keys or ephemeral scalars. This scalar-input vector supplies no password/PBKDF recipe; no checker or exploit runs.' : failed ? 'Confirmation mismatch rejects an unconfirmed candidate. ' + variantDetail + ' The remote endpoint learns only its own wait outcome. No authorization, session, cookie, token or ticket follows.' : 'A public recording is not a password checker. Online guessing, endpoint compromise and verifier-record disclosure are different threats. A confirmed PAKE key is not an authorization grant.',
  }, PAKELAB_ATTRIBUTES, a.steps, a.actors);
}

export const PAKELAB_SCENARIOS = [
  pakeScenario(false),
  pakeScenario(false, 'password-mismatch'),
  pakeScenario(false, 'transcript-reject'),
  pakeScenario(true),
  pakeScenario(true, 'password-mismatch'),
  pakeScenario(true, 'transcript-reject'),
  pakeScenario(true, 'record-boundary'),
];
