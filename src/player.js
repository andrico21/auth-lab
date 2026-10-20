const LEAD = 380, TRAVEL = 1050, GAP = 240, TAIL = 800;
const packetCount = step => Math.max(1, step?.payload?.length || 0);
const stepDuration = step => LEAD + packetCount(step) * (TRAVEL + GAP) + TAIL;

/** Resolve presentation timing from the same authored event interval as holdings. */
export function authoredMessageTiming(plan, step, kind) {
  if (!plan || !step) return undefined;
  const event = plan.events?.[step.sourceStepId || step.id];
  if (!event?.messages?.length) return undefined;
  let start = 0, end = 1;
  if (step.heldCursorStart && step.heldCursorEnd) {
    const first = step.heldCursorStart, last = step.heldCursorEnd;
    if (first.eventIndex !== last.eventIndex || first.eventIndex < 0) return undefined;
    const at = cursor => cursor.milestone === 'before' ? 0 : event.milestones.find(item => item.id === cursor.milestone).at;
    start = at(first); end = at(last);
  } else if (kind === 'connection') {
    const messages = (event?.messages || []).filter(message => message.from === step.from && message.to === step.to);
    if (messages.length) {
      start = Math.min(...messages.map(message => message.start));
      end = Math.max(...messages.map(message => message.end));
    }
  }
  const messages = (event?.messages || []).filter(message =>
    (!step.from || message.from === step.from) && (!step.to || message.to === step.to) &&
    (!step.artifactId || message.from === step.from && message.to === step.to &&
      message.objects.some(object => object.artifactId === step.artifactId && (!step.representationId || object.representationId === step.representationId))) &&
    message.end > start && message.start < end);
  return messages.length ? { start, end, messages } : undefined;
}

function packetPresentation(elapsed, count, scale = 1) {
  const packetWindow = (TRAVEL + GAP) * scale;
  const packetIndex = Math.min(count - 1, Math.max(0, Math.floor((elapsed - LEAD * scale) / packetWindow)));
  const packetElapsed = elapsed - LEAD * scale - packetIndex * packetWindow;
  return { packetIndex, progress: Math.max(0, Math.min(1, packetElapsed / (TRAVEL * scale))),
    visible: elapsed >= LEAD * scale && packetElapsed <= TRAVEL * scale && elapsed < LEAD * scale + count * packetWindow };
}

function authoredPacket(timing, elapsed, duration, count) {
  const span = timing.end - timing.start;
  const sourceProgress = timing.start + span * Math.max(0, Math.min(1, elapsed / duration));
  const message = timing.messages.find(item => sourceProgress >= item.start && sourceProgress < item.end) ||
    timing.messages.find(item => sourceProgress < item.start) || timing.messages.at(-1);
  const messagePhase = sourceProgress < message.start ? 'pending' : sourceProgress < message.end ? 'in-flight' : 'received';
  const messageStart = (message.start - timing.start) / span;
  const messageEnd = (message.end - timing.start) / span;
  // Keep the normal lead, travel and inter-field gaps unless receipt requires compression.
  // Only field travel must finish by receipt; the ordinary trailing gap/tail need not fit.
  const travelEnd = LEAD + (count - 1) * (TRAVEL + GAP) + TRAVEL;
  const scale = Math.min(1, (messageEnd - messageStart) * duration / travelEnd);
  const presentation = packetPresentation(elapsed - messageStart * duration, count, scale);
  return { ...presentation, ...(messagePhase === 'received' ? { packetIndex: count - 1, progress: 1 } : {}),
    visible: presentation.visible && messagePhase === 'in-flight',
    messagePhase, messageId: message.messageId, messageStart, messageEnd };
}

/** A deterministic animation clock. Packets are intentionally sent one at a time. */
export class FlowPlayer {
  constructor({ requestFrame = cb => requestAnimationFrame(cb), cancelFrame = id => cancelAnimationFrame(id), getTiming } = {}) {
    this.requestFrame = requestFrame;
    this.cancelFrame = cancelFrame;
    this.getTiming = getTiming;
    this.listeners = new Set();
    this.speed = 1;
    this.status = 'idle';
    this.queue = [];
    this.position = 0;
    this.elapsed = 0;
    this.lastTime = null;
    this.handle = null;
    this.kind = 'demo';
    this.reducedMotion = false;
    this.timer = null;
  }
  subscribe(listener) { this.listeners.add(listener); return () => this.listeners.delete(listener); }
  emit(type, extra = {}) { this.listeners.forEach(fn => fn({ type, ...this.snapshot(), ...extra })); }
  totalDuration(queue = this.queue) { return queue.reduce((total, step) => total + stepDuration(step), 0); }
  snapshot() {
    const step = this.queue[this.position];
    const count = packetCount(step), duration = stepDuration(step);
    const legacy = packetPresentation(this.elapsed, count);
    const overallDuration = this.totalDuration();
    const precedingDuration = this.totalDuration(this.queue.slice(0, this.position));
    const overallElapsed = this.queue.length ? precedingDuration + Math.max(0, Math.min(duration, this.elapsed)) : 0;
    const timing = step && this.getTiming?.(step, this.kind);
    const presentation = timing?.messages?.length ? authoredPacket(timing, this.elapsed, duration, count) : {
      ...legacy, visible: !!step && legacy.visible, messagePhase: 'unmodeled' };
    return { status: this.status, speed: this.speed, kind: this.kind, step, queuePosition: this.position,
      queueLength: this.queue.length, ...presentation, packet: step?.payload?.[presentation.packetIndex],
      duration, elapsed: this.elapsed, stepElapsed: this.elapsed, overallDuration, overallElapsed,
      overallProgress: overallDuration ? overallElapsed / overallDuration : 0 };
  }
  play(queue, kind = 'demo') {
    this.stop(false);
    if (!queue.length) return;
    this.queue = queue.slice(); this.position = 0; this.elapsed = 0; this.lastTime = null;
    this.kind = kind; this.status = this.speed > 0 ? 'playing' : 'paused';
    this.emit('step'); this.emit('state'); this.schedule();
  }
  /** Preview an absolute position in this queue; a seek never starts playback. */
  seek(queue, fraction, kind = 'demo') {
    const value = Number(fraction);
    if (!Array.isArray(queue) || !Number.isFinite(value)) return false;
    this.stop(false);
    this.kind = kind;
    if (!queue.length) { this.emit('state'); this.emit('frame'); return true; }
    this.queue = queue.slice();
    const fraction01 = Math.max(0, Math.min(1, value));
    let remaining = this.totalDuration() * fraction01;
    while (this.position + 1 < this.queue.length && remaining >= stepDuration(this.queue[this.position])) {
      remaining -= stepDuration(this.queue[this.position]);
      this.position += 1;
    }
    this.elapsed = Math.min(stepDuration(this.queue[this.position]), remaining);
    this.status = 'paused';
    this.emit('step'); this.emit('state'); this.emit('frame');
    return true;
  }
  setReducedMotion(enabled) {
    const next=!!enabled;
    if(next===this.reducedMotion)return;
    this.cancel();this.reducedMotion=next;this.lastTime=null;this.schedule();
  }
  schedule() {
    if(this.status!=='playing'||this.handle!==null||this.timer!==null)return;
    if(this.reducedMotion){this.timer=setTimeout(()=>this.advanceReducedMotion(),600/this.speed);return;}
    this.handle=this.requestFrame(time=>this.tick(time));
  }
  advanceReducedMotion() {
    this.timer=null;if(this.status!=='playing')return;
    this.elapsed=stepDuration(this.queue[this.position]);this.emit('stepcomplete');
    if(this.position+1>=this.queue.length){this.status='complete';this.emit('complete');this.emit('state');return;}
    this.position+=1;this.elapsed=0;this.emit('step');this.emit('frame');this.schedule();
  }
  tick(time) {
    this.handle = null;
    if (this.status !== 'playing') return;
    const delta = this.lastTime === null ? 0 : Math.max(0, Math.min(100, time - this.lastTime));
    this.lastTime = time; this.elapsed += delta * this.speed;
    let state = this.snapshot();
    while (this.elapsed >= state.duration) {
      this.emit('stepcomplete');
      if (this.position + 1 >= this.queue.length) {
        this.elapsed = state.duration;
        this.status = 'complete'; this.emit('complete'); this.emit('state'); return;
      }
      this.elapsed -= state.duration;
      this.position += 1; this.emit('step'); state = this.snapshot();
    }
    this.emit('frame', state); this.schedule();
  }
  pause() { if (this.status !== 'playing') return; this.status = 'paused'; this.cancel(); this.lastTime = null; this.emit('state'); }
  resume() {
    if (this.status !== 'paused' || this.speed === 0) return;
    if (this.snapshot().overallProgress >= 1) {
      this.status = 'complete'; this.emit('complete'); this.emit('state'); return;
    }
    this.status = 'playing'; this.lastTime = null; this.emit('state'); this.schedule();
  }
  setSpeed(speed) {
    if (!['number', 'string'].includes(typeof speed) || typeof speed === 'string' && !speed.trim()) return false;
    const value = Number(speed);
    if (!Number.isFinite(value) || value < 0) return false;
    this.speed = value === 0 ? 0 : Math.max(.01, Math.min(4, value));
    if (this.speed === 0) this.pause();
    this.emit('speed'); return true;
  }
  cancel() { if(this.timer!==null){clearTimeout(this.timer);this.timer=null;}if (this.handle !== null) this.cancelFrame(this.handle); this.handle = null; }
  stop(notify = true) { this.cancel(); this.status = 'idle'; this.queue = []; this.position = 0; this.elapsed = 0; this.lastTime = null; if (notify) this.emit('state'); }
}

export const resolveActor = (id, authenticator) => id === 'authenticator' ? authenticator : id;
export const pairKey = (a, b) => [a, b].sort().join('--');

export function connectionSteps(steps, pair, authenticator) {
  return steps.filter(s => pairKey(resolveActor(s.from, authenticator), resolveActor(s.to, authenticator)) === pair);
}
