const LEAD = 380, TRAVEL = 1050, GAP = 240, TAIL = 800;
const packetCount = step => Math.max(1, step?.payload?.length || 0);
const stepDuration = step => LEAD + packetCount(step) * (TRAVEL + GAP) + TAIL;

/** A deterministic animation clock. Packets are intentionally sent one at a time. */
export class FlowPlayer {
  constructor({ requestFrame = cb => requestAnimationFrame(cb), cancelFrame = id => cancelAnimationFrame(id) } = {}) {
    this.requestFrame = requestFrame;
    this.cancelFrame = cancelFrame;
    this.listeners = new Set();
    this.speed = 1;
    this.status = 'idle';
    this.queue = [];
    this.position = 0;
    this.elapsed = 0;
    this.lastTime = null;
    this.handle = null;
    this.kind = 'demo';
  }
  subscribe(listener) { this.listeners.add(listener); return () => this.listeners.delete(listener); }
  emit(type, extra = {}) { this.listeners.forEach(fn => fn({ type, ...this.snapshot(), ...extra })); }
  totalDuration(queue = this.queue) { return queue.reduce((total, step) => total + stepDuration(step), 0); }
  snapshot() {
    const step = this.queue[this.position];
    const count = packetCount(step), duration = stepDuration(step);
    const packetWindow = TRAVEL + GAP;
    const index = Math.min(count - 1, Math.max(0, Math.floor((this.elapsed - LEAD) / packetWindow)));
    const packetElapsed = this.elapsed - LEAD - index * packetWindow;
    const progress = Math.max(0, Math.min(1, packetElapsed / TRAVEL));
    const overallDuration = this.totalDuration();
    const precedingDuration = this.totalDuration(this.queue.slice(0, this.position));
    const overallElapsed = this.queue.length ? precedingDuration + Math.max(0, Math.min(duration, this.elapsed)) : 0;
    return { status: this.status, speed: this.speed, kind: this.kind, step, queuePosition: this.position,
      queueLength: this.queue.length, packetIndex: index, packet: step?.payload?.[index], progress,
      visible: !!step && this.elapsed >= LEAD && packetElapsed <= TRAVEL && this.elapsed < LEAD + count * packetWindow,
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
  schedule() { if (this.status === 'playing' && this.handle === null) this.handle = this.requestFrame(time => this.tick(time)); }
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
  cancel() { if (this.handle !== null) this.cancelFrame(this.handle); this.handle = null; }
  stop(notify = true) { this.cancel(); this.status = 'idle'; this.queue = []; this.position = 0; this.elapsed = 0; this.lastTime = null; if (notify) this.emit('state'); }
}

export const resolveActor = (id, authenticator) => id === 'authenticator' ? authenticator : id;
export const pairKey = (a, b) => [a, b].sort().join('--');

export function connectionSteps(steps, pair, authenticator) {
  return steps.filter(s => pairKey(resolveActor(s.from, authenticator), resolveActor(s.to, authenticator)) === pair);
}
