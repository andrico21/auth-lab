export const PRESENTATION_PREFERENCE_KEY = 'auth-flow-studio.presentation.v1';

/** Only an explicit enum choice is persisted; automatic viewport choice is local. */
export class PresentationPreference {
  constructor(host = window) {
    this.host = host;
    this.mode = null;
    try {
      const stored = host.localStorage.getItem(PRESENTATION_PREFERENCE_KEY);
      if (stored === 'compact' || stored === 'full') this.mode = stored;
    } catch {
      // file: and privacy policies may deny even reading the storage property.
    }
    if (this.mode) this.source = 'stored';
    else {
      const width = host.innerWidth;
      const available = typeof width === 'number' && Number.isFinite(width) && width > 0;
      this.mode = available && width <= 700 ? 'compact' : 'full';
      this.source = available ? 'initial-viewport' : 'unavailable-viewport';
    }
  }
  select(mode) {
    if (mode !== 'compact' && mode !== 'full') throw new RangeError('Unknown presentation.');
    this.mode = mode;
    this.source = 'explicit-memory';
    try {
      this.host.localStorage.setItem(PRESENTATION_PREFERENCE_KEY, mode);
      this.source = 'explicit-stored';
    } catch {
      // The explicit choice still works for this page when persistence is denied.
    }
    return this.mode;
  }
}
