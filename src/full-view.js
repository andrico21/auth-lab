/** Full owns only diagram/editor DOM and its listeners/observers, never a session. */
export class FullView {
  constructor(app) { this.app = app; this.listeners = []; this.host = null; }
  listen(node, type, listener, options) {
    node.addEventListener(type, listener, options);
    this.listeners.push([node, type, listener, options]);
  }
  mount(host) {
    this.host = host;
    host.innerHTML = this.app.fullShell();
    this.app.cacheRefs();
    this.app.refs['show-step-attributes'].checked = this.app.showStepAttributes;
    this.app.refs['show-held-objects'].checked = this.app.heldView.visible;
    this.app.refs['move-participants'].checked = this.app.moveParticipants;
    this.app.heldView.mount();
    this.app.bindFull();
  }
  render(reason) { this.app.renderFull(reason); }
  onPlayer(event) { this.app.onFullPlayer(event); }
  unmount() {
    this.app.releaseActorDrag();
    this.app.hideStepAttributes();
    this.app.heldView.unmount();
    for (const [node, type, listener, options] of this.listeners) node.removeEventListener(type, listener, options);
    this.listeners.length = 0;
    this.host = null;
  }
}
