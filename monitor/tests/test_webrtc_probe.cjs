'use strict';

const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const source = fs.readFileSync(require('path').join(__dirname, '../Resources/webrtc_probe.js'), 'utf8');

function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

function load({ trace = 'ip=203.0.113.7\n', peerPlans = [], fetchError, timers = false } = {}) {
  const messages = [], peers = [], requests = [];
  let now = 1000, timerID = 0;
  const pendingTimers = new Map();
  class AbortController { constructor() { this.signal = {}; this.aborted = false; } abort() { this.aborted = true; } }
  class Peer {
    constructor(config) { this.config = config; this.iceGatheringState = 'new'; this.plan = peerPlans.shift() || {}; peers.push(this); }
    createDataChannel() {}
    createOffer() { if (this.plan.throwOffer) throw new Error('offer failed'); return Promise.resolve({ type: 'offer', sdp: '' }); }
    setLocalDescription() {
      if (this.plan.throwSet) return Promise.reject(new Error('set failed'));
      if (this.plan.emit) queueMicrotask(() => this.plan.emit.forEach(c => this.onicecandidate({ candidate: c })));
      if (this.plan.emitNull) queueMicrotask(() => this.onicecandidate({ candidate: null }));
      if (this.plan.candidateError) queueMicrotask(() => this.onicecandidateerror({ errorText: 'STUN error' }));
      if (this.plan.complete !== false) queueMicrotask(() => { this.iceGatheringState = 'complete'; this.onicegatheringstatechange(); });
      return Promise.resolve();
    }
    close() { this.closed = true; }
  }
  const context = {
    window: { webkit: { messageHandlers: { leakProbe: { postMessage: m => messages.push(m) } } } },
    RTCPeerConnection: Peer, AbortController,
    fetch: (url, opts) => { requests.push({ url, opts }); return fetchError ? Promise.reject(fetchError) : Promise.resolve({ ok: true, text: () => Promise.resolve(trace) }); },
    Date: { now: () => now * 1000 }, Promise, Set, Map, Number, String, Error, RegExp,
    clearTimeout: id => pendingTimers.delete(id),
    setTimeout: (fn, ms) => { const id = ++timerID; pendingTimers.set(id, { fn, ms }); return id; },
    queueMicrotask, console
  };
  context.window.window = context.window;
  vm.createContext(context); vm.runInContext(source, context);
  return { api: context.window.ClaudeWatchProbe, messages, peers, requests, pendingTimers, fire(ms) { [...pendingTimers.values()].filter(t => t.ms === ms).forEach(t => t.fn()); } };
}

async function flush() { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); }

(async () => {
  let h = load({ peerPlans: [{ emit: [{ address: '172.16.1.2', type: 'srflx' }] }, { emit: [{ candidate: 'candidate:1 1 udp 1 2001:db8::1 9 typ prflx' }] }] });
  const normal = h.api.run({ runID: 'normal' }); await flush(); const normalPayload = await normal;
  assert.equal(normalPayload.status, 'complete');
  assert(h.requests[0].opts.credentials === 'omit' && h.requests[0].opts.cache === 'no-store');
  assert(normalPayload.observations.some(o => o.address === '172.16.1.2' && o.kind === 'srflx'));
  assert(normalPayload.observations.some(o => o.address === '2001:db8::1' && o.kind === 'prflx' && o.family === 6));
  assert.equal(normalPayload.scope, '当前检测WebView的ICE/STUN与同轮HTTP参考');
  assert.deepEqual(h.requests.map(r => r.url), ['https://1.1.1.1/cdn-cgi/trace']);

  h = load({ trace: 'ip=198.51.100.1\n', peerPlans: [{ emit: [{ address: '198.51.100.2', type: 'srflx' }] }, { emit: [{ address: '198.51.100.2', type: 'srflx' }] }] });
  const single = await h.api.run({ runID: 'single' }); await flush();
  assert.equal(single.status, 'complete', 'collector must not make a safety judgement from one address');

  h = load({ peerPlans: [{ emit: [{ address: 'machine.local', type: 'host' }, { address: '::ffff:192.0.2.4', type: 'srflx' }] }, { emit: [{ address: '192.0.2.3', type: 'srflx' }] }] });
  const mdns = h.api.run({ runID: 'mdns' }); await flush(); const mdnsPayload = await mdns;
  assert(mdnsPayload.observations.some(o => o.address === 'machine.local' && o.kind === 'mdns' && !('family' in o)));
  assert(mdnsPayload.observations.some(o => o.address === '::ffff:192.0.2.4' && o.family === 6));

  h = load({ trace: '', peerPlans: [{}, {}] }); const zero = h.api.run({ runID: 'zero' }); await flush(); const zeroPayload = await zero;
  assert.equal(zeroPayload.status, 'partial'); assert(zeroPayload.errors.some(e => e.code === 'no_candidates'));

  h = load({ peerPlans: [{ emit: [{ address: '10.0.0.1', type: 'host' }] }, { emit: [{ address: '192.0.2.2', type: 'relay' }] }] });
  const noStun = h.api.run({ runID: 'no-stun' }); await flush(); const noStunPayload = await noStun;
  assert.equal(noStunPayload.status, 'partial');
  assert.equal(noStunPayload.errors.filter(e => e.code === 'no_stun_candidate').length, 2);

  h = load({ trace: 'colo=HKG\n', peerPlans: [{ emitNull: true }, { emitNull: true }] });
  const nullComplete = h.api.run({ runID: 'null-complete' }); await flush(); const nullPayload = await nullComplete;
  assert.equal(nullPayload.status, 'partial'); assert(nullPayload.errors.some(e => e.code === 'no_http_ip'));

  h = load({ peerPlans: [{ candidateError: true }, { emit: [{ address: '192.0.2.4', type: 'srflx' }] }] });
  const candidateError = h.api.run({ runID: 'candidate-error' }); await flush(); const candidateErrorPayload = await candidateError;
  assert.equal(candidateErrorPayload.status, 'partial'); assert(candidateErrorPayload.errors.some(e => e.code === 'candidate_error'));

  h = load({ trace: `ip=203.0.113.4\n${'x'.repeat(32768)}`, peerPlans: [{ emit: [{ address: '192.0.2.4', type: 'srflx' }] }, { emit: [{ address: '192.0.2.5', type: 'srflx' }] }] });
  const oversized = h.api.run({ runID: 'oversized' }); await flush(); const oversizedPayload = await oversized;
  assert.equal(oversizedPayload.status, 'partial'); assert(oversizedPayload.errors.some(e => e.code === 'body_too_large'));

  h = load({ fetchError: new Error('offline'), peerPlans: [{ throwOffer: true }, {}] }); const failed = h.api.run({ runID: 'failed' }); await flush(); const failedPayload = await failed;
  assert.equal(failedPayload.status, 'partial'); assert(failedPayload.errors.some(e => e.stage === 'http_reference'));

  h = load({ peerPlans: [{ complete: false }, { complete: false }] }); const timed = h.api.run({ runID: 'timed', timeoutMs: 9 }); h.fire(9); const timedPayload = await timed;
  assert.equal(timedPayload.status, 'timeout'); assert.equal(timedPayload.errors.filter(e => e.code === 'peer_timeout').length, 2);

  h = load({ peerPlans: [{ complete: false }, { complete: false }] }); const late = h.api.run({ runID: 'late' }); assert.equal(h.api.cancel('late'), true); assert.equal(await late, null); h.fire(8000); await flush();
  assert.equal(h.messages.length, 0, 'cancelled runs must not post late callbacks');
  console.log('webrtc_probe tests passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
