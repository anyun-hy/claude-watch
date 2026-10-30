const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(`${__dirname}/../Resources/netcoffee_probe.js`, 'utf8');

class Clock {
  constructor() { this.now = 0; this.next = 1; this.tasks = []; }
  set(fn, delay) {
    const id = this.next++;
    this.tasks.push({ id, at: this.now + Math.max(0, Number(delay) || 0), fn });
    return id;
  }
  clear(id) { this.tasks = this.tasks.filter(task => task.id !== id); }
  async runUntil(done, maximum = 10000) {
    for (let turns = 0; turns < maximum && !done(); turns++) {
      this.tasks.sort((a, b) => a.at - b.at || a.id - b.id);
      const task = this.tasks.shift();
      if (!task) throw new Error('virtual clock ran out of work before a receipt');
      this.now = task.at;
      task.fn();
      // The collector uses nested async functions. Flush the resulting
      // microtasks without advancing real wall clock time.
      for (let i = 0; i < 12; i++) await Promise.resolve();
    }
    if (!done()) throw new Error('virtual clock exceeded its turn budget');
  }
}

function receipt(kind, query, data = {}, raw = '{}') {
  return { kind, query, sourceURL: `https://fixture.invalid/${kind}`, queriedAt: 1,
    finishedAt: 2, status: 'complete', httpStatus: 200, raw, data, error: null };
}

function fixture(options = {}) {
  const clock = new Clock();
  const payloads = [], requests = [], cancellations = [], images = [], diagnostics = [];
  const queued = [];
  let context;
  const apiOutcomes = { trace: [], dns: [], geoip: [], ...(options.apiOutcomes || {}) };
  const shift = kind => apiOutcomes[kind].length ? apiOutcomes[kind].shift() : { delay: 0 };
  class Image {
    set src(value) {
      if (!value) return;
      images.push(value);
      if (options.imageNeverCompletes) return;
      clock.set(() => this.onload && this.onload(), options.imageDelayMs ?? 0);
    }
  }
  class Peer {
    constructor() { this.iceGatheringState = 'new'; }
    createDataChannel() {}
    createOffer() { return Promise.resolve({}); }
    setLocalDescription() {
      clock.set(() => {
        this.onicecandidate && this.onicecandidate({ candidate: { address: '8.8.4.4', type: 'srflx' } });
        this.onicecandidate && this.onicecandidate({ candidate: null });
      }, 0);
      return Promise.resolve();
    }
    close() {}
  }
  const deliver = (request, outcome) => {
    if (outcome.never) return;
    clock.set(() => {
      const value = outcome.value || (() => {
        if (request.kind === 'trace') return receipt('trace', '', {}, 'ip=8.8.4.4\nloc=JP\n');
        if (request.kind === 'dns') return receipt('dns', request.query, { dns_servers: options.emptyDns ? [] : ['8.8.8.8'] });
        return receipt('geoip', request.query, { ip: request.query, country: 'JP', city: 'Tokyo', isp: 'fixture' });
      })();
      context.window.NetCoffeeProbe.receive(request.id, value);
    }, outcome.delay ?? 0);
  };
  context = vm.createContext({
    document: { getElementById() { return null; } },
    window: { webkit: { messageHandlers: { coffeeProbe: { postMessage(message) {
      if (message.payload) { payloads.push(message.payload); return; }
      if (message.diagnostic) diagnostics.push(message.diagnostic);
      if (message.cancelRequest) { cancellations.push(message.cancelRequest.id); return; }
      if (!message.request) return;
      requests.push(message.request);
      const outcome = shift(message.request.kind);
      if (options.deferRequests) queued.push({ request: message.request, outcome });
      else deliver(message.request, outcome);
    } } } } },
    Map, Set, Uint8Array, Array, Math, Promise, Image,
    RTCPeerConnection: options.noRtc ? undefined : Peer,
    crypto: require('node:crypto').webcrypto,
    Date: { now: () => clock.now },
    performance: { now: () => clock.now },
    setTimeout: (fn, ms) => clock.set(fn, ms),
    clearTimeout: id => clock.clear(id),
  });
  vm.runInContext(source, context);
  return {
    clock, context, payloads, requests, cancellations, images, queued, diagnostics,
    start(kind, id, rounds = 5, budgetMs = 70000) {
      context.window.NetCoffeeProbe.run({ kind, runID: id, rounds, budgetMs });
    },
    deliver,
  };
}

async function collect(run, kind = 'dns', id = 'one', rounds = 5) {
  run.start(kind, id, rounds);
  await run.clock.runUntil(() => run.payloads.length > 0);
  return run.payloads[0];
}

(async () => {
  // Slow images plus three DNS record reads used to have a possible 87-second
  // path (5 image fallbacks + 3 x 21s API waits + backoff), beyond Swift's
  // former 75s watchdog. This remains below the collector's 70s deadline and
  // preserves an already collected HTTP observation.
  let run = fixture({ imageDelayMs: 3000, emptyDns: true,
    apiOutcomes: { dns: [{ delay: 10000 }, { delay: 10000 }, { delay: 10000 }] } });
  let slow = await collect(run);
  assert.equal(slow.status, 'partial');
  assert(slow.elapsedMs < 70000, `DNS finished after its total budget: ${slow.elapsedMs}`);
  assert(slow.observations.some(row => row.kind === 'http'));
  assert.equal(run.requests.filter(row => row.kind === 'dns').length, 3);
  assert(run.requests.every(row => /^\d+$/.test(row.timeoutMs) && Number(row.timeoutMs) <= 21000));

  // A stalled DNS bridge sends cancellation for its owned request and returns
  // a bounded partial receipt rather than waiting for the outer WebKit timer.
  run = fixture({ apiOutcomes: { dns: [{ never: true }, { never: true }, { never: true }] } });
  const stalled = await collect(run);
  assert.equal(stalled.status, 'partial');
  assert(stalled.errors.some(row => row.stage === 'dns_records' && row.code === 'timeout'));
  assert.equal(run.cancellations.length, 3);
  assert(stalled.elapsedMs < 70000);

  // GeoIP enrichment can time out after DNS has succeeded. The resolver and
  // HTTP address remain visible, but the entire receipt must not be complete.
  run = fixture({ apiOutcomes: { geoip: [{ never: true }, { never: true }] } });
  const geo = await collect(run);
  assert.equal(geo.status, 'partial');
  assert(geo.observations.some(row => row.kind === 'resolver'));
  assert(geo.errors.some(row => row.stage === 'geoip' && row.code === 'timeout'));

  // Preserve the established 21-second per-request tolerance: a normally
  // slow (13–16s) Net.Coffee response remains a success when the remaining
  // collection budget can still accommodate it.
  run = fixture({ apiOutcomes: {
    trace: [{ delay: 16000 }],
    dns: [{ delay: 13000 }],
    geoip: [{ delay: 16000 }, { delay: 16000 }],
  } });
  const slowSuccess = await collect(run);
  assert.equal(slowSuccess.status, 'complete');
  assert(slowSuccess.elapsedMs < 70000);
  assert(run.requests.some(row => Number(row.timeoutMs) === 21000));

  // A transient WebRTC HTTP timeout gets one new HTTP/ICE attempt. Existing
  // ICE observations remain part of the result, and retries stay in budget.
  const timeoutReceipt = { ...receipt('trace', ''), status: 'timeout', error: 'fixture timeout' };
  run = fixture({ apiOutcomes: { trace: [{ delay: 5000, value: timeoutReceipt }, { delay: 0 }] } });
  const recoveredRTC = await collect(run, 'webrtc');
  assert.equal(recoveredRTC.status, 'complete');
  assert.equal(run.requests.filter(row => row.kind === 'trace').length, 2);
  assert(run.diagnostics.includes('http_retry'));
  assert(recoveredRTC.elapsedMs < 70000);

  // Both failed attempts remain incomplete, and both stalled requests are
  // cancelled rather than silently becoming a pass.
  run = fixture({ apiOutcomes: { trace: [{ never: true }, { never: true }] } });
  const failedRTC = await collect(run, 'webrtc');
  assert.equal(failedRTC.status, 'partial');
  assert.equal(run.requests.filter(row => row.kind === 'trace').length, 2);
  assert(failedRTC.errors.some(row => row.stage === 'http' && row.code === 'timeout'));
  assert.equal(run.cancellations.length, 2);
  assert(failedRTC.elapsedMs < 70000);

  // Cancelling during the retry cannot publish a late result.
  run = fixture({ apiOutcomes: { trace: [{ delay: 5000, value: timeoutReceipt }, { never: true }] } });
  run.start('webrtc', 'retry-cancel');
  await run.clock.runUntil(() => run.requests.filter(row => row.kind === 'trace').length === 2);
  run.context.window.NetCoffeeProbe.cancel();
  await Promise.resolve();
  assert.equal(run.payloads.length, 0);

  // A late response belonging to a cancelled run cannot populate a later run.
  run = fixture({ deferRequests: true });
  run.start('dns', 'old');
  const oldTrace = run.queued.find(item => item.request.kind === 'trace');
  assert(oldTrace);
  run.start('dns', 'new');
  run.deliver(oldTrace.request, { delay: 0 });
  for (const item of run.queued.filter(item => item.request.id !== oldTrace.request.id)) run.deliver(item.request, item.outcome);
  await run.clock.runUntil(() => run.payloads.length > 0);
  assert.equal(run.payloads.length, 1);
  assert.equal(run.payloads[0].kind, 'dns');
  assert(!run.payloads[0].observations.some(row => String(row.source).includes('old')));

  // Explicit cancellation never publishes a success receipt.
  run = fixture({ imageNeverCompletes: true });
  run.start('dns', 'cancelled');
  run.context.window.NetCoffeeProbe.cancel();
  await Promise.resolve();
  assert.equal(run.payloads.length, 0);

  for (const rounds of [5, 8]) {
    run = fixture();
    const ok = await collect(run, 'dns', `success-${rounds}`, rounds);
    assert.equal(ok.status, 'complete');
    assert.equal(run.images.length, rounds);
    assert.equal(ok.kind, 'dns');
  }
  console.log('NetCoffee deadline: slow DNS, cancellation, stale reply, GeoIP and 5/8-round contracts passed; no real network');
})().catch(error => { console.error(error); process.exitCode = 1; });
