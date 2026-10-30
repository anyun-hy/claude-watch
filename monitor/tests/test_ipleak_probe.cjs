const vm = require('node:vm');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const code = fs.readFileSync(__dirname + '/../Resources/ipleak_probe.js', 'utf8');

async function run(options = {}) {
  let finish;
  const result = new Promise(resolve => { finish = resolve; });
  const requests = [];
  const context = vm.createContext({
    document: {getElementById() { return null; }},
    window: {webkit: {messageHandlers: {ipLeakProbe: {postMessage(message) {
      if (message.payload) finish(message.payload);
    }}}}},
    crypto: require('node:crypto').webcrypto, Uint8Array, Array, Map, Set, Object,
    Number, String, Date, Promise, AbortController, TextDecoder, TextEncoder, setTimeout, clearTimeout,
    fetch: async function (raw, settings) {
      requests.push({raw, settings});
      const url = new URL(raw);
      assert.equal(url.protocol, 'https:');
      assert.equal(settings.credentials, 'omit');
      assert.equal(settings.redirect, 'error');
      let body;
      if (url.pathname === '/dnsdetection/') {
        const match = url.hostname.match(/^([0-9a-f]{40})-([0-7])\.ipleak\.net$/);
        assert(match, 'DNS query must use a fresh bounded IPLeak subdomain');
        if (options.dnsFailure && match[2] === '2') return new Response('{}', {status: 503});
        body = {session: options.wrongSession ? 'wrong' : match[1], ip: options.empty ? {} : {'8.8.8.8': Number(match[2]) + 1}};
      } else if (url.hostname === 'ipleak.net' && url.pathname === '/json/') {
        body = {ip: '1.1.1.1', country_code: 'JP', region_name: 'Tokyo', isp_name: 'fixture'};
      } else if (url.hostname === 'ipleak.net' && url.pathname === '/json/8.8.8.8') {
        body = {ip: options.wrongGeoIP ? '9.9.9.9' : '8.8.8.8', country_code: options.missingCountry ? null : 'JP'};
      } else {
        throw new Error('unexpected network destination');
      }
      return new Response(JSON.stringify(body), {status: 200, headers: {'Content-Type': 'application/json'}});
    }
  });
  vm.runInContext(code, context);
  context.window.IPLeakProbe.run({runID: 'fixture', rounds: options.rounds || 5});
  const value = await Promise.race([result, new Promise((_, reject) => setTimeout(() => reject(Error('probe test timed out')), 3000))]);
  return {value, requests};
}

async function cancelRun() {
  const signals = [];
  let delivered = false;
  const context = vm.createContext({
    document: {getElementById() { return null; }},
    window: {webkit: {messageHandlers: {ipLeakProbe: {postMessage(message) {
      if (message.payload) delivered = true;
    }}}}},
    crypto: require('node:crypto').webcrypto, Uint8Array, Array, Map, Set, Object,
    Number, String, Date, Promise, AbortController, TextDecoder, TextEncoder, setTimeout, clearTimeout,
    fetch: function (_url, options) {
      signals.push(options.signal);
      return new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => reject(Error('aborted'))));
    }
  });
  vm.runInContext(code, context);
  context.window.IPLeakProbe.run({runID: 'cancel', rounds: 5});
  await new Promise(resolve => setImmediate(resolve));
  context.window.IPLeakProbe.cancel();
  await new Promise(resolve => setTimeout(resolve, 20));
  assert(signals.length >= 2 && signals.every(signal => signal.aborted));
  assert.equal(delivered, false, 'cancelled run must not publish a late receipt');
}

(async () => {
  let r = await run();
  assert.equal(r.value.status, 'complete');
  assert.equal(r.requests.filter(x => x.raw.includes('/dnsdetection/')).length, 5);
  assert.equal(r.value.observations.find(x => x.kind === 'resolver').country, 'JP');
  assert.equal(r.value.observations.find(x => x.kind === 'http').address, '1.1.1.1');
  assert.equal(r.value.errors.length, 0);
  const evidence = JSON.parse(r.value.externalJSON);
  assert.equal(evidence.dns_servers['8.8.8.8'], 5);
  assert.equal(evidence.geoip[0].country_code, 'JP');
  r = await run({rounds: 8});
  assert.equal(r.requests.filter(x => x.raw.includes('/dnsdetection/')).length, 8);
  r = await run({empty: true});
  assert.equal(r.value.status, 'partial');
  assert(r.value.errors.some(x => x.stage === 'dns'));
  r = await run({wrongSession: true});
  assert.equal(r.value.status, 'partial');
  assert(r.value.errors.some(x => x.stage === 'dns'));
  r = await run({missingCountry: true});
  assert.equal(r.value.status, 'partial');
  assert(r.value.errors.some(x => x.stage === 'geoip'));
  r = await run({wrongGeoIP: true});
  assert.equal(r.value.status, 'partial');
  assert(r.value.errors.some(x => x.stage === 'geoip'));
  r = await run({dnsFailure: true});
  assert.equal(r.value.status, 'partial');
  assert(r.value.observations.some(x => x.kind === 'resolver'));
  await cancelRun();
  console.log('IPLeakProbe: 8 isolated protocol scenarios passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
