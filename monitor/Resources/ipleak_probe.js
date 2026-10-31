/* IPLeak.net DNS probe. Requests run in this WebView. */
(function () {
  'use strict';
  var active = null;
  var maxBodyBytes = 65536, maxResolvers = 127, maxGeoLookups = 32;

  function send(run, value) {
    if (active === run && !run.stopped) {
      window.webkit.messageHandlers.ipLeakProbe.postMessage(Object.assign({runID: run.id}, value));
    }
  }
  function progress(run, value) {
    var label = document.getElementById('status');
    if (label) label.textContent = value;
    send(run, {progress: value});
  }
  function error(run, stage, message, code) {
    if (run.errors.length < 32) run.errors.push({stage: stage, code: code || 'incomplete', message: String(message).slice(0, 300)});
  }
  function diagnose(run, stage, e) {
    var reason = e && (e.name === 'AbortError' || e.name === 'TimeoutError') ? 'timeout'
      : e && e.name === 'TypeError' ? 'network'
      : e && /^HTTP \d+$/.test(String(e.message || '')) ? 'http_status' : 'invalid_response';
    send(run, {diagnostic: stage + '_request_' + reason});
  }
  function address(value) {
    return typeof value === 'string' && value.length <= 64 &&
      (/^(\d{1,3}\.){3}\d{1,3}$/.test(value) || /^[0-9a-f:]+$/i.test(value) && value.includes(':'));
  }
  function country(value) {
    return typeof value === 'string' && /^[A-Za-z]{2}$/.test(value) ? value.toUpperCase() : null;
  }
  function text(value) {
    return typeof value === 'string' && value.length <= 256 ? value : null;
  }
  async function request(run, url) {
    var controller = new AbortController();
    run.controllers.add(controller);
    var timer;
    var deadline = new Promise(function (_, reject) {
      timer = setTimeout(function () { controller.abort(); var e = new Error('请求超时'); e.name = 'TimeoutError'; reject(e); }, 8000);
    });
    try {
      var operation = (async function () {
        var response = await fetch(url, {method: 'GET', mode: 'cors', credentials: 'omit', cache: 'no-store',
          redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal});
        if (!response.ok) throw new Error('HTTP ' + response.status);
        var declared = Number(response.headers.get('content-length') || 0);
        if (declared > maxBodyBytes) throw new Error('响应超过大小限制');
        var raw = '', size = 0;
        if (response.body && response.body.getReader) {
          var reader = response.body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true}), part;
          while (!(part = await reader.read()).done) {
            size += part.value.byteLength;
            if (size > maxBodyBytes) { controller.abort(); throw new Error('响应超过大小限制'); }
            raw += decoder.decode(part.value, {stream: true});
          }
          raw += decoder.decode();
        } else { throw new Error('无法安全读取响应流'); }
        return JSON.parse(raw);
      })();
      return await Promise.race([operation, deadline]);
    } finally {
      clearTimeout(timer);
      run.controllers.delete(controller);
    }
  }
  async function collectDNS(run, session, rounds) {
    var addresses = new Map();
    var tasks = [];
    for (var i = 0; i < rounds; i++) {
      tasks.push((async function (index) {
      if (run.stopped) return;
      progress(run, 'IPLeak DNS 查询 ' + (index + 1) + ' / ' + rounds);
      try {
        var data;
        try { data = await request(run, 'https://' + session + '-' + index + '.ipleak.net/dnsdetection/'); }
        catch (first) {
          if (run.stopped) return;
          diagnose(run, 'dns', first);
          progress(run, 'IPLeak DNS 本轮重试');
          data = await request(run, 'https://' + session + '-' + index + 'r.ipleak.net/dnsdetection/');
        }
        if (!data || data.session !== session || !data.ip || typeof data.ip !== 'object' || Array.isArray(data.ip)) {
          throw new Error('DNS 回执格式或会话不匹配');
        }
        var entries = Object.entries(data.ip);
        if (entries.length > maxResolvers) throw new Error('DNS 地址数量超过限制');
        for (var entry of entries) {
          if (!address(entry[0]) || !Number.isSafeInteger(entry[1]) || entry[1] <= 0) {
            error(run, 'dns', 'DNS 回执包含无效地址或计数');
            continue;
          }
          if (!addresses.has(entry[0]) && addresses.size >= maxResolvers) throw new Error('DNS 地址数量超过限制');
          addresses.set(entry[0], Math.max(addresses.get(entry[0]) || 0, entry[1]));
        }
        progress(run, 'IPLeak DNS 本轮请求完成');
      } catch (e) {
        if (!run.stopped) { diagnose(run, 'dns', e); progress(run, 'IPLeak DNS 本轮请求失败'); error(run, 'dns', e.message || e, e.name === 'TimeoutError' || e.name === 'AbortError' ? 'timeout' : 'incomplete'); }
      }
      })(i));
    }
    await Promise.all(tasks);
    if (!run.stopped && !addresses.size) error(run, 'dns', '未取得 DNS 递归出口');
    return addresses;
  }
  async function httpReference(run) {
    progress(run, '读取 IPLeak HTTP 出口');
    try {
      var data = await request(run, 'https://ipleak.net/json/');
      if (!data || !address(data.ip)) throw new Error('未取得有效 HTTP 出口');
      var code = country(data.country_code);
      if (!code) error(run, 'http', 'HTTP 出口未取得国家归属');
      progress(run, 'IPLeak HTTP 出口请求完成');
      return {address: data.ip, kind: 'http', source: 'https://ipleak.net/json/',
        family: data.ip.includes(':') ? 6 : 4, country: code,
        region: text(data.region_name), city: text(data.city_name), isp: text(data.isp_name)};
    } catch (e) {
      if (!run.stopped) { diagnose(run, 'http', e); progress(run, 'IPLeak HTTP 出口请求失败'); error(run, 'http', e.message || e, e.name === 'TimeoutError' || e.name === 'AbortError' ? 'timeout' : 'incomplete'); }
      return null;
    }
  }
  async function enrich(run, addresses) {
    var values = Array.from(addresses.keys());
    if (values.length > maxGeoLookups) error(run, 'geoip', 'DNS 地址超过归属查询上限，结果不完整');
    var observations = values.map(function (ip) {
      return {address: ip, kind: 'resolver', source: 'IPLeak.net DNS', family: ip.includes(':') ? 6 : 4};
    });
    for (var i = 0; i < Math.min(values.length, maxGeoLookups); i += 4) {
      if (run.stopped) break;
      progress(run, '读取 IPLeak DNS 归属 ' + Math.min(i + 4, values.length) + ' / ' + values.length);
      await Promise.all(values.slice(i, i + 4).map(async function (ip, offset) {
        try {
          var data = await request(run, 'https://ipleak.net/json/' + encodeURIComponent(ip));
          if (!data || typeof data.ip !== 'string' || data.ip.toLowerCase() !== ip.toLowerCase()) {
            throw new Error('地址归属与查询地址不匹配');
          }
          var code = country(data.country_code);
          if (!code) throw new Error('未取得国家归属');
          Object.assign(observations[i + offset], {country: code, region: text(data.region_name),
            city: text(data.city_name), isp: text(data.isp_name), geoSource: 'IPLeak.net', geoQueriedAt: Date.now() / 1000});
          run.geoEvidence.push({ip: ip, country_code: code, region: text(data.region_name),
            city: text(data.city_name), isp: text(data.isp_name)});
        } catch (e) {
          if (!run.stopped) { diagnose(run, 'geoip', e); error(run, 'geoip', ip + '：' + (e.message || e), e.name === 'TimeoutError' || e.name === 'AbortError' ? 'timeout' : 'incomplete'); }
        }
      }));
    }
    return observations;
  }
  function cancel(id) {
    if (!active || (id && active.id !== id)) return;
    active.stopped = true;
    active.controllers.forEach(function (controller) { controller.abort(); });
    active.controllers.clear();
    active = null;
  }
  async function run(options) {
    cancel();
    var run = {id: options.runID, stopped: false, controllers: new Set(), errors: [], geoEvidence: [], startedAt: Date.now() / 1000};
    active = run;
    try {
      var session = Array.from(crypto.getRandomValues(new Uint8Array(20))).map(function (b) {
        return b.toString(16).padStart(2, '0');
      }).join('');
      var rounds = options.rounds === 8 ? 8 : 5;
      var pair = await Promise.all([collectDNS(run, session, rounds), httpReference(run)]);
      if (run.stopped) return;
      var dns = await enrich(run, pair[0]);
      if (run.stopped) return;
      var observations = dns.concat(pair[1] ? [pair[1]] : []);
      var evidence = JSON.stringify({session: session, dns_servers: Object.fromEntries(pair[0]),
        http: pair[1], geoip: run.geoEvidence});
      send(run, {payload: {kind: 'dns', status: run.errors.length ? 'partial' : 'complete',
        startedAt: run.startedAt, finishedAt: Date.now() / 1000, scope: 'IPLeak.net · 本机 WebView DNS 检测',
        observations: observations, errors: run.errors, contextChanged: false,
        details: ['IPLeak.net 多轮权威 DNS 采样和同一 WebView 的 HTTP 出口。',
          '结果不代表其他应用的 DNS 路径。'], externalJSON: evidence}});
    } catch (e) {
      if (!run.stopped) {
        error(run, 'collector', e.message || e);
        send(run, {payload: {kind: 'dns', status: 'error', startedAt: run.startedAt, finishedAt: Date.now() / 1000,
          scope: 'IPLeak.net · 本机 WebView DNS 检测', observations: [], errors: run.errors, contextChanged: false, details: []}});
      }
    } finally {
      if (active === run) cancel();
    }
  }
  window.IPLeakProbe = {run: run, cancel: cancel};
}());
