(function () {
  'use strict';

  var activeRuns = new Map();
  var TRACE_URL = 'https://1.1.1.1/cdn-cgi/trace';
  var ICE_SERVERS = [
    { url: 'stun:stun.l.google.com:19302', source: 'stun.l.google.com:19302' },
    { url: 'stun:stun.cloudflare.com:3478', source: 'stun.cloudflare.com:3478' }
  ];
  var MAX_OBSERVATIONS = 128;
  var MAX_HTTP_BODY_BYTES = 32768;

  function unixSeconds() { return Math.floor(Date.now() / 1000); }

  function messageHandler() {
    return window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.leakProbe;
  }

  function addError(state, stage, code, message) {
    state.errors.push({ stage: stage, code: String(code), message: String(message || code) });
  }

  function parseCandidate(candidate) {
    if (!candidate) return null;
    var address = candidate.address;
    var kind = candidate.type;
    if (!address || !kind) {
      var fields = String(candidate.candidate || '').trim().split(/\s+/);
      if (!address && fields.length > 4) address = fields[4];
      if (!kind) {
        var typIndex = fields.indexOf('typ');
        if (typIndex >= 0 && fields.length > typIndex + 1) kind = fields[typIndex + 1];
      }
    }
    if (!address || !kind) return null;
    address = String(address);
    // WebKit may expose local host candidates through mDNS names. They are a
    // distinct observation category, rather than IP input for native policy.
    if (/\.local$/i.test(address)) kind = 'mdns';
    return { address: address, kind: String(kind) };
  }

  function familyOf(address) {
    if (/\.local$/i.test(address)) return undefined;
    // IPv4-mapped IPv6 has a colon and intentionally remains family 6.
    if (address.indexOf(':') >= 0) return 6;
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(address)) return 4;
    return undefined;
  }

  function addObservation(state, address, kind, source) {
    if (state.observationKeys.size >= MAX_OBSERVATIONS) {
      state.capped = true;
      return;
    }
    var key = address + '\u0000' + kind + '\u0000' + source;
    if (state.observationKeys.has(key)) return;
    var observation = { address: address, kind: kind, source: source };
    var family = familyOf(address);
    if (family) observation.family = family;
    state.observationKeys.add(key);
    state.observations.push(observation);
  }

  function cleanup(state) {
    state.timers.forEach(function (timer) { clearTimeout(timer); });
    state.timers = [];
    if (state.controller) state.controller.abort();
    state.peers.forEach(function (peer) {
      try { peer.close(); } catch (_) { /* already closed */ }
    });
    state.peers = [];
  }

  function isActive(state) { return !state.finished && activeRuns.get(state.runID) === state; }

  function finish(state, status) {
    if (!isActive(state)) return;
    state.finished = true;
    cleanup(state);
    if (state.capped) addError(state, 'collector', 'observation_limit', '采集候选数量已达到上限');
    if (!state.observations.length) addError(state, 'collector', 'no_candidates', '未采集到 ICE 或 HTTP 参考地址');
    var payload = {
      kind: 'webrtc',
      status: status,
      startedAt: state.startedAt,
      finishedAt: unixSeconds(),
      scope: '当前检测WebView的ICE/STUN与同轮HTTP参考',
      observations: state.observations,
      errors: state.errors,
      contextChanged: false,
      details: state.details
    };
    activeRuns.delete(state.runID);
    var handler = messageHandler();
    if (handler && typeof handler.postMessage === 'function') {
      try { handler.postMessage({ runID: state.runID, payload: payload }); } catch (_) { /* native boundary is best effort */ }
    }
    state.resolve(payload);
  }

  function peerComplete(state, peerState) {
    if (!isActive(state) || peerState.done) return;
    peerState.done = true;
    if (peerState.stunCandidates === 0) {
      addError(state, 'ice:' + peerState.source, 'no_stun_candidate', '未采集到 server-reflexive 或 peer-reflexive 候选');
    }
    state.pendingPeers -= 1;
    maybeFinish(state);
  }

  function startPeer(state, server) {
    var peerState = { done: false, source: server.source, stunCandidates: 0 };
    state.peerStates.push(peerState);
    var peer;
    try {
      peer = new RTCPeerConnection({ iceServers: [{ urls: server.url }] });
      state.peers.push(peer);
      // Register before setting local description: candidates may begin immediately.
      peer.onicecandidate = function (event) {
        if (!isActive(state)) return;
        if (!event || !event.candidate) {
          peerComplete(state, peerState);
          return;
        }
        var parsed = parseCandidate(event.candidate);
        if (parsed) {
          addObservation(state, parsed.address, parsed.kind, peerState.source);
          if (parsed.kind === 'srflx' || parsed.kind === 'prflx') peerState.stunCandidates += 1;
        }
      };
      peer.onicegatheringstatechange = function () {
        if (peer.iceGatheringState === 'complete') peerComplete(state, peerState);
      };
      peer.onicecandidateerror = function (event) {
        if (!isActive(state)) return;
        var message = event && (event.errorText || event.url) || 'ICE 候选收集失败';
        addError(state, 'ice:' + peerState.source, 'candidate_error', message);
        peerComplete(state, peerState);
      };
      peer.createDataChannel('probe');
      Promise.resolve(peer.createOffer())
        .then(function (offer) {
          if (!isActive(state)) return null;
          return peer.setLocalDescription(offer);
        })
        .then(function () {
          if (isActive(state) && peer.iceGatheringState === 'complete') peerComplete(state, peerState);
        })
        .catch(function (error) {
          if (!isActive(state)) return;
          addError(state, 'ice:' + peerState.source, 'peer_failed', error && error.message ? error.message : 'ICE 建连失败');
          peerComplete(state, peerState);
        });
    } catch (error) {
      addError(state, 'ice:' + server.source, 'peer_create_failed', error && error.message ? error.message : '无法创建 ICE 连接');
      peerComplete(state, peerState);
    }
  }

  function startReference(state) {
    if (typeof fetch !== 'function' || typeof AbortController !== 'function') {
      addError(state, 'http_reference', 'unsupported', '当前 WebView 不支持 HTTP 参考请求');
      state.httpDone = true;
      maybeFinish(state);
      return;
    }
    state.controller = new AbortController();
    var httpTimer = setTimeout(function () {
      if (!isActive(state) || state.httpDone) return;
      addError(state, 'http_reference', 'timeout', 'HTTP 参考请求超时');
      state.controller.abort();
    }, 6000);
    state.timers.push(httpTimer);
    fetch(TRACE_URL, { credentials: 'omit', cache: 'no-store', signal: state.controller.signal })
      .then(function (response) {
        if (!response || !response.ok) throw new Error('HTTP ' + (response ? response.status : 'failed'));
        var length = response.headers && typeof response.headers.get === 'function' && response.headers.get('content-length');
        if (length && Number(length) > MAX_HTTP_BODY_BYTES) {
          var tooLarge = new Error('HTTP 参考响应超过大小上限');
          tooLarge.code = 'body_too_large';
          throw tooLarge;
        }
        return response.text();
      })
      .then(function (text) {
        if (!isActive(state)) return;
        if (String(text).length > MAX_HTTP_BODY_BYTES) {
          addError(state, 'http_reference', 'body_too_large', 'HTTP 参考响应超过大小上限');
          state.httpDone = true;
          clearTimeout(httpTimer);
          maybeFinish(state);
          return;
        }
        var found = false;
        var lines = String(text).split(/\r?\n/);
        for (var i = 0; i < lines.length; i += 1) {
          if (lines[i].slice(0, 3) === 'ip=') {
            var address = lines[i].slice(3).trim();
            if (isPlausibleIP(address)) {
              addObservation(state, address, 'http', TRACE_URL);
              found = true;
            }
            break;
          }
        }
        if (!found) addError(state, 'http_reference', 'no_http_ip', 'HTTP 参考响应中没有可用的 IP 字段');
        state.httpDone = true;
        clearTimeout(httpTimer);
        maybeFinish(state);
      })
      .catch(function (error) {
        if (!isActive(state)) return;
        addError(state, 'http_reference', error && error.code === 'body_too_large' ? 'body_too_large' : (error && error.name === 'AbortError' ? 'timeout' : 'fetch_failed'), error && error.message ? error.message : 'HTTP 参考请求失败');
        state.httpDone = true;
        clearTimeout(httpTimer);
        maybeFinish(state);
      });
  }

  function isPlausibleIP(address) {
    if (!address || /\s/.test(address)) return false;
    if (address.indexOf(':') >= 0) return address.length > 2;
    var octets = address.split('.');
    if (octets.length !== 4) return false;
    for (var i = 0; i < octets.length; i += 1) {
      if (!/^\d+$/.test(octets[i]) || Number(octets[i]) > 255) return false;
    }
    return true;
  }

  function maybeFinish(state) {
    if (!isActive(state) || !state.httpDone || state.pendingPeers > 0) return;
    var hasFailure = state.errors.length > 0 || state.capped || state.observations.length === 0;
    finish(state, hasFailure ? 'partial' : 'complete');
  }

  function run(options) {
    options = options || {};
    if (!options.runID || typeof options.runID !== 'string') return Promise.reject(new Error('runID is required'));
    cancel(options.runID);
    var timeoutMs = Number(options.timeoutMs);
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) timeoutMs = 8000;
    var resolve;
    var promise = new Promise(function (done) { resolve = done; });
    var state = {
      runID: options.runID,
      startedAt: unixSeconds(),
      observations: [], observationKeys: new Set(), errors: [],
      details: [
        'HTTP参考：Cloudflare 1.1.1.1/cdn-cgi/trace',
        'STUN：stun.l.google.com:19302',
        'STUN：stun.cloudflare.com:3478',
        '候选列表在本机汇总；诊断服务会看到各自请求的网络地址。结果仅反映当前检测页和系统路由。'
      ],
      peers: [], peerStates: [], timers: [], controller: null, pendingPeers: ICE_SERVERS.length,
      httpDone: false, capped: false, finished: false, resolve: resolve
    };
    activeRuns.set(state.runID, state);
    state.timers.push(setTimeout(function () {
      if (!isActive(state)) return;
      state.peerStates.forEach(function (peerState) {
        if (!peerState.done) addError(state, 'ice:' + peerState.source, 'peer_timeout', 'ICE 候选收集未在检测期限内完成');
      });
      addError(state, 'collector', 'timeout', '检测期限已到');
      finish(state, 'timeout');
    }, timeoutMs));
    startReference(state);
    ICE_SERVERS.forEach(function (server) { startPeer(state, server); });
    return promise;
  }

  function cancel(runID) {
    var state = activeRuns.get(runID);
    if (!state) return false;
    state.finished = true;
    activeRuns.delete(runID);
    cleanup(state);
    state.resolve(null);
    return true;
  }

  window.ClaudeWatchProbe = { run: run, cancel: cancel };
}());
