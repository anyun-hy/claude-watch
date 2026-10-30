/* Net.Coffee protocol adapter. API GETs use the fixed native bridge; DNS
   images and ICE run in this WebView. One monotonic deadline covers the whole
   result, so a slow DNS retry cannot outlive the native worker's watchdog. */
(function () {
  'use strict';
  var active, serial = 0;
  var stuns = ['stun.l.google.com:19302','stun.cloudflare.com:3478','stun1.l.google.com:19302'];
  var MAX_BUDGET_MS = 70000, RETURN_RESERVE_MS = 1000, MIN_API_MS = 1000, API_CAP_MS = 21000;
  var phaseNames = {http:true,dns_images:true,dns_records:true,geoip:true,ice:true,collector:true};
  function handler() { return window.webkit.messageHandlers.coffeeProbe; }
  function clock() { return typeof performance !== 'undefined' && performance.now ? performance.now() : Date.now(); }
  function elapsed(run) { return Math.max(0, Math.floor(clock() - run.startedClock)); }
  function remaining(run) { return Math.max(0, Math.floor(run.deadline - clock())); }
  function sendFor(run,x) { if(active === run && !run.stopped) handler().postMessage(Object.assign({runID:run.id},x)); }
  function stage(run,name,label) {
    run.phase = phaseNames[name] ? name : 'collector';
    var node=document.getElementById('status'); if(node) node.textContent=label;
    sendFor(run,{progress:label,phase:run.phase,elapsedMs:elapsed(run)});
  }
  function timeoutError() { var e=new Error('budget timeout'); e.budget=true; return e; }
  function ensure(run,phase,need) {
    run.phase = phase;
    if(run.stopped || remaining(run) <= (need || RETURN_RESERVE_MS)) { run.timedOut=true; throw timeoutError(); }
  }
  function wait(run,ms,phase) {
    ensure(run,phase,ms + RETURN_RESERVE_MS);
    return new Promise(function(resolve){var t=setTimeout(resolve,ms);run.timers.push(t);});
  }
  function api(run,kind,query,phase,cap) {
    ensure(run,phase,MIN_API_MS + RETURN_RESERVE_MS);
    var timeout=Math.min(API_CAP_MS, remaining(run)-RETURN_RESERVE_MS);
    if(timeout < MIN_API_MS) { run.timedOut=true; return Promise.reject(timeoutError()); }
    return new Promise(function(resolve,reject){
      var id=String(++serial);
      var timer=setTimeout(function(){
        if(run.pending.delete(id)) {
          sendFor(run,{cancelRequest:{id:id},phase:phase,elapsedMs:elapsed(run)});
          var e=new Error('API timeout'); e.timeout=true; reject(e);
        }
      },timeout);
      run.timers.push(timer);run.pending.set(id,{resolve:resolve,reject:reject,timer:timer});
      sendFor(run,{request:{id:id,kind:kind,query:query||'',timeoutMs:String(Math.floor(timeout))},phase:phase,elapsedMs:elapsed(run)});
    }).then(function(r){
      if(active!==run || run.stopped) throw new Error('cancelled');
      run.receipts.push(r);
      if(r.status!=='complete') { var e=new Error(r.error||r.status); if(r.status==='timeout') e.timeout=true; throw e; }
      return r;
    });
  }
  function receive(id,r) { if(!active||active.stopped)return;var p=active.pending.get(id);if(p){clearTimeout(p.timer);active.pending.delete(id);p.resolve(r);} }
  function address(ip) { return /^[0-9a-f:.]+$/i.test(ip) && (ip.includes(':') || /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)); }
  function publicAddress(ip) {
    if(!address(ip))return false;
    if(ip.includes(':'))return /^[23]/.test(ip)&&!/^2001:db8:/i.test(ip);
    var b=ip.split('.').map(Number);return b.every(function(x){return x<=255;})&&b[0]>0&&b[0]!==10&&b[0]!==127&&b[0]<224&&!(b[0]===169&&b[1]===254)&&!(b[0]===172&&b[1]>=16&&b[1]<=31)&&!(b[0]===192&&b[1]===168)&&!(b[0]===198&&(b[1]===18||b[1]===19))&&!(b[0]===100&&b[1]>=64&&b[1]<=127);
  }
  function observe(run,ip,kind,source) {
    var key=ip+'|'+kind+'|'+source;if(run.observations.length>=128)throw new Error('candidate limit');
    if(!run.keys.has(key)){run.keys.add(key);run.observations.push({address:ip,kind:kind,source:source,family:ip.endsWith('.local')?null:ip.includes(':')?6:4});}
  }
  function error(run,stageName,e,code){
    run.errors.push({stage:phaseNames[stageName]?stageName:'collector',code:code || (e&&e.budget?'timeout':'incomplete'),message:String((e&&e.message)||e)});
  }
  async function traceOnce(run){var r=await api(run,'trace','','http'),m=r.raw.match(/^ip=(.+)$/m);if(!m||!publicAddress(m[1].trim()))throw new Error('HTTP reference missing');observe(run,m[1].trim(),'http',r.sourceURL+' · 本机代理 HTTP');}
  async function trace(run){
    stage(run,'http','读取同轮 HTTP 参考');
    try{await traceOnce(run);return;}catch(first){
      // Retry a transient WebRTC HTTP timeout once, within the original
      // deadline. Re-sample ICE as well and retain the first candidates: an
      // observed mismatch or any other failed probe must never be hidden.
      if(run.kind==='webrtc' && first.timeout && !first.budget && !run.stopped && remaining(run)>9000){
        run.details.push('HTTP 参考首次超时，已重新采集 HTTP 与 ICE；保留此前候选用于比较。');
        sendFor(run,{diagnostic:'http_retry',phase:'http',elapsedMs:elapsed(run)});
        stage(run,'http','HTTP 参考超时，正在重新采集');
        var results=await Promise.all([traceOnce(run).then(function(){return null;},function(e){return e;}),Promise.all(stuns.map(function(source){return ice(run,source);}))]);
        if(!results[0])return;
        first=results[0];
      }
      error(run,'http',first,first.timeout||first.budget?'timeout':undefined);
    }
  }
  function image(run,url){
    ensure(run,'dns_images',3000 + RETURN_RESERVE_MS);
    return new Promise(function(resolve){var img=new Image(),done=false;run.images.push(img);function end(){if(done)return;done=true;img.onload=img.onerror=null;resolve();}img.onload=img.onerror=end;run.timers.push(setTimeout(end,3000));img.src=url;});
  }
  async function dns(run,rounds){
    var token=Array.from(crypto.getRandomValues(new Uint8Array(12))).map(function(b){return b.toString(16).padStart(2,'0');}).join('');
    run.details.push('DNS 权威查询 · '+rounds+' 轮');
    for(var i=0;i<rounds;i++){stage(run,'dns_images','DNS 查询 '+(i+1)+' / '+rounds);await image(run,'https://'+token+'-'+i+'.d.ip.net.coffee/pixel.gif?_='+Date.now());if(run.stopped)return;await wait(run,600,'dns_images');}
    await wait(run,2000,'dns_records');
    for(var attempt=0;attempt<3;attempt++){
      stage(run,'dns_records','读取 Net.Coffee DNS 记录 '+(attempt+1)+' / 3');
      try{var r=await api(run,'dns',token,'dns_records'),ips=r.data.dns_servers;
        if(!Array.isArray(ips)||!ips.every(function(x){return typeof x==='string';}))throw new Error('invalid dns_servers');
        if(ips.length>128)throw new Error('resolver limit');
        ips.forEach(function(ip){if(address(ip))observe(run,ip,'resolver',r.sourceURL);else error(run,'dns_records','invalid resolver address');});
        if(ips.length)return;
      }catch(e){if(e.budget){error(run,'dns_records',e,'timeout');throw e;}if(attempt===2)error(run,'dns_records',e,e.timeout?'timeout':undefined);}
      if(attempt<2)await wait(run,2000,'dns_records');
    }
    error(run,'dns_records','原站未返回解析器；空结果不能判定无泄漏');
  }
  function ice(run,source){return new Promise(async function(resolve){
    stage(run,'ice','采集 ICE 候选');
    if(typeof RTCPeerConnection!=='function'){error(run,'ice','此 WebView 没有 WebRTC 能力');resolve();return;}
    var peer,count=0,done=false,timer;
    function end(){if(done)return;done=true;clearTimeout(timer);if(!count)error(run,'ice','未取得公网 STUN 候选');try{peer.close();}catch(_){}resolve();}
    try{
      ensure(run,'ice',8000 + RETURN_RESERVE_MS);
      peer=new RTCPeerConnection({iceServers:[{urls:'stun:'+source}]});run.peers.push(peer);
      timer=setTimeout(end,Math.min(8000,remaining(run)-RETURN_RESERVE_MS));run.timers.push(timer);
      peer.onicecandidate=function(event){if(!event.candidate){end();return;}var c=event.candidate,f=String(c.candidate||'').trim().split(/\s+/),ip=c.address||f[4],t=c.type||f[f.indexOf('typ')+1];
        if(!ip||!t)return;if(/\.local$/i.test(ip))t='mdns';
        if(address(ip)||t==='mdns'){observe(run,ip,t,source);if((t==='srflx'||t==='prflx')&&publicAddress(ip))count++;}};
      peer.onicegatheringstatechange=function(){if(peer.iceGatheringState==='complete')end();};
      peer.createDataChannel('diagnostic');await peer.setLocalDescription(await peer.createOffer());
    }catch(e){error(run,'ice',e,e.budget?'timeout':undefined);end();}
  });}
  async function enrich(run){
    stage(run,'geoip','补充 Net.Coffee 地址归属');
    var ips=Array.from(new Set(run.observations.map(function(o){return o.address;}).filter(publicAddress)));
    if(ips.length>12)error(run,'geoip','超过 12 个地址，部分归属未查询');
    for(var i=0;i<Math.min(12,ips.length);i+=3){
      if(remaining(run)<=MIN_API_MS+RETURN_RESERVE_MS){error(run,'geoip',timeoutError(),'timeout');return;}
      await Promise.all(ips.slice(i,i+3).map(async function(ip){try{var r=await api(run,'geoip',ip,'geoip');run.observations.filter(function(o){return o.address===ip;}).forEach(function(o){o.country=r.data.country;o.region=r.data.region;o.city=r.data.city;o.isp=r.data.isp;o.geoSource=r.sourceURL;o.geoQueriedAt=r.queriedAt;});}catch(e){error(run,'geoip',e,e.timeout||e.budget?'timeout':undefined);}}));
    }
  }
  function cleanup(run){if(!run||run.stopped)return;run.pending.forEach(function(p,id){sendFor(run,{cancelRequest:{id:id},phase:run.phase,elapsedMs:elapsed(run)});});run.stopped=true;run.timers.forEach(clearTimeout);run.peers.forEach(function(p){try{p.close();}catch(_){}});run.images.forEach(function(i){i.onload=i.onerror=null;i.src='';});run.pending.forEach(function(p){p.reject(new Error('cancelled'));});run.pending.clear();}
  function publish(run){
    if(run.published || run.stopped || active!==run)return;
    run.published=true;
    var payload={kind:run.kind,status:run.timedOut?'timeout':(run.errors.length?'partial':'complete'),startedAt:run.startedAt,finishedAt:Date.now()/1000,scope:run.kind==='dns'?'本机 WebView 查询 → Net.Coffee 权威 DNS 记录':'当前检测 WebView · 原站 STUN 列表',observations:run.observations,errors:run.errors,contextChanged:false,details:run.details,externalJSON:JSON.stringify(run.receipts),phase:run.phase,elapsedMs:elapsed(run)};
    sendFor(run,{payload:payload,phase:run.phase,elapsedMs:elapsed(run)});
  }
  async function run(options){
    if(active)cleanup(active);
    var requested=Number(options&&options.budgetMs);var budget=Number.isFinite(requested)&&requested>0?Math.min(Math.floor(requested),MAX_BUDGET_MS):MAX_BUDGET_MS;
    active={id:options.runID,kind:options.kind,stopped:false,published:false,startedAt:Date.now()/1000,startedClock:clock(),deadline:clock()+budget,phase:'collector',timedOut:false,pending:new Map(),timers:[],peers:[],images:[],keys:new Set(),observations:[],errors:[],receipts:[],details:['Net.Coffee 公开接口；不使用站点的安全判词。','API / HTTP 经 7890；DNS 图片与 ICE 遵循当前系统路由。']};
    var own=active;
    own.timers.push(setTimeout(function(){if(active!==own||own.stopped||own.published)return;own.timedOut=true;error(own,own.phase,timeoutError(),'timeout');publish(own);cleanup(own);},budget));
    try{stage(own,'collector','采集同轮 HTTP 参考和 '+(options.kind==='dns'?'DNS 查询':'ICE 候选'));await Promise.all([trace(own),options.kind==='dns'?dns(own,options.rounds===8?8:5):Promise.all(stuns.map(function(source){return ice(own,source);} ))]);if(own.stopped)return;await enrich(own);}
    catch(e){if(own.stopped)return;own.timedOut=own.timedOut||!!e.budget;error(own,own.phase,e,e.budget?'timeout':undefined);}
    if(own.stopped||active!==own)return;
    publish(own);cleanup(own);
  }
  window.NetCoffeeProbe={run:run,receive:receive,cancel:function(){cleanup(active);}};
}());
