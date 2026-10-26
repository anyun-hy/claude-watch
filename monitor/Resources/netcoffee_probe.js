/* Net.Coffee protocol adapter, independently implemented. API GETs use the
   native fixed-endpoint bridge; DNS images and ICE run in this WebView. */
(function () {
  'use strict';
  var active, serial = 0;
  var stuns = ['stun.l.google.com:19302','stun.cloudflare.com:3478','stun1.l.google.com:19302'];
  function handler() { return window.webkit.messageHandlers.coffeeProbe; }
  function send(x) { if (active && !active.stopped) handler().postMessage(Object.assign({runID:active.id},x)); }
  function progress(s) { var label=document.getElementById("status"); if(label)label.textContent=s; send({progress:s}); }
  function wait(ms) { return new Promise(function(resolve){var t=setTimeout(resolve,ms);active.timers.push(t);}); }
  function api(kind,query) {
    return new Promise(function(resolve,reject){
      var id=String(++serial), run=active;
      var timer=setTimeout(function(){run.pending.delete(id);reject(new Error('API timeout'));},21000);
      run.timers.push(timer);run.pending.set(id,{resolve:resolve,reject:reject,timer:timer});
      send({request:{id:id,kind:kind,query:query||''}});
    }).then(function(r){ active.receipts.push(r);if(r.status!=='complete') throw new Error(r.error||r.status);return r; });
  }
  function receive(id,r) { if(!active||active.stopped)return;var p=active.pending.get(id);if(p){clearTimeout(p.timer);active.pending.delete(id);p.resolve(r);} }
  function address(ip) { return /^[0-9a-f:.]+$/i.test(ip) && (ip.includes(':') || /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)); }
  function publicAddress(ip) {
    if(!address(ip))return false;
    if(ip.includes(':'))return /^[23]/.test(ip)&&!/^2001:db8:/i.test(ip);
    var b=ip.split('.').map(Number);return b.every(function(x){return x<=255;})&&b[0]>0&&b[0]!==10&&b[0]!==127&&b[0]<224&&!(b[0]===169&&b[1]===254)&&!(b[0]===172&&b[1]>=16&&b[1]<=31)&&!(b[0]===192&&b[1]===168)&&!(b[0]===198&&(b[1]===18||b[1]===19))&&!(b[0]===100&&b[1]>=64&&b[1]<=127);
  }
  function observe(ip,kind,source) {
    var key=ip+'|'+kind+'|'+source;if(active.observations.length>=128)throw new Error('candidate limit');
    if(!active.keys.has(key)){active.keys.add(key);active.observations.push({address:ip,kind:kind,source:source,family:ip.endsWith('.local')?null:ip.includes(':')?6:4});}
  }
  function error(stage,e){active.errors.push({stage:stage,code:'incomplete',message:String(e.message||e)});}
  async function trace(){try{var r=await api('trace',''),m=r.raw.match(/^ip=(.+)$/m);if(!m||!publicAddress(m[1].trim()))throw new Error('HTTP reference missing');observe(m[1].trim(),'http',r.sourceURL+' · 本机代理 HTTP');}catch(e){error('http',e);}}
  function image(url){return new Promise(function(resolve){var img=new Image(),done=false;active.images.push(img);function end(){if(done)return;done=true;img.onload=img.onerror=null;resolve();}img.onload=img.onerror=end;active.timers.push(setTimeout(end,3000));img.src=url;});}
  async function dns(rounds){
    var token=Array.from(crypto.getRandomValues(new Uint8Array(12))).map(function(b){return b.toString(16).padStart(2,'0');}).join('');
    active.details.push('DNS token: '+token+' · '+rounds+' 轮权威查询');
    for(var i=0;i<rounds;i++){progress('DNS 查询 '+(i+1)+' / '+rounds);await image('https://'+token+'-'+i+'.d.ip.net.coffee/pixel.gif?_='+Date.now());if(active.stopped)return;await wait(600);}
    await wait(2000);
    for(var attempt=0;attempt<3;attempt++){
      progress('读取 Net.Coffee DNS 记录 '+(attempt+1)+' / 3');
      try{var r=await api('dns',token),ips=r.data.dns_servers;
        if(!Array.isArray(ips)||!ips.every(function(x){return typeof x==='string';}))throw new Error('invalid dns_servers');
        if(ips.length>128)throw new Error('resolver limit');
        ips.forEach(function(ip){if(address(ip))observe(ip,'resolver',r.sourceURL);else error('dns','invalid resolver address');});
        if(ips.length)return;
      }catch(e){if(attempt===2)error('dns',e);}
      if(attempt<2)await wait(2000);
    }
    error('dns','原站未返回解析器；空结果不能判定无泄漏');
  }
  function ice(source){return new Promise(async function(resolve){
    if(typeof RTCPeerConnection!=='function'){error('ice:'+source,'此 WebView 没有 WebRTC 能力');resolve();return;}
    var peer,count=0,done=false,timer;
    function end(){if(done)return;done=true;clearTimeout(timer);if(!count)error('ice:'+source,'未取得公网 STUN 候选');try{peer.close();}catch(_){}resolve();}
    try{
      peer=new RTCPeerConnection({iceServers:[{urls:'stun:'+source}]});active.peers.push(peer);
      timer=setTimeout(end,8000);active.timers.push(timer);
      peer.onicecandidate=function(event){if(!event.candidate){end();return;}var c=event.candidate,f=String(c.candidate||'').trim().split(/\s+/),ip=c.address||f[4],t=c.type||f[f.indexOf('typ')+1];
        if(!ip||!t)return;if(/\.local$/i.test(ip))t='mdns';
        if(address(ip)||t==='mdns'){observe(ip,t,source);if((t==='srflx'||t==='prflx')&&publicAddress(ip))count++;}};
      peer.onicegatheringstatechange=function(){if(peer.iceGatheringState==='complete')end();};
      peer.createDataChannel('diagnostic');await peer.setLocalDescription(await peer.createOffer());
    }catch(e){error('ice:'+source,e);end();}
  });}
  async function enrich(){
    progress('补充 Net.Coffee 地址归属');
    var ips=Array.from(new Set(active.observations.map(function(o){return o.address;}).filter(publicAddress)));
    // A bound avoids unbounded third-party requests; omitted enrichment is explicit.
    if(ips.length>12)error('geoip','超过 12 个地址，部分归属未查询');
    for(var i=0;i<Math.min(12,ips.length);i+=3){await Promise.all(ips.slice(i,i+3).map(async function(ip){try{var r=await api('geoip',ip);active.observations.filter(function(o){return o.address===ip;}).forEach(function(o){o.country=r.data.country;o.region=r.data.region;o.city=r.data.city;o.isp=r.data.isp;o.geoSource=r.sourceURL;o.geoQueriedAt=r.queriedAt;});}catch(e){error('geoip:'+ip,e);}}));}
  }
  function cleanup(){if(!active)return;active.stopped=true;active.timers.forEach(clearTimeout);active.peers.forEach(function(p){try{p.close();}catch(_){}});active.images.forEach(function(i){i.onload=i.onerror=null;i.src='';});active.pending.forEach(function(p){p.reject(new Error('cancelled'));});active.pending.clear();}
  async function run(options){
    if(active)cleanup();active={id:options.runID,kind:options.kind,stopped:false,startedAt:Date.now()/1000,pending:new Map(),timers:[],peers:[],images:[],keys:new Set(),observations:[],errors:[],receipts:[],details:['Net.Coffee 公开接口；不使用站点的安全判词。','API / HTTP 经 7890；DNS 图片与 ICE 遵循当前系统路由。']};
    var own=active;
    try{progress('采集同轮 HTTP 参考和 '+(options.kind==='dns'?'DNS 查询':'ICE 候选'));await Promise.all([trace(),options.kind==='dns'?dns(options.rounds===8?8:5):Promise.all(stuns.map(ice))]);if(own.stopped)return;await enrich();}
    catch(e){if(own.stopped)return;error('collector',e);}
    if(own.stopped||active!==own)return;
    var payload={kind:own.kind,status:own.errors.length?'partial':'complete',startedAt:own.startedAt,finishedAt:Date.now()/1000,scope:own.kind==='dns'?'本机 WebView 查询 → Net.Coffee 权威 DNS 记录':'当前检测 WebView · 原站 STUN 列表',observations:own.observations,errors:own.errors,contextChanged:false,details:own.details,externalJSON:JSON.stringify(own.receipts)};
    send({payload:payload});cleanup();
  }
  window.NetCoffeeProbe={run:run,receive:receive,cancel:cleanup};
}());
