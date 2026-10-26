const vm=require('node:vm'),fs=require('node:fs'),assert=require('node:assert/strict');
const code=fs.readFileSync(__dirname+'/../Resources/netcoffee_probe.js','utf8');
async function run(kind,{empty=false,missingHTTP=false,rtcMissing=false,apiFailure=false}={}) {
 let context,done,requests=[],images=[];const result=new Promise(r=>done=r);
 const timer=(f,ms)=>setTimeout(f,Math.min(ms,20));
 class Image {set src(v){if(!v)return;images.push(v);queueMicrotask(()=>this.onload&&this.onload());}}
 class Peer {constructor(){this.iceGatheringState='new';}createDataChannel(){}createOffer(){return Promise.resolve({});}setLocalDescription(){queueMicrotask(()=>{this.onicecandidate({candidate:{address:'8.8.4.4',type:'srflx'}});this.onicecandidate({candidate:null});});return Promise.resolve();}close(){}}
 context=vm.createContext({document:{getElementById(){return null;}},console,URL,Map,Set,Uint8Array,Array,Math,Date,Promise,Image,setTimeout:timer,clearTimeout,crypto:require('node:crypto').webcrypto,RTCPeerConnection:rtcMissing?undefined:Peer,window:{webkit:{messageHandlers:{coffeeProbe:{postMessage(m){
  if(m.payload){done(m.payload);return;}if(!m.request)return;requests.push(m.request);
  let r={kind:m.request.kind,status:'complete',httpStatus:200,query:m.request.query,sourceURL:'https://ip.net.coffee/api/'+m.request.kind,queriedAt:1,finishedAt:2,raw:'{}',data:{}};
  if(apiFailure){r.status='timeout';r.error='fixture timeout';}
  if(r.kind==='trace')r.raw=missingHTTP?'error=missing':'ip=8.8.4.4\n';
  if(r.kind==='dns')r.data={dns_servers:empty?[]:['8.8.8.8']};
  if(r.kind==='geoip')r.data={country:'United States',city:'Mountain View',isp:'Google'};
  queueMicrotask(()=>context.window.NetCoffeeProbe.receive(m.request.id,r));
 }}}}}});vm.runInContext(code,context);context.window.NetCoffeeProbe.run({kind,runID:'fixture',rounds:5});
 const p=await Promise.race([result,new Promise((_,rej)=>setTimeout(()=>rej(Error('test timeout')),3000))]);return {p,requests,images};
}
(async()=>{
 let r=await run('dns');assert.equal(r.p.status,'complete');assert.equal(r.images.length,5);assert(r.images.every(x=>/^https:\/\/[a-f0-9]{24}-[0-4]\.d\.ip\.net\.coffee\//.test(x)));assert.equal(r.p.observations.find(x=>x.kind==='resolver').isp,'Google');assert(JSON.parse(r.p.externalJSON).some(x=>x.kind==='dns'));
 r=await run('dns',{empty:true});assert.equal(r.p.status,'partial');assert(r.p.errors.some(x=>x.stage==='dns'));assert.equal(r.requests.filter(x=>x.kind==='dns').length,3);
 r=await run('webrtc');assert.equal(r.p.status,'complete');assert.equal(r.p.observations.filter(x=>x.kind==='srflx').length,3);
 r=await run('webrtc',{missingHTTP:true});assert.equal(r.p.status,'partial');assert(r.p.errors.some(x=>x.stage==='http'));
 r=await run('webrtc',{rtcMissing:true});assert.equal(r.p.status,'partial');assert.equal(r.p.errors.filter(x=>x.stage.startsWith('ice:')).length,3);
 r=await run('dns',{apiFailure:true});assert.equal(r.p.status,'partial');assert(r.p.errors.some(x=>x.stage==='http'));
 console.log('NetCoffeeProbe: 6 isolated protocol scenarios passed; no real network');
})().catch(e=>{console.error(e);process.exitCode=1;});
