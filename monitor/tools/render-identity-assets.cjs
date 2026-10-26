// Deterministic build-time rendering; no runtime network loading.
const fs=require('node:fs'),path=require('node:path');
const sharp=require('/Users/anyun/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/sharp');
const root=path.resolve(__dirname,'../Resources/Identity');
(async()=>{
 for(const [name,extension] of [['claude','webp'],['chatgpt','png'],['cloudflare','webp']]){
  const input=path.join(root,'sources',name+'.'+extension);console.log(name,await sharp(input).metadata());
  await sharp(input).resize(192,192,{fit:'contain',background:{r:0,g:0,b:0,alpha:0}}).png().toFile(path.join(root,'brands',name+'.png'));
 }
 for(const name of fs.readdirSync(path.join(root,'sources')).filter(n=>/^flag-[a-z]{2}\.svg$/.test(n))){
  await sharp(path.join(root,'sources',name)).resize(72,54).png().toFile(path.join(root,'flags',name.slice(5,-4)+'.png'));
 }
 const tiles=await Promise.all(['claude','chatgpt','cloudflare'].map(async(name,i)=>({input:await sharp(path.join(root,'brands',name+'.png')).resize(72,72).png().toBuffer(),left:24+i*120,top:24})));
 await sharp({create:{width:384,height:120,channels:4,background:'#f3f5f7'}}).composite(tiles).png().toFile('/private/tmp/watch-identity-assets.png');
 console.log('rendered brands and flags');
})().catch(e=>{console.error(e);process.exit(1)});
