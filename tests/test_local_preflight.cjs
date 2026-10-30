const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const {webcrypto}=require('node:crypto');
const root=path.resolve(__dirname,'..');
async function check({permission=true,url='https://gitlab.com/users/sign_in',secure=true,injectionFails=false,related=false,listed=true,closed=false}={}){
  const calls=[];
  const origin=related?'https://login.example.net':'https://gitlab.com';
  const page={location:{origin},window:{isSecureContext:secure,PublicKeyCredential:{parseRequestOptionsFromJSON(){}}},navigator:{credentials:{get(){throw Error('Preflight must not authenticate');}}}};
  page.window.top=page.window;vm.createContext(page);
  const ctx={crypto:webcrypto,URL,AbortSignal,setTimeout,console,
    chrome:{permissions:{async contains(){return permission;}},
      tabs:{async create(options){calls.push(['open',options]);return {id:7};},async get(){if(closed)throw Error('Tab closed');return {status:'complete',url:related?origin+'/':url};},async remove(id){calls.push(['close',id]);}},
      scripting:{async executeScript({func}){if(injectionFails)throw Error('Injection denied');return [{result:vm.runInContext('('+func.toString()+')()',page)}];}}},
    fetch:async()=>{calls.push(['well-known']);return {ok:true,status:200,headers:{get:()=> 'application/json'},async json(){return {origins:listed?[origin]:[]};}};}};
  vm.createContext(ctx);
  for(const name of ['profiles.js','preflight.js'])vm.runInContext(fs.readFileSync(path.join(root,'local-extension',name),'utf8'),ctx);
  const report=await ctx.BridgePreflight.run({name:'test',origin,pageUrl:related?origin+'/':url,rpId:related?'example.com':'gitlab.com',allowRelatedOrigins:related});
  return {report,calls};
}
(async()=>{
  let t=await check();assert.equal(t.report.ok,true);assert.equal(t.report.checkedOn,'local');assert.deepEqual(t.calls.map(x=>x[0]),['open','close']);
  t=await check({permission:false});assert.equal(t.report.ok,false);assert.match(t.report.error,/Local site permission/);assert.equal(t.calls.length,0);
  t=await check({secure:false});assert.equal(t.report.ok,false);assert.equal(t.calls.at(-1)[0],'close');
  t=await check({injectionFails:true});assert.match(t.report.error,/Injection denied/);assert.equal(t.calls.at(-1)[0],'close');
  t=await check({url:'https://other.example/'});assert.equal(t.report.ok,false);assert.equal(t.calls.at(-1)[0],'close');
  t=await check({closed:true});assert.match(t.report.error,/Tab closed/);assert.equal(t.calls.at(-1)[0],'close');
  t=await check({related:true});assert.equal(t.report.ok,true,t.report.error);assert.equal(t.report.relatedOrigin.checked,true);assert(t.calls.some(x=>x[0]==='well-known'));
  t=await check({related:true,listed:false});assert.equal(t.report.ok,false);assert.match(t.report.error,/does not list/);assert.equal(t.calls.at(-1)[0],'close');
  console.log('Local preflight: page readiness, local permissions, redirects, failed injection, cleanup, related-origin checks, and no authenticator operation passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
