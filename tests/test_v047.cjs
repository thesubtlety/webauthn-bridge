const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const read = name => fs.readFileSync(path.join(root,name),'utf8');
async function testCapabilityResult(value){
  const sent=[];
  class TestURL extends URL{}
  const ctx={
    location:{href:'chrome-extension://remote/capability.html?nonce=11111111-1111-4111-8111-111111111111'},
    URL:TestURL,isSecureContext:true,PublicKeyCredential:{isUserVerifyingPlatformAuthenticatorAvailable:async()=>value},
    chrome:{runtime:{sendMessage:async payload=>{sent.push(payload);return {ok:true};}}}
  };
  vm.createContext(ctx);
  await vm.runInContext(read('remote-extension/capability.js'),ctx);
  await new Promise(resolve=>setTimeout(resolve,0));
  assert.equal(sent.length,1);
  assert.equal(sent[0].available,value);
  assert.equal(sent[0].source,'browser-api');
  assert.equal(sent[0].nonce,'11111111-1111-4111-8111-111111111111');
}
function makeTracer(){
  const outputs=[];
  const listeners={};
  const win={addEventListener(n,fn){(listeners[n]??=[]).push(fn);},
    dispatchEvent(ev){outputs.push(ev.detail);for(const fn of listeners[ev.type]||[])fn(ev);}};
  win.top=win;
  const navigator={credentials:{get:async ()=>({id:'mock'})}};
  const context={window:win,navigator,document:{readyState:'loading'},
    location:{origin:'https://login.microsoftonline.com'},
    CustomEvent:class{constructor(type,init){this.type=type;this.detail=init.detail;}},
    performance:{now:()=>Date.now()},setTimeout,Reflect,Promise};
  vm.createContext(context);
  vm.runInContext(read('remote-extension/idp-trace-main.js'),context);
  return {outputs,navigator};
}
(async()=>{
  await testCapabilityResult(true);await testCapabilityResult(false);
  const tracer=makeTracer();
  await tracer.navigator.credentials.get({publicKey:{rpId:'login.microsoft.com',allowCredentials:[{id:'PRIVATE-CREDENTIAL-ID',transports:['internal']}],userVerification:'required'},mediation:'conditional'});
  await tracer.navigator.credentials.get({publicKey:{rpId:'login.microsoft.com',extensions:{localDesktopClientOverride:{}}}});
  const starts=tracer.outputs.filter(x=>x.kind==='get-start');
  assert.equal(starts.length,2);
  assert.equal(starts[0].source,'site');assert.equal(starts[0].mediation,'conditional');
  assert.equal(starts[0].allowCount,1);
  assert.equal(starts[0].transports,'internal');
  assert.equal(starts[0].uv,'required');
  assert.equal(JSON.stringify(tracer.outputs).includes('PRIVATE-CREDENTIAL-ID'),false,
    'no credential IDs may appear in browser trace');
  assert.equal(starts[1].source,'bridge');
  assert.ok(tracer.outputs.some(x=>x.kind==='hook-ready'));
  const local=read('local-extension/background.js');
  const remote=read('remote-extension/background.js');
  assert.match(local,/kind:'uvpaa-query'/);
  assert.match(local,/completeIsUvpaaRequest\(\{requestId:job.requestId,isUvpaa:available===true\}\)/);
  assert.match(remote,/kind:'uvpaa-result'/);
  assert.match(remote,/source:measured.source/); // capability result source forwarded without fabrication
  const manifest=JSON.parse(read('remote-extension/manifest.json'));
  assert.equal(manifest.version,'1.0.5');
  const editor=read('local-extension/profiles.html');
  assert.match(editor,/id="provider"/);assert.match(editor,/id="loginUrl"/);
  assert.match(editor,/<details class="advanced"/);
  const inspector=read('remote-extension/diagnostics.html');
  assert.match(inspector,/id="enableTrace"/);assert.match(inspector,/id="probePlatform"/);
  console.log('v0.4.7 UVPAA true/false, page tracer, encrypted protocol plumbing and UI smoke tests passed');
})().catch(error=>{console.error(error);process.exitCode=1});
