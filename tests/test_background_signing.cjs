const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const {webcrypto}=require('node:crypto');
const root=path.resolve(__dirname,'..');
const read=file=>fs.readFileSync(path.join(root,file),'utf8');
const tick=()=>new Promise(resolve=>setImmediate(resolve));
function harness({result={ok:true,pageOrigin:'https://gitlab.com',credential:{}},hold=false,missingTab=false,creationDelay=false,anchor={left:100,top:50,width:1440,height:900}}={}){
  const calls=[],messages=[];const stored={};let replyMain,replyCreate;
  const event=()=>({listeners:[],addListener(fn){this.listeners.push(fn);},fire(id){for(const fn of this.listeners)fn(id);}});
  const tabs={onRemoved:event(),async create(options){calls.push(['tab',options]);return {id:21};},async query(){return missingTab?[]:[{id:22}];},async remove(id){calls.push(['removeTab',id]);}};
  const windows={onRemoved:event(),async getLastFocused(){if(!anchor)throw Error('No normal window');return anchor;},async create(options){calls.push(['window',options]);if(creationDelay)await new Promise(r=>replyCreate=r);return {id:31,tabs:missingTab?[]:[{id:22}]};},async remove(id){calls.push(['removeWindow',id]);}};
  const chrome={tabs,windows,storage:{local:{async get(keys){return Object.fromEntries(keys.map(k=>[k,stored[k]]));},async set(data){Object.assign(stored,data);}}},
    permissions:{async contains(){return true;}},alarms:{onAlarm:event()},runtime:{onMessage:event(),getURL:f=>'chrome-extension://test/'+f},
    scripting:{async getRegisteredContentScripts(){return [];},async executeScript(options){calls.push(['script',options.world]);if(options.world==='MAIN'){if(hold)return new Promise(r=>replyMain=r);return [{result}];}return [];}}};
  const ctx={chrome,crypto:webcrypto,URL,console,WebSocket:{OPEN:1},
    setTimeout:(fn,ms)=>{const t=setTimeout(fn,ms);t.unref();return t;},clearTimeout,setInterval,clearInterval,
    BridgeDiag:{async log(){},async snapshot(){return [];},async clear(){}},BridgeIndicator:{update(){}},
    BridgeValidate:{async assertion(){calls.push(['validate']);}},runSiteCeremony(){},installPageStageRelay(){},importScripts(){}};
  vm.createContext(ctx);
  vm.runInContext(read('remote-extension/profiles.js'),ctx);
  vm.runInContext(read('remote-extension/signing-page.js'),ctx);
  vm.runInContext(read('remote-extension/background.js'),ctx);
  ctx.captureResult=packet=>messages.push(packet);
  vm.runInContext('send=async packet=>captureResult(packet);waitForOrigin=async()=>({actualOrigin:"https://gitlab.com"});',ctx);
  const run=code=>vm.runInContext(code,ctx);
  return {ctx,calls,messages,chrome,run,
    async start({background=true,manual=false,auto=true}={}){
      const r=await run(`handleCommand({action:'saveProfile',profile:{name:'GitLab',origin:'https://gitlab.com',pageUrl:'https://gitlab.com/users/sign_in',rpId:'gitlab.com'}})`);
      ctx.profileId=r.profile.id;
      run(`pending.set('request',{id:'request',rp:'gitlab.com',options:{challenge:'test'},status:'waiting',started:Date.now(),tabId:null,windowId:null,signingWindowId:null,timer:null,backgroundSigning:${background},forceManual:${manual},streamlinedAuto:${auto}});`);
      assert.equal((await run("approve('request',profileId)")).ok,true);
      for(let i=0;i<10;i++)await tick();
    },
    release(){replyMain?.([{result}]);},releaseCreation(){replyCreate?.();}
  };
}
(async()=>{
  // The default preserves the existing foreground flow.
  let h=harness();await h.start({background:false});
  assert.equal(h.calls.filter(c=>c[0]==='window').length,0);
  assert.equal(h.calls.find(c=>c[0]==='tab')[1].active,true);
  assert.equal(h.messages.at(-1).ok,true);assert(h.calls.some(c=>c[0]==='removeTab'&&c[1]===21));
  // Optional mode uses only its own unfocused window and validates before return.
  h=harness();await h.start();
  const options=h.calls.find(c=>c[0]==='window')[1];
  assert.equal(options.width,240);assert.equal(options.height,160);assert.equal(options.left,1292);assert.equal(options.top,782);assert.equal(options.state,undefined);
  assert.equal(options.focused,false);assert.equal(options.type,'popup');assert.equal(options.url,'https://gitlab.com/users/sign_in');
  assert.equal(h.calls.filter(c=>c[0]==='tab').length,0);
  assert(h.calls.some(c=>c[0]==='validate'));assert(h.calls.some(c=>c[0]==='removeWindow'&&c[1]===31));
  assert.equal(h.messages.at(-1).ok,true);
  // Preserve monitor coordinates and allow fallback without an anchor.
  h=harness({anchor:{left:-1440,top:0,width:1440,height:900}});await h.start();
  let placement=h.calls.find(c=>c[0]==='window')[1];assert.equal(placement.left,-248);assert.equal(placement.top,732);
  h=harness({anchor:{left:0,top:0,width:200,height:200}});await h.start();
  placement=h.calls.find(c=>c[0]==='window')[1];assert.equal(placement.width,184);assert.equal(placement.left,8);
  h=harness({anchor:null});await h.start();
  placement=h.calls.find(c=>c[0]==='window')[1];assert.equal(placement.width,240);assert.equal(placement.left,undefined);assert.equal(h.messages.at(-1).ok,true);
  // Browser refusal closes the window and never launches a foreground retry.
  h=harness({result:{ok:false,name:'NotAllowedError',phase:'get',error:'Document is not focused'}});await h.start();
  assert.match(h.messages.at(-1).error,/Turn off background signing/);
  assert.equal(h.calls.filter(c=>c[0]==='window').length,1);assert.equal(h.calls.filter(c=>c[0]==='tab').length,0);
  assert(h.calls.some(c=>c[0]==='removeWindow'));
  // Explicit manual approval must keep its click target visible.
  h=harness();await h.start({manual:true});assert.equal(h.calls.find(c=>c[0]==='tab')[1].active,true);
  h=harness();await h.start({auto:false});assert.equal(h.calls.find(c=>c[0]==='tab')[1].active,true);
  // Cancellation during an outstanding ceremony releases only the owned window.
  h=harness({hold:true});await h.start();await h.run("finish('request',{},false)");h.release();await tick();
  assert.equal(h.messages.length,0);assert(h.calls.some(c=>c[0]==='removeWindow'&&c[1]===31));
  // Late window creation after cancellation cannot leave an orphan.
  h=harness({creationDelay:true});await h.start();await h.run("finish('request',{},false)");h.releaseCreation();await tick();await tick();
  assert(h.calls.some(c=>c[0]==='removeWindow'&&c[1]===31));assert.equal(h.calls.filter(c=>c[0]==='script').length,0);
  // Closing the temporary window ends the pending request.
  h=harness({hold:true});await h.start();h.chrome.windows.onRemoved.fire(31);await tick();h.release();await tick();
  assert.match(h.messages.at(-1).error,/Signing window closed/);assert.equal(h.run('pending.size'),0);
  // A malformed create response also cleans up the newly allocated window.
  h=harness({missingTab:true});await h.start();assert(h.calls.some(c=>c[0]==='removeWindow'&&c[1]===31));
  assert.equal(h.messages.at(-1).ok,false);
  console.log('Background signing: unfocused creation, foreground default/manual mode, validation, refusal, cancellation races, window closure, and cleanup passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
