const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const {webcrypto}=require('node:crypto');
const root=path.resolve(__dirname,'..');
const sockets={};
const sent=[];
const readLocal=name=>fs.readFileSync(path.join(root,'local-extension',name),'utf8');
function browser(role,initial={}){
  let listener;const stored={...initial};const pages=[];let siteAccess=true;const events=()=>({listeners:[],addListener(fn){this.listeners.push(fn);},fire(value){for(const fn of this.listeners)fn(value);}});
  class Socket{
    static OPEN=1;static CONNECTING=0;
    constructor(url){this.readyState=1;this.role=new URL(url).searchParams.get('role');sockets[this.role]=this;}
    send(data){if(data!=='ping')sent.push({role:this.role,packet:JSON.parse(data)});const peer=sockets[this.role==='local'?'remote':'local'];if(data==='ping')return;queueMicrotask(()=>peer?.onmessage?.({data}));}
    close(){this.readyState=3;}
  }
  const chrome={storage:{local:{async get(keys){return Object.fromEntries(keys.map(k=>[k,stored[k]]));},async set(data){Object.assign(stored,data);}}},
    runtime:{id:role,getURL:f=>'chrome-extension://'+role+'/'+f,onMessage:{addListener(fn){listener=fn;}}},
    webAuthenticationProxy:{async attach(){},async detach(){},async completeGetRequest(){},onGetRequest:events(),onCreateRequest:events(),onRequestCanceled:events(),onIsUvpaaRequest:events()},
    permissions:{async contains({origins}){return siteAccess||!origins.some(x=>x.includes("gitlab.com"));}},alarms:{async create(){},onAlarm:events()},
    tabs:{onRemoved:events(),async create(options){pages.push(options);return {id:44};},async get(){return {status:"complete",url:"https://gitlab.com/users/sign_in"};},async remove(){},async query(){return [{url:"https://gitlab.com/users/sign_in"}];}},windows:{onRemoved:events()},
    scripting:{async getRegisteredContentScripts(){return [];},async executeScript(){return [{result:{origin:"https://gitlab.com",secure:true,topLevel:true,hasGet:true,hasParser:true}}];}}};
  const ctx={chrome,crypto:webcrypto,URL,WebSocket:Socket,console,AbortController,atob,btoa,
    setTimeout:(fn,ms)=>{const t=setTimeout(fn,ms);t.unref();return t;},clearTimeout,
    setInterval:(fn,ms)=>{const t=setInterval(fn,ms);t.unref();return t;},clearInterval,
    fetch:async()=>({status:200,text:async()=>'ok'}),
    BridgeDiag:{async log(){},async snapshot(){return [];},async clear(){}},
    BridgeIndicator:{update(){},state(){return 'green';},healthUrl:()=> 'https://relay.test/health',permissionPattern:()=> 'https://relay.test/*'},
    BridgeCrypto:{async init(){return {room:'test'};},relayURL:(url,room,r)=>'wss://relay.test/?role='+r,async seal(c,obj){return JSON.stringify(obj);},async open(c,str){return JSON.parse(str);}},
    importScripts(){}};
  vm.createContext(ctx);
  if(role==='local'){
    vm.runInContext(readLocal('profiles.js'),ctx);vm.runInContext(readLocal('preflight.js'),ctx);
  }
  if(role==='remote')vm.runInContext(fs.readFileSync(path.join(root,'remote-extension/profiles.js'),'utf8'),ctx);
  vm.runInContext(fs.readFileSync(path.join(root,role+'-extension/background.js'),'utf8'),ctx);
  return {ctx,stored,chrome,pages,setSiteAccess(value){siteAccess=value;},ask:msg=>new Promise(resolve=>listener(msg,{},resolve))};
}
(async()=>{
  const local=browser('local'),remote=browser('remote');
  assert.equal((await local.ask({action:'status'})).backgroundSigning,false);
  assert.match((await local.ask({action:'listProfiles'})).error,/Connect both/);
  for(const b of [local,remote])assert.equal((await b.ask({action:'enable',relayUrl:'wss://relay.test/',pairingKey:'test'})).ok,true);
  for(const socket of Object.values(sockets))await socket.onmessage({data:JSON.stringify({type:'peer',online:true})});
  remote.setSiteAccess(false);
  const save=await local.ask({action:'saveProfile',profile:{name:'GitLab',origin:'https://gitlab.com',pageUrl:'https://gitlab.com/users/sign_in',rpId:'gitlab.com'}});
  assert.equal(save.ok,true,save.error);
  assert.equal(save.missingPermissions[0],'https://gitlab.com/*');
  assert.equal((await remote.ask({action:'originPreflight',profileId:save.profile.id})).error,'Unknown action');
  const preflight=await local.ask({action:'originPreflight',profileId:save.profile.id});
  assert.equal(preflight.ok,true,preflight.error);assert.equal(preflight.checkedOn,'local');
  assert.equal(local.pages.length,1);assert.equal(remote.pages.length,0);
  assert.equal(sent.some(p=>p.packet.kind==='manage-request'&&p.packet.command.action==='originPreflight'),false);

  remote.setSiteAccess(true);
  assert.equal(remote.stored.profiles[0].rpId,'gitlab.com');
  assert.equal(local.stored.profiles,undefined,'signing rules are enforced and stored by the remote browser');
  const list=await local.ask({action:'listProfiles'});assert.equal(list.profiles.length,1);
  const relation=await local.ask({action:'relatedOriginCheck',profileId:save.profile.id});assert.equal(relation.ok,true);
  const hint=await local.ask({action:'setAuthenticatorPreference',preference:'security-key'});
  assert.equal(hint.ok,true);assert.equal(local.stored.authenticatorPreference,'security-key');
  assert.equal((await local.ask({action:'setBackgroundSigning',enabled:true})).backgroundSigning,true);
  assert.equal(local.stored.backgroundSigning,true);
  assert.match((await local.ask({action:'setBackgroundSigning',enabled:'true'})).error,/must be true or false/);
  local.chrome.webAuthenticationProxy.onGetRequest.fire({requestId:123,requestDetailsJson:JSON.stringify({challenge:'dGVzdA',rpId:'gitlab.com'})});
  for(let i=0;i<50&&!sent.some(p=>p.role==='local'&&p.packet.kind==='get');i++)await new Promise(r=>setTimeout(r,5));
  assert.equal(sent.find(p=>p.role==='local'&&p.packet.kind==='get').packet.backgroundSigning,true,'setting crosses the encrypted request channel');
  assert.equal((await local.ask({action:'setBackgroundSigning',enabled:false})).backgroundSigning,false);
  assert.equal(local.stored.backgroundSigning,false);
  await local.ask({action:'deleteProfile',id:save.profile.id});
  assert.equal((await local.ask({action:'listProfiles'})).profiles.length,0);
  assert.equal(JSON.parse(fs.readFileSync(path.join(root,'local-extension/manifest.json'))).permissions.includes('webAuthenticationProxy'),true);
  assert.equal(JSON.parse(fs.readFileSync(path.join(root,'remote-extension/manifest.json'))).permissions.includes('webAuthenticationProxy'),false);
  const manifest=JSON.parse(fs.readFileSync(path.join(root,'remote-extension/manifest.json')));
  assert.deepEqual(manifest.host_permissions,['https://*/*']);
  assert.equal(manifest.optional_host_permissions,undefined);
  const restored=browser('local',{backgroundSigning:true});
  assert.equal((await restored.ask({action:'status'})).backgroundSigning,true,'preference restored before handling messages');
  console.log('Role reversal: local proxy/preferences, encrypted profile CRUD, remote rule enforcement, and disconnected management passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
