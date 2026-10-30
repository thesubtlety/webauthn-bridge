/* global BridgeCrypto, BridgeDiag */
importScripts('crypto.js','diag.js','indicator.js','profiles.js','preflight.js');
let preflightRunning=false;
const proxy = chrome.webAuthenticationProxy;
const pending = new Map();
const pings = new Map();
const managementJobs=new Map();
async function manageRemote(command){
  if(!enabled||!connected()||!peerOnline)return {error:'Connect both extensions before managing remote signing profiles'};
  const id=crypto.randomUUID();
  return new Promise(resolve=>{
    const timer=setTimeout(()=>{managementJobs.delete(id);resolve({error:'Remote management timed out; check the remote extension and site permissions'});},75000);
    managementJobs.set(id,{resolve,timer});
    send({kind:'manage-request',id,command}).catch(e=>{clearTimeout(timer);managementJobs.delete(id);resolve({error:e.message});});
  });
}
const uvpaaQueries=new Map();
let lastPlatformResult=null;
async function settleUvpaa(id,available,source){
  const job=uvpaaQueries.get(id);if(!job)return;
  uvpaaQueries.delete(id);clearTimeout(job.timer);
  lastPlatformResult={available:available===true,source,at:Date.now()};
  try{await proxy.completeIsUvpaaRequest({requestId:job.requestId,isUvpaa:available===true});}
  catch(e){await log('warn','local-platform-response-failed',String(e?.message||e).slice(0,120));}
  await log(available?'info':'warn','local-platform-capability',
    `Remote platform authenticator ${available===true} (${source}) forwarded to local Chrome`);
}
function failUvpaaQueries(source){
  for(const id of [...uvpaaQueries.keys()])settleUvpaa(id,false,source).catch(()=>{});
}

const rpAttemptHistory=new Map();
const RETRY_WINDOW_MS=90000,MAX_RP_ATTEMPTS=5;
function trackRpAttempt(rp,id){
  const now=Date.now();
  const current=(rpAttemptHistory.get(rp)||[]).filter(t=>now-t<RETRY_WINDOW_MS);
  current.push(now);rpAttemptHistory.set(rp,current);
  if(current.length>=2)log('warn','rp-challenge-repeated',
    `RP ${rp} started ${current.length} WebAuthn requests in ${RETRY_WINDOW_MS/1000}s. Assertion handoff does not prove the site accepted login.`,id);
  if(current.length>MAX_RP_ATTEMPTS)throw Error(`Possible WebAuthn retry loop for ${rp} (more than ${MAX_RP_ATTEMPTS} requests in ${RETRY_WINDOW_MS/1000}s). Pause, inspect server login result, then use Clear retry guard.`);
}
const VERSION='1.0.5', ROLE='local';
let ws=null, context=null, config=null, enabled=false, attached=false, peerOnline=false;
let connectionState='disabled', lastError='', attempts=0, connectedAt=null;
let authenticatorPreference='default',forceManualNext=false,backgroundSigning=false;
let localProfiles=[];let preferredProfileByRp={};
const HINTS=new Set(['default','security-key','client-device','hybrid']);
const preferencesReady=chrome.storage.local.get(['authenticatorPreference','preferredProfileByRp','backgroundSigning']).then(r=>{
  backgroundSigning=r.backgroundSigning===true;
  if(HINTS.has(r.authenticatorPreference))authenticatorPreference=r.authenticatorPreference;
  if(r.preferredProfileByRp && typeof r.preferredProfileByRp==='object')
    preferredProfileByRp=r.preferredProfileByRp;
}).catch(()=>{});
let pingTimer=null, retryTimer=null, retryDelay=1500;
let lastRelayPongAt=0,relayConnectStartedAt=0;
function watchdogRelay(){
  if(!enabled||!context||!config)return;
  const now=Date.now();
  if(ws?.readyState===WebSocket.CONNECTING && now-relayConnectStartedAt>30000){
    log('warn','relay-connect-stalled','No WSS handshake after 30s; reconnecting with unchanged pairing');
    closeConnection();reconnectLater();return;
  }
  if(connected() && now-lastRelayPongAt>90000){
    log('warn','relay-heartbeat-stale',
      `No relay pong for ${Math.round((now-lastRelayPongAt)/1000)}s; reconnecting without rekey`);
    closeConnection();reconnectLater();return;
  }
  if(!ws&&!retryTimer)connect();
}
const log=(...args)=>BridgeDiag.log(...args);

// Relay HTTP health is independently probed. Green also requires a recent
// encrypted round trip, not merely a WebSocket handshake or a peer announcement.
let health='unknown',healthDetail='Health check has not run',healthAt=0,linkAt=0,healthProbeActive=false;
const HEALTH_ALARM='bridge-status-health',LINK_FRESH_MS=90000;
function indicatorInput(){
  return {role:ROLE,enabled,connected:connected() && Date.now()-lastRelayPongAt<65000,peerOnline,health,healthDetail,
    healthAt,linkAt,proxyReady:attached};
}
const updateIndicator=()=>BridgeIndicator.update(indicatorInput());
async function checkRelayHealth(){
  if(healthProbeActive||!enabled||!config)return;
  healthProbeActive=true;
  let stage='permission';
  try{
    const url=BridgeIndicator.healthUrl(config.relayUrl);
    const allowed=await chrome.permissions.contains({origins:[BridgeIndicator.permissionPattern(config.relayUrl)]});
    if(!allowed){
      health='unknown';healthDetail='Health not checked: grant the relay HTTPS permission from Connect';
      healthAt=0;
    } else {
      stage='fetch';
      const controller=new AbortController();
      const timer=setTimeout(()=>controller.abort(),5000);
      let response;
      try { response=await fetch(url,{method:'GET',credentials:'omit',cache:'no-store',redirect:'error',signal:controller.signal}); }
      finally { clearTimeout(timer); }
      const body=(await response.text()).trim();
      health=response.status===200&&body==='ok'?'ok':'bad';
      healthAt=Date.now();
      healthDetail=health==='ok'?'200 ok':`HTTP ${response.status}, response did not equal ok`;
    }
  }catch(e){
    health=stage==='permission'?'unknown':'bad';
    healthAt=stage==='permission'?0:Date.now();
    healthDetail=String(e?.name||'Error')+': '+String(e?.message||e).slice(0,85);
  }finally{
    healthProbeActive=false;
    updateIndicator();
  }
}
async function monitorTick(){
  if(!enabled)return updateIndicator();
  watchdogRelay();
  await checkRelayHealth();
  if(connected()&&peerOnline&&(!linkAt||Date.now()-linkAt>25000))
    linkTest(true).catch(()=>{});
  updateIndicator();
}
async function startMonitor(){
  try { await chrome.alarms.create(HEALTH_ALARM,{periodInMinutes:0.5}); }
  catch(e){ await log('warn','monitor-alarm-unavailable',e.message); }
  checkRelayHealth().catch(()=>{});
  updateIndicator();
}
chrome.alarms.onAlarm.addListener(alarm=>{
  if(alarm.name===HEALTH_ALARM)monitorTick().catch(()=>{});
});

function connected() {return ws?.readyState === WebSocket.OPEN;}
function relayHost() {try{return new URL(config?.relayUrl||'').host;}catch{return '';}}
function closeConnection(){
  clearInterval(pingTimer);clearTimeout(retryTimer);pingTimer=null;retryTimer=null;
  const old=ws;ws=null;peerOnline=false;linkAt=0;updateIndicator();
  if(old){old.onclose=null;old.onmessage=null;try{old.close(1000,'Reconfigure');}catch{}}
}
async function send(obj){
  if(!connected()||!context)throw Error('Local relay is offline');
  const old=ws;const encrypted=await BridgeCrypto.seal(context,obj);
  if(ws!==old||!connected())throw Error('Relay changed while encrypting');
  ws.send(encrypted);
}
async function finish(id,fields){
  const p=pending.get(id);
  if(!p)return;
  pending.delete(id);clearTimeout(p.timer);
  try {await proxy.completeGetRequest({requestId:p.requestId,...fields});
    await log('info','local-webAuthn-complete',fields.responseJson?'Assertion delivered':'Error returned to login website',id);
  } catch(e){await log('warn','local-complete-failed','Browser request already canceled or proxy detached: '+e.message,id);}
}
async function failAll(message){
  for(const id of Array.from(pending.keys()))await finish(id,{error:{name:'NotAllowedError',message}});
}
function reconnectLater(){
  if(!enabled)return;
  clearTimeout(retryTimer);connectionState='retrying';
  const delay=retryDelay;retryTimer=setTimeout(connect,delay);retryDelay=Math.min(retryDelay*2,30000);
  log('warn','relay-retry',`Retry in ${delay}ms`);
}
function connect(){
  if(!enabled||!context||!config)return;
  closeConnection();connectionState='connecting';relayConnectStartedAt=Date.now();attempts++;updateIndicator();
  try{ws=new WebSocket(BridgeCrypto.relayURL(config.relayUrl,context.room,ROLE));}
  catch(e){lastError=e.message;log('error','relay-open-failed',e.message);reconnectLater();return;}
  const current=ws;
  log('info','relay-connecting',`Outbound WSS ${relayHost()} (attempt ${attempts})`);
  current.onopen=()=>{
    connectionState='connected';lastError='';retryDelay=1500;connectedAt=Date.now();linkAt=0;updateIndicator();
    log('success','relay-connected','WebSocket transport ready');
    lastRelayPongAt=Date.now();
    pingTimer=setInterval(()=>{if(current.readyState===WebSocket.OPEN)current.send('ping');},20000);
  };
  current.onmessage=async event=>{
    if(current!==ws||typeof event.data!=='string')return;
    if(event.data==='pong'){lastRelayPongAt=Date.now();return;}
    try{
      const meta=JSON.parse(event.data);
      if(meta?.type==='peer'){
        peerOnline=Boolean(meta.online);if(!peerOnline)linkAt=0;updateIndicator();
        if(peerOnline)linkTest(true).catch(()=>{});
        await log('info','peer-state',peerOnline?'Remote extension online':'Remote extension offline');
        if(!peerOnline)await failAll('Remote browser disconnected');
        return;
      }
      const packet=await BridgeCrypto.open(context,event.data);
      if(packet?.kind==='manage-result'){
        const job=managementJobs.get(packet.id);if(!job)return;
        managementJobs.delete(packet.id);clearTimeout(job.timer);job.resolve(packet.result);return;
      }
      if(!packet||typeof packet.kind!=='string')return;
      if(packet.kind==='uvpaa-result'){
        if(typeof packet.id!=='string')return;
        await settleUvpaa(packet.id,packet.available===true,
          'remote '+String(packet.source||'unknown').slice(0,35)+(packet.cached?' cached':''));
        return;
      }
      if(packet.kind==='profile-inventory'){
        if(!Array.isArray(packet.profiles)||packet.profiles.length>100)return;
        localProfiles=packet.profiles.filter(p=>typeof p?.id==='string' &&
          typeof p?.rpId==='string' && typeof p?.origin==='string').map(p=>({
          id:p.id,rpId:p.rpId,origin:p.origin,
          name:String(p.name||'').slice(0,60),group:String(p.group||'').slice(0,60),
          quickStart:p.quickStart===true,autoInvoke:p.autoInvoke===true,
          preferredForRp:p.preferredForRp===true
        }));
        await log('info','profile-inventory-received',`${localProfiles.length} remotely saved RP rules (E2EE)`);
        return;
      }
      if(packet.kind==='diag-ping'){await send({kind:'diag-pong',id:packet.id});return;}
      if(packet.kind==='diag-pong'){
        const p=pings.get(packet.id);if(p){pings.delete(packet.id);clearTimeout(p.timer);linkAt=Date.now();updateIndicator();p.resolve({ok:true,rttMs:Date.now()-p.started});}return;
      }
      if(packet.kind!=='result'||typeof packet.id!=='string')return;
      if(!pending.has(packet.id)){await log('warn','unexpected-response','Unknown/canceled request ignored');return;}
      if(packet.ok){
        if(!packet.credential?.response?.clientDataJSON || !packet.credential?.response?.signature)
          throw Error('Invalid credential object returned by remote browser');
        await finish(packet.id,{responseJson:JSON.stringify(packet.credential)});
        await log('success','assertion-complete','Assertion delivered to local Chrome. Website acceptance is not confirmed.',packet.id);
      }else{
        const message=String(packet.error||'Authentication denied remotely').slice(0,170);
        await finish(packet.id,{error:{name:'NotAllowedError',message}});
        await log('warn','assertion-rejected',`Remote extension returned: ${message}`,packet.id);
      }
    }catch(e){await log('warn','relay-invalid-frame','Bad/decryption-failed packet: '+e.message);}
  };
  current.onerror=()=>{lastError='WebSocket error (network, relay, TLS, or duplicate role)';log('warn','relay-socket-error',lastError);};
  current.onclose=event=>{
    if(current!==ws)return;
    ws=null;peerOnline=false;linkAt=0;updateIndicator();clearInterval(pingTimer);pingTimer=null;
    log('warn','relay-closed',`Close ${event.code||'unknown'}; ${String(event.reason||'').slice(0,70)}`);
    for(const [id,p]of pings){pings.delete(id);clearTimeout(p.timer);p.resolve({error:'Relay disconnected'});}
    failUvpaaQueries('relay disconnected');
    failAll('WebSocket relay disconnected').catch(()=>{});
    reconnectLater();
  };
}
async function enable(next){
  if(enabled && attached && config?.relayUrl===next.relayUrl && config?.pairingKey===next.pairingKey){
    await log('info','relay-config-unchanged','Keeping existing proxy, pairing and relay connection');
    if(!ws && !retryTimer) connect();
    checkRelayHealth().catch(()=>{});
    return;
  }
  const ctx=await BridgeCrypto.init(next.pairingKey);
  BridgeCrypto.relayURL(next.relayUrl,ctx.room,ROLE);
  if(!attached){
    await proxy.attach();attached=true;
    await log('success','proxy-attached','Chrome WebAuthn traffic will be intercepted while enabled');
  }
  failUvpaaQueries('bridge reconfigured');await failAll('Local bridge reconfigured');closeConnection();
  context=ctx;config={relayUrl:next.relayUrl,pairingKey:next.pairingKey};
  enabled=true;lastError='';retryDelay=1500;
  await chrome.storage.local.set({...config,enabled:true});
  connect();startMonitor().catch(()=>{});
}
async function disable(){
  enabled=false;await chrome.storage.local.set({enabled:false});
  failUvpaaQueries('bridge disabled');await failAll('Local bridge disabled');closeConnection();connectionState='disabled';
  health='unknown';healthAt=0;linkAt=0;healthDetail='Disconnected';updateIndicator();
  if(attached){try{await proxy.detach();await log('info','proxy-detached','Normal local WebAuthn restored');}
    catch(e){lastError=e.message;await log('warn','proxy-detach-failed',e.message);}attached=false;}
}
async function linkTest(silent=false){
  if(!connected()||!peerOnline)return {error:'Both extensions must be online'};
  const id=crypto.randomUUID();
  return new Promise(resolve=>{
    const timer=setTimeout(()=>{pings.delete(id);if(!silent)log('warn','link-test-timeout');linkAt=0;updateIndicator();resolve({error:'No encrypted response within 8 seconds'});},8000);
    pings.set(id,{timer,resolve,started:Date.now()});
    send({kind:'diag-ping',id}).then(()=>{if(!silent)log('info','link-test-sent');}).catch(e=>{
      clearTimeout(timer);pings.delete(id);resolve({error:e.message});
    });
  }).then(r=>{if(r.ok&&!silent)log('success','link-test-ok',`Encrypted round trip ${r.rttMs} ms`);return r;});
}
proxy.onGetRequest.addListener(req=>{
  const id=crypto.randomUUID();
  const timer=setTimeout(()=>finish(id,{error:{name:'NotAllowedError',message:'Local YubiKey request timed out'}}),240000);
  pending.set(id,{requestId:req.requestId,timer,started:Date.now(),rp:'',fingerprint:''});
  (async()=>{
    try{
      await preferencesReady;
      if(!enabled||!connected()||!peerOnline)throw Error('Bridge not paired; verify both extension diagnostics');
      const options=JSON.parse(req.requestDetailsJson);
      if(typeof options?.challenge!=='string'||options.challenge.length>4096)throw Error('Invalid challenge');
      const manual=forceManualNext;forceManualNext=false;
      await log('info','local-options-summary',
        `RP ${options.rpId||'(omitted)'}; preferred authenticator ${authenticatorPreference}; manual=${manual}; `+
        `allowCredentials=${Array.isArray(options.allowCredentials)?options.allowCredentials.length:'discoverable'}; `+
        `UV=${options.userVerification||'preferred'}; `+
        `hints=${(options.hints||[]).join(',')||'none'}; `+
        `extensions=${Object.keys(options.extensions||{}).join(',')||'none'}`,id);
      if(options.rpId){lastLocalRp=options.rpId;trackRpAttempt(options.rpId,id);}
      const u8=Uint8Array.from(atob(options.challenge.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-options.challenge.length%4)%4)),c=>c.charCodeAt(0));
      const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',u8));
      const fp=Array.from(hash.slice(0,6),b=>b.toString(16).padStart(2,'0')).join('');
      // Chrome proxy does NOT identify the WebAuthn caller. This is ONLY an active-tab observation.
      let observedTopOrigin=null;
      try{
        const top=await chrome.tabs.query({active:true,lastFocusedWindow:true});
        const url=top[0]?.url;
        if(url&&new URL(url).protocol==='https:')observedTopOrigin=new URL(url).origin;
      }catch(e){await log('warn','top-tab-inspection-failed','Could not inspect focused tab: '+e.message,id);}
      await log('info','local-tab-observed',observedTopOrigin ?
        `${observedTopOrigin} (active top tab only; NOT WebAuthn caller attestation)`:
        'Active-tab origin unavailable; Chrome proxy provides no caller origin',id);
      const p=pending.get(id);if(!p)return;
      p.rp=options.rpId||'(omitted)';p.fingerprint=fp;p.observedTopOrigin=observedTopOrigin;
      await log('info','local-challenge',`RP ${p.rp}; fingerprint ${fp}; local origin unavailable in Chrome proxy event`,id);
      const profile=localProfiles.find(p=>p.rpId===options.rpId &&
        preferredProfileByRp[options.rpId]===p.id);
      await send({kind:'get',id,options,observedTopOrigin,
        authenticatorPreference,forceManual:manual,backgroundSigning,
        preferredProfileId:profile?.id||null});
      await log('info','challenge-forwarded','Encrypted challenge sent to remote browser',id);
    }catch(e){lastError=e.message;await log('error','request-forward-failed',e.message,id);
      await finish(id,{error:{name:'NotAllowedError',message:String(e.message||e).slice(0,170)}});
    }
  })();
});
proxy.onRequestCanceled.addListener(requestId=>{
  for(const[id,p]of pending){if(p.requestId===requestId){
    pending.delete(id);clearTimeout(p.timer);log('info','local-request-canceled','Website canceled the request',id);
    send({kind:'cancel',id}).catch(()=>{});break;
  }}
});
proxy.onCreateRequest.addListener(req=>{
  log('warn','registration-not-supported','New credentials / security-key enrollment is disabled');
  proxy.completeCreateRequest({requestId:req.requestId,error:{name:'NotSupportedError',message:'This bridge supports sign-in, not credential registration'}}).catch(()=>{});
});
proxy.onIsUvpaaRequest.addListener(req=>{
  const id=crypto.randomUUID();
  const timer=setTimeout(()=>settleUvpaa(id,false,'remote measurement timed out').catch(()=>{}),7500);
  uvpaaQueries.set(id,{requestId:req.requestId,timer});
  log('info','platform-authenticator-probe','Querying remote Chrome for actual platform-authenticator capability');
  if(!enabled||!connected()||!peerOnline){
    settleUvpaa(id,false,'remote peer unavailable; fallback not measured').catch(()=>{});return;
  }
  send({kind:'uvpaa-query',id}).catch(e=>
    settleUvpaa(id,false,'query error: '+String(e?.message||e).slice(0,100)).catch(()=>{}));
});
chrome.runtime.onMessage.addListener((msg,sender,reply)=>{
  (async()=>{
    await preferencesReady;
    switch(msg?.action){
      case 'listProfiles':case 'saveProfile':case 'deleteProfile':case 'relatedOriginCheck':case 'setStreamlinedMode':
        return await manageRemote(msg);
      case 'originPreflight':{
        if(preflightRunning||pending.size)return {error:'Finish the current preflight or authentication request first'};
        preflightRunning=true;
        try{
          const inventory=await manageRemote({action:'listProfiles'});
          if(inventory.error)return inventory;
          const profile=inventory.profiles?.find(p=>p.id===msg.profileId);
          if(!profile)return {error:'Choose a saved profile to test'};
          const result=await BridgePreflight.run(profile);
          await log(result.ok?'success':'warn','local-preflight',result.ok?'Local sign-in page is ready':result.error);
          return result;
        }finally{preflightRunning=false;}
      }
      case 'enable':await enable(msg);return {ok:true};
      case 'disable':await disable();return {ok:true};
      case 'checkHealth':await checkRelayHealth();return {ok:true,health,healthDetail};
      case 'getConfig':return {ok:true,settings:await chrome.storage.local.get(['relayUrl','pairingKey','relayDraftUrl','relayDraftPairingKey'])};
      case 'status':return {ok:true,role:ROLE,version:VERSION,enabled,attached,connected:connected(),connectionState,
        health,healthDetail,healthAt,linkAt,indicator:BridgeIndicator.state(indicatorInput()),
        peerOnline,relayHost:relayHost(),lastError,connectedAt,attempts,
        authenticatorPreference,forceManualNext,backgroundSigning,localProfiles,preferredProfileByRp,
        lastPlatformResult,pendingPlatformQueries:uvpaaQueries.size,
        pending:Array.from(pending.entries()).map(([id,p])=>({id:id.slice(0,8),rp:p.rp,fingerprint:p.fingerprint,observedTopOrigin:p.observedTopOrigin||null,ageSeconds:Math.round((Date.now()-p.started)/1000)})),
        events:(await BridgeDiag.snapshot()).slice(-12)};
      case 'diagnostics':return {ok:true,role:ROLE,version:VERSION,enabled,attached,connected:connected(),connectionState,
        health,healthDetail,healthAt,linkAt,indicator:BridgeIndicator.state(indicatorInput()),
        peerOnline,relayHost:relayHost(),lastError,lastPlatformResult,backgroundSigning,
        pendingPlatformQueries:uvpaaQueries.size,events:await BridgeDiag.snapshot()};
      case 'clearLogs':await BridgeDiag.clear();return {ok:true};
      case 'linkTest':return await linkTest();
      case 'clearRetryGuard':rpAttemptHistory.clear();await log('info','retry-guard-cleared','Per-RP retry history cleared');return {ok:true};
      case 'setBackgroundSigning':{
        if(typeof msg.enabled!=='boolean')throw Error('Background signing must be true or false');
        await chrome.storage.local.set({backgroundSigning:msg.enabled});
        backgroundSigning=msg.enabled;
        await log('info','background-signing-setting',backgroundSigning?'Next automatic sign-in uses a small unfocused signing window':'Next sign-in uses an active signing tab');
        return {ok:true,backgroundSigning};
      }
      case 'authenticatorPreference':return {ok:true,preference:authenticatorPreference};
      case 'setAuthenticatorPreference':{
        if(!HINTS.has(msg.preference))throw Error('Unknown WebAuthn authenticator hint');
        authenticatorPreference=msg.preference;
        await chrome.storage.local.set({authenticatorPreference});
        await log('info','authenticator-preference-saved',`Remote Chrome chooser hint: ${authenticatorPreference} (next request)`);
        return {ok:true,preference:authenticatorPreference};
      }
      case 'manualNext':forceManualNext=true;
        await log('info','manual-profile-next','Next WebAuthn request will show manual remote profile selection');
        return {ok:true};
      case 'setLocalProfile':{
        const match=localProfiles.find(p=>p.id===msg.profileId);
        if(!match)throw Error('The saved remote rule is not in the encrypted profile inventory yet');
        if(!match.quickStart)throw Error('Enable Quick-start on the remote rule before locally auto-selecting it');
        preferredProfileByRp={...preferredProfileByRp,[match.rpId]:match.id};
        await chrome.storage.local.set({preferredProfileByRp});
        await log('info','local-rule-choice-saved',`${match.rpId}: ${match.group}/${match.name}. Remote RP/origin checks remain active.`);
        return {ok:true};
      }
      case 'clearLocalProfile':{
        const rp=String(msg.rpId||'');
        delete preferredProfileByRp[rp];
        await chrome.storage.local.set({preferredProfileByRp});
        return {ok:true};
      }
      default:return {error:'Unknown action'};
    }
  })().then(reply,e=>{lastError=e.message||String(e);log('error','command-error',lastError);reply({error:lastError});});
  return true;
});
(async()=>{
  const saved=await chrome.storage.local.get(['enabled','relayUrl','pairingKey']);
  if(saved.enabled&&saved.relayUrl&&saved.pairingKey){
    try{await enable(saved);}catch(e){lastError=e.message;enabled=false;attached=false;connectionState='error';
      await chrome.storage.local.set({enabled:false});await log('error','local-restore-failed',e.message);}
  }
})();

updateIndicator();
