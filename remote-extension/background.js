/* global BridgeCrypto, BridgeDiag, BridgeValidate, BridgeProfiles, runSiteCeremony, installPageStageRelay */
importScripts('crypto.js','diag.js','indicator.js','profiles.js','validation.js','site-page.js','signing-page.js');
const pending=new Map(), pings=new Map();
// A Chrome profile can only have one active native WebAuthn operation at a time.
// Different RP IDs may queue together, but signing is strictly serialized.
const requestQueue=[];
let lastLocalRp=null,lastLocalRpAt=0;
const MAX_PENDING_REQUESTS=4, MAX_REQUEST_AGE_MS=210000;
const ACTIVE_CEREMONY_TIMEOUT_MS=180000, SETTLE_AFTER_CEREMONY_MS=2000;
let activeRequestId=null, queueTimer=null, queuePumping=false;
let streamlinedMode=true; // default on; user can disable it in Remote popup
let queuePaused=false, lastCeremonyEndAt=0;
function queuedPosition(id){const index=requestQueue.indexOf(id);return index<0?0:index+1;}
function scheduleNextRequest(delay=0){
  if(queuePaused||activeRequestId||!requestQueue.length||!enabled)return;
  clearTimeout(queueTimer);
  queueTimer=setTimeout(()=>pumpRequestQueue().catch(e=>log('error','queue-pump-error',e?.message||String(e))),delay);
}
async function pumpRequestQueue(){
  if(queuePumping||queuePaused||activeRequestId||!enabled||!connected()||!peerOnline)return;
  queuePumping=true;
  try{
    while(requestQueue.length&&!activeRequestId){
      const remaining=SETTLE_AFTER_CEREMONY_MS-(Date.now()-lastCeremonyEndAt);
      if(lastCeremonyEndAt&&remaining>0){
        await log('info','native-ceremony-settling',`Waiting ${remaining}ms before next remote WebAuthn operation`);
        scheduleNextRequest(remaining);return;
      }
      const id=requestQueue.shift();const p=pending.get(id);
      if(!p)continue;
      if(Date.now()-p.started>=MAX_REQUEST_AGE_MS){
        await finish(id,{ok:false,error:'Queued challenge expired before remote approval'});continue;
      }
      activeRequestId=id;p.status='waiting';
      clearTimeout(p.timer);
      p.timer=setTimeout(()=>finish(id,{ok:false,error:'Active remote approval timed out'}).catch(()=>{}),
        Math.min(ACTIVE_CEREMONY_TIMEOUT_MS,MAX_REQUEST_AGE_MS-(Date.now()-p.started)));
      await log('info','request-dequeued',`Now handling RP ${p.rp}; ${requestQueue.length} waiting behind it`,id);
      if(!BridgeProfiles.candidates(profiles,p.rp).length)
        await log('warn','no-profile-match',`No saved profile permits RP ${p.rp}; add one while this request is open`,id);
      if(streamlinedMode && !p.forceManual){
        const matches=BridgeProfiles.candidates(profiles,p.rp);
        const explicit=matches.find(r=>r.id===p.requestedProfileId);
        const preferred=matches.filter(r=>r.preferredForRp);
        const selected=explicit || (preferred.length===1 ? preferred[0] :
          (matches.length===1 ? matches[0] : null));
        if(!selected){
          const reason=matches.length===0 ?
            `No saved remote profile for RP ${p.rp}. Add a provider, then retry the VM sign-in.` :
            `Multiple remote profiles match RP ${p.rp}; select a saved profile in the local extension or set a preferred rule.`;
          await log('warn','auto-profile-unavailable',reason,id);
          await finish(id,{ok:false,error:reason});return;
        }
        p.streamlinedAuto=true;
        await log('info','auto-profile-selected',
          `RP ${p.rp}; provider ${selected.group}; rule ${selected.name}; origin ${selected.origin}; no remote approval dialog`,id);
        const started=await approve(id,selected.id,true).catch(e=>({error:e?.message||String(e)}));
        if(started.ok)return;
        if(pending.has(id)){
          await log('error','auto-profile-failed',started.error||'Unable to start saved profile',id);
          await finish(id,{ok:false,error:started.error||'Unable to start saved profile'});
        }
        return;
      }
      // Quick-start is an explicit per-RP rule preference. It only skips our
      // *extra* approval window, not the final remote WebAuthn button/touch.
      // A visible foreground RP-related tab is a heuristic, never attestation.
      const quick=BridgeProfiles.candidates(profiles,p.rp).filter(r=>r.quickStart);
      // Multiple rules may share an RP (Microsoft direct + related origin).
      // Only a unique saved preference or a single rule can auto-select.
      const preferred=quick.filter(r=>r.preferredForRp);
      // A local choice is an existing, remotely saved rule, and local cannot
      // grant it the remote quick-start consent that was not already saved.
      const localOverride=quick.find(r=>r.id===p.requestedProfileId);
      const selected=localOverride || (preferred.length===1 ? preferred[0] :
        (quick.length===1 ? quick[0] : null));
      if(localOverride)await log('info','local-rule-preselected',
        `Local selected saved remote rule ${localOverride.name} for RP ${p.rp}`,id);
      let looksExpected=false;
      try{
        const observed=new URL(p.observedTopOrigin||'');
        looksExpected=observed.protocol==='https:' &&
          (observed.hostname===p.rp || observed.hostname.endsWith('.'+p.rp));
      }catch{}
      if(!p.forceManual && selected && (looksExpected || selected.autoInvoke)){
        if(!looksExpected)await log('warn','rp-only-auto-selection',
          `Trusted-VM opt-in: local caller origin cannot be verified. Selected saved RP rule ${selected.name}.`,id);
        await log('info','quickstart-selected',
          `Saved rule ${selected.name} for RP ${p.rp}; autoInvoke=${selected.autoInvoke}; verifiedRedirect=${selected.autoRedirect}`,id);
        const started=await approve(id,selected.id,selected.autoRedirect).catch(e=>({error:e?.message||String(e)}));
        if(started.ok)return;
        await log('warn','quickstart-fallback',started.error||'Unable to quick-start',id);
        if(!pending.has(id))return;
      }
      try{
        const win=await chrome.windows.create({url:chrome.runtime.getURL('approve.html')+'?id='+encodeURIComponent(id),
          type:'popup',width:625,height:720,focused:true});
        if(!pending.has(id)){chrome.windows.remove(win.id).catch(()=>{});return;}
        p.windowId=win.id;
        await log('info','approval-window-open','Only one remote approval is active; other providers remain queued',id);
      }catch(e){await finish(id,{ok:false,error:'Could not open approval window: '+e.message});}
      return;
    }
  } finally { queuePumping=false; }
}

let ws=null, context=null, enabled=false, peerOnline=false, config=null, profiles=[];
let connectionState='disabled', lastError='', attempts=0, attachedAt=null;
let pingTimer=null,retryTimer=null,retryDelay=1500;
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
const VERSION='1.0.5',ROLE='remote';
const log=(...a)=>BridgeDiag.log(...a);

// Relay HTTP health is independently probed. Green also requires a recent
// encrypted round trip, not merely a WebSocket handshake or a peer announcement.
let health='unknown',healthDetail='Health check has not run',healthAt=0,linkAt=0,healthProbeActive=false;
const HEALTH_ALARM='bridge-status-health',LINK_FRESH_MS=90000;
function indicatorInput(){
  return {role:ROLE,enabled,connected:connected() && Date.now()-lastRelayPongAt<65000,peerOnline,health,healthDetail,
    healthAt,linkAt,proxyReady:true};
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

// Real remote Chrome UVPAA measurement. Never substitutes user consent or enrollment.
const PLATFORM_CACHE_MS=60000;
let remotePlatformResult=null,capabilityInflight=null;
const capabilityJobs=new Map();
async function measureRemotePlatform(fresh=false){
  if(!fresh&&remotePlatformResult&&Date.now()-remotePlatformResult.at<PLATFORM_CACHE_MS)
    return {...remotePlatformResult,cached:true};
  if(capabilityInflight)return capabilityInflight;
  capabilityInflight=(async()=>{
    const nonce=crypto.randomUUID();
    const result=await new Promise(resolve=>{
      const job={tabId:null,timer:null,resolve:null};
      const complete=value=>{
        if(!capabilityJobs.has(nonce))return;
        capabilityJobs.delete(nonce);clearTimeout(job.timer);
        if(job.tabId!==null)chrome.tabs.remove(job.tabId).catch(()=>{});
        resolve(value);
      };
      job.resolve=complete;
      capabilityJobs.set(nonce,job);
      job.timer=setTimeout(()=>complete({available:false,source:'timeout',error:'No remote capability result after 7 seconds'}),7000);
      chrome.tabs.create({url:chrome.runtime.getURL('capability.html')+'?nonce='+nonce,active:false})
        .then(tab=>{job.tabId=tab.id;if(!capabilityJobs.has(nonce))chrome.tabs.remove(tab.id).catch(()=>{});})
        .catch(e=>complete({available:false,source:'tab-error',error:String(e?.message||e).slice(0,120)}));
    });
    const sampled={...result,at:Date.now(),cached:false};remotePlatformResult=sampled;
    await log(result.source==='browser-api'?'info':'warn','remote-platform-capability',
      `UVPAA ${result.available===true}; source=${result.source}; ${result.error||'measured in remote top-level extension document'}`);
    return sampled;
  })();
  try{return await capabilityInflight;}finally{capabilityInflight=null;}
}

// Diagnostic-only tracing. Events from webpages are NEVER trusted for auth.
const TRACE_MAIN='ykwss-idp-main-047',TRACE_RELAY='ykwss-idp-relay-047';
let traceOrigin=null;
async function getTraceStatus(){
  const scripts=await chrome.scripting.getRegisteredContentScripts();
  const main=scripts.find(x=>x.id===TRACE_MAIN),relay=scripts.find(x=>x.id===TRACE_RELAY);
  const pattern=main?.matches?.[0]||null;
  return {registered:!!main&&!!relay,origin:pattern?pattern.replace(/\/\*$/,''):null,
    main:!!main,relay:!!relay};
}
async function enableTrace(raw){
  const origin=BridgeProfiles.origin(String(raw||'').trim());
  const pattern=BridgeProfiles.sitePattern(origin);
  if(!await chrome.permissions.contains({origins:[pattern]}))
    throw Error('Grant the '+pattern+' host permission in Diagnostics before starting the tracer');
  const registered=await chrome.scripting.getRegisteredContentScripts();
  const old=registered.map(x=>x.id).filter(x=>[TRACE_MAIN,TRACE_RELAY,'ykwss-idp-probe'].includes(x));
  if(old.length)await chrome.scripting.unregisterContentScripts({ids:old});
  // The isolated listener registers alongside the MAIN-world hook at document_start.
  await chrome.scripting.registerContentScripts([
    {id:TRACE_RELAY,matches:[pattern],js:['idp-trace-relay.js'],runAt:'document_start',world:'ISOLATED',allFrames:true,persistAcrossSessions:true},
    {id:TRACE_MAIN,matches:[pattern],js:['idp-trace-main.js'],runAt:'document_start',world:'MAIN',allFrames:true,persistAcrossSessions:true}
  ]);
  traceOrigin=origin;
  await log('info','idp-trace-enabled',`Registered on ${origin}. Reload IdP tabs to activate. No request suppression.`);
  return getTraceStatus();
}
async function disableTrace(){
  const ids=(await chrome.scripting.getRegisteredContentScripts()).map(x=>x.id)
    .filter(x=>[TRACE_MAIN,TRACE_RELAY,'ykwss-idp-probe'].includes(x));
  if(ids.length)await chrome.scripting.unregisterContentScripts({ids});
  traceOrigin=null;
  await log('info','idp-trace-disabled','Tracer unregistered. Close/reload IdP tabs to remove any active wrapper.');
  return getTraceStatus();
}

const connected=()=>ws?.readyState===WebSocket.OPEN;
function relayHost(){try{return new URL(config?.relayUrl||'').host;}catch{return '';}}
async function loadProfiles(){
  const data=await chrome.storage.local.get(['profiles','allowedOrigin','loginPageUrl']);
  let list=Array.isArray(data.profiles)?data.profiles:[];
  if(!Array.isArray(data.profiles)&&data.allowedOrigin){
    try{
      const old=BridgeProfiles.origin(data.allowedOrigin);
      let legacyPage=old+'/';
      try{
        const existing=new URL(data.loginPageUrl||old+'/');
        if(existing.origin===old){
          if(existing.search||existing.hash)await log('warn','legacy-url-sanitized','Removed prior remote login URL query/fragment from migrated profile');
          existing.search='';existing.hash='';legacyPage=existing.toString();
        }
      }catch{}
      list=[{name:'Migrated v0.3 '+new URL(old).hostname,origin:old,pageUrl:legacyPage,rpId:new URL(old).hostname}];
      await log('info','profiles-migrated','Previous origin migrated as a profile; verify the expected RP ID before using');
    }catch(e){await log('warn','profile-migration-skipped',e.message);}
  }
  profiles=[];
  for(const p of list){try{profiles.push(BridgeProfiles.normalize(p));}catch(e){await log('warn','profile-invalid','Skipped invalid saved profile: '+e.message);}}
  if(!Array.isArray(data.profiles))await chrome.storage.local.set({profiles});
  return profiles;
}
const profilesReady=loadProfiles();
// A popup may save a new profile while an approval dialog is open. Re-read the
// durable storage instead of relying solely on an MV3 service worker's cache.
async function reloadProfiles(){
  await profilesReady;
  const saved=await chrome.storage.local.get(['profiles']);
  if(!Array.isArray(saved.profiles))return profiles;
  const next=[];
  for(const row of saved.profiles){
    try{next.push(BridgeProfiles.normalize(row));}
    catch(e){await log('warn','profile-invalid','Saved profile skipped: '+String(e.message||e).slice(0,100));}
  }
  profiles=next;
  return profiles;
}
async function shareProfileInventory(){
  if(!connected()||!peerOnline)return;
  await reloadProfiles();
  const summary=profiles.map(p=>({id:p.id,rpId:p.rpId,origin:p.origin,
    name:p.name,group:p.group,quickStart:p.quickStart,
    autoInvoke:p.autoInvoke,preferredForRp:p.preferredForRp}));
  await send({kind:'profile-inventory',profiles:summary});
  await log('info','profile-inventory-shared',`${summary.length} saved RP rules sent over E2EE to paired local extension`);
}
function profileSummary(p,rp){
  const mode=BridgeProfiles.relation(p,rp);
  return {id:p.id,name:p.name,origin:p.origin,rpId:p.rpId,mode,
    reason:mode==='none'?(p.rpId!==rp?'Different requested RP ID':'Origin relationship not allowed'):
      mode==='direct'?'Direct domain match (no well-known request required)':'Related-origin authorization required'};
}
async function inspectRelation(p,rp){
  const basics=profileSummary(p,rp);
  if(basics.mode==='none')return {...basics,ok:false,checked:false,reason:basics.reason};
  if(basics.mode==='direct')return {...basics,ok:true,checked:false,
    reason:'Direct origin/RP match; NOT a related-origin check. No /.well-known/webauthn request was made.'};
  const r=await checkRelatedOrigin(p,rp);
  return {...basics,...r,checked:r.networkFetch===true};
}
function closeConnection(){
  clearInterval(pingTimer);clearTimeout(retryTimer);pingTimer=null;retryTimer=null;
  const old=ws;ws=null;peerOnline=false;linkAt=0;updateIndicator();
  if(old){old.onclose=null;old.onmessage=null;try{old.close(1000,'Reconfigure');}catch{}}
}
async function send(obj){
  if(!connected()||!context)throw Error('Relay is not connected');
  const current=ws,encrypted=await BridgeCrypto.seal(context,obj);
  if(ws!==current||!connected())throw Error('Relay changed while encrypting');
  ws.send(encrypted);
}
async function finish(id,result={},notify=true){
  const p=pending.get(id);if(!p)return;
  const wasActive=activeRequestId===id;
  pending.delete(id);clearTimeout(p.timer);
  const index=requestQueue.indexOf(id);if(index>=0)requestQueue.splice(index,1);
  if(wasActive)activeRequestId=null;
  if(notify){try{await send({kind:'result',id,...result});}catch(e){await log('error','result-delivery-failed',e.message,id);}}
  // Wait for the tab to close so that the old navigator.credentials.get()
  // aborts/releases Chrome's authenticator before opening another provider.
  await BridgeSigningPage.close({tabId:p.tabId,windowId:p.signingWindowId});
  if(p.windowId!==null)await chrome.windows.remove(p.windowId).catch(()=>{});
  if(wasActive)lastCeremonyEndAt=Date.now();
  await log(result.ok?'success':'info',result.ok?'assertion-forwarded':'request-ended',
    result.ok?'Verified assertion forwarded':(result.error||'Canceled'),id);
  if(!queuePaused&&enabled)scheduleNextRequest(wasActive?SETTLE_AFTER_CEREMONY_MS:0);
}
async function cancelAll(notify=false){
  queuePaused=true;clearTimeout(queueTimer);
  try { for(const id of Array.from(pending.keys()))await finish(id,{ok:false,error:'Disconnected'},notify); }
  finally { requestQueue.length=0;activeRequestId=null;queuePaused=false; }
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
    retryDelay=1500;connectionState='connected';lastError='';attachedAt=Date.now();linkAt=0;updateIndicator();
    log('success','relay-connected','End-to-end encrypted transport available');
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
        if(peerOnline)scheduleNextRequest();
        if(peerOnline)linkTest(true).catch(()=>{});
        if(peerOnline)shareProfileInventory().catch(e=>log('warn','profile-inventory-sync-failed',e.message));
        await log('info','peer-state',peerOnline?'Local browser online':'Local browser offline');return;
      }
      const packet=await BridgeCrypto.open(context,event.data);
      if(packet?.kind==='manage-request'){
        const allowed=new Set(['listProfiles','saveProfile','deleteProfile','relatedOriginCheck','setStreamlinedMode']);
        if(typeof packet.id!=='string'||!allowed.has(packet.command?.action))return;
        let result;try{result=await handleCommand(packet.command);}catch(e){result={error:String(e.message||e)};}
        await send({kind:'manage-result',id:packet.id,result});return;
      }
      if(!packet||typeof packet.kind!=='string')return;
      if(packet.kind==='uvpaa-query'){
        if(typeof packet.id!=='string'||!/^[0-9a-f-]{36}$/.test(packet.id))return;
        const measured=await measureRemotePlatform();
        await send({kind:'uvpaa-result',id:packet.id,available:measured.available===true,
          source:measured.source,cached:measured.cached===true});
        return;
      }
      if(packet.kind==='cancel'){await finish(packet.id,{},false);return;}
      if(packet.kind==='get'){await onGet(packet);return;}
      if(packet.kind==='diag-ping'){await send({kind:'diag-pong',id:packet.id});return;}
      if(packet.kind==='diag-pong'){
        const p=pings.get(packet.id);
        if(p){pings.delete(packet.id);clearTimeout(p.timer);linkAt=Date.now();updateIndicator();p.resolve({ok:true,rttMs:Date.now()-p.started});}
      }
    }catch(e){await log('warn','relay-invalid-frame','Decryption/packet parsing failed: '+e.message);}
  };
  current.onerror=()=>{lastError='WebSocket error (network/relay/TLS/duplicate role)';log('warn','relay-socket-error',lastError);};
  current.onclose=ev=>{
    if(current!==ws)return;
    ws=null;peerOnline=false;linkAt=0;updateIndicator();clearInterval(pingTimer);pingTimer=null;
    log('warn','relay-closed',`Close ${ev.code||'unknown'}; ${String(ev.reason||'').slice(0,70)}`);
    for(const[id,p]of pings){pings.delete(id);clearTimeout(p.timer);p.resolve({error:'Relay disconnected'});}
    cancelAll(false).catch(()=>{});reconnectLater();
  };
}
async function checkRelatedOrigin(profile,rp){
  // The browser must ALSO enforce WebAuthn Related Origin Requests. This is only a conservative precheck.
  if(!profile.allowRelatedOrigins)return {ok:false,networkFetch:false,reason:'Related Origin Requests are disabled for this profile'};
  const hostPermission=BridgeProfiles.sitePattern('https://'+rp);
  if(!await chrome.permissions.contains({origins:[hostPermission]}))
    return {ok:false,networkFetch:false,reason:'RP host permission missing. Allow site access in the remote extension’s Chrome settings for https://'+rp+'/*'};
  const uri='https://'+rp+'/.well-known/webauthn';
  try{
    const response=await fetch(uri,{credentials:'omit',redirect:'follow',cache:'no-store',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(8000)});
    const meta={url:uri,finalUrl:response.url||uri,httpStatus:response.status??null};
    if(!response.ok)return {...meta,ok:false,networkFetch:true,reason:'RP /.well-known/webauthn HTTP '+response.status};
    if(!response.headers.get('content-type')?.toLowerCase().includes('application/json'))
      return {...meta,ok:false,networkFetch:true,reason:'RP /.well-known/webauthn is not JSON'};
    const body=await response.json();
    const allowed=Array.isArray(body.origins)&&body.origins.includes(profile.origin);
    return allowed?{...meta,ok:true,networkFetch:true,reason:'RP published this exact origin in /.well-known/webauthn'}:
      {...meta,ok:false,networkFetch:true,reason:'RP did not list '+profile.origin+' in /.well-known/webauthn'};
  }catch(e){return {ok:false,networkFetch:true,url:uri,errorName:e?.name||'Error',
    reason:`RP well-known fetch failed at ${uri}: ${e?.name||'Error'}: ${String(e.message||e).slice(0,100)}. Check remote extension service-worker Network and IT policies.`};}
}
async function onGet(packet){
  await profilesReady;
  const {id,options}=packet;
  if(typeof id!=='string'||!/^[0-9a-f-]{36}$/.test(id)){
    await log('warn','invalid-request-id');return;
  }
  if(pending.has(id)){await log('warn','duplicate-request','Repeated request ID ignored',id);return;}
  let info,fp;
  try{info=BridgeValidate.request(options);fp=await BridgeValidate.fingerprint(options.challenge);}
  catch(e){await log('warn','request-invalid',e.message,id);
    await send({kind:'result',id,ok:false,error:e.message});return;}
  // Do not open two prompts for the same in-flight challenge. New challenges
  // from a relying party are distinct and must never reuse an old assertion.
  if(Array.from(pending.values()).some(p=>p.rp===info.rp&&p.fingerprint===fp)){
    await log('warn','same-challenge-in-flight',`RP ${info.rp}; fingerprint ${fp} already pending`,id);
    await send({kind:'result',id,ok:false,error:'Same WebAuthn challenge already pending remotely'});return;
  }
  if(pending.size>=MAX_PENDING_REQUESTS){
    await log('warn','remote-queue-full',`Reached ${MAX_PENDING_REQUESTS} outstanding WebAuthn requests`,id);
    await send({kind:'result',id,ok:false,error:'Remote WebAuthn queue full; complete or cancel an existing login'});return;
  }
  await reloadProfiles();
  lastLocalRp=info.rp;lastLocalRpAt=Date.now();
  const matches=BridgeProfiles.candidates(profiles,info.rp);
  const p={id,options,rp:info.rp,fingerprint:fp,started:Date.now(),status:'queued',tabId:null,windowId:null,signingWindowId:null,timer:null,
    origin:null,pageUrl:null,profileId:null,profileName:null,match:null,
    observedTopOrigin:packet.observedTopOrigin||null,diagnosticsTag:null,
    forceManual:packet.forceManual===true,
    backgroundSigning:packet.backgroundSigning===true,
    requestedProfileId:typeof packet.preferredProfileId==='string'?packet.preferredProfileId:null,
    authenticatorPreference:['default','security-key','client-device','hybrid'].includes(packet.authenticatorPreference)?
      packet.authenticatorPreference:'default'};
  pending.set(id,p);
  p.timer=setTimeout(()=>finish(id,{ok:false,error:'WebAuthn request expired in remote queue'}).catch(()=>{}),MAX_REQUEST_AGE_MS);
  requestQueue.push(id);
  await log('info','challenge-received',
    `RP=${info.rp} fp=${fp} matches=${matches.length} allowedCredentials=${Array.isArray(options.allowCredentials)?options.allowCredentials.length:0} UV=${options.userVerification||'preferred'} transports=${(options.allowCredentials||[]).map(x=>(x.transports||[]).join('+')||'unknown').join(';')||'none'} hint=${p.authenticatorPreference} localTab=${p.observedTopOrigin||'unknown'} (caller origin unverified)`,id);
  await log('info','request-queued',`Queue position ${queuedPosition(id)}; ${activeRequestId?'a ceremony is active':'next available'}; distinct RP IDs are serialized`,id);
  if(matches.some(x=>x.match==='related'))
    await log('info','related-profile-available','Related origin requires live well-known authorization and Chrome approval',id);
  scheduleNextRequest();
}
async function waitForOrigin(tabId,origin,timeoutMs,requestId=null,followRedirect=false,launchOrigin=origin){
  const started=Date.now();let last='loading',waitLogged=false;
  while(Date.now()-started<timeoutMs){
    if(requestId&&!pending.has(requestId))throw Error('Request canceled during remote page navigation');
    let tab;try{tab=await chrome.tabs.get(tabId);}catch{throw Error('Remote login tab was closed');}
    if(tab.url){
      try{last=new URL(tab.url).origin;}catch{last='unparseable URL';}
      if(tab.status==='complete'){
        if(last!==origin){
          // A complete intermediate launch page may initiate a later redirect.
          // Wait for the configured origin, but never sign on the launch origin.
          if(launchOrigin!==origin && last===launchOrigin){
            if(!waitLogged){
              await log('info','launch-page-wait',`Waiting for ${launchOrigin} to redirect to ${origin}`,requestId||'');
              waitLogged=true;
            }
            await new Promise(r=>setTimeout(r,250));
            continue;
          }
          await log('warn','remote-origin-redirect',`Expected ${origin}; actual ${last}; ${followRedirect?'checking saved redirected-origin profiles':'signing blocked'}`,requestId||'');
          if(!followRedirect)throw Error(`Remote page ended at ${last}, expected ${origin} (redirect/origin mismatch)`);
        }
        return {tab,actualOrigin:last};
      }
    }
    await new Promise(r=>setTimeout(r,200));
  }
  throw Error(`Remote login page did not reach ${origin} within ${Math.round(timeoutMs/1000)} seconds; last origin ${last}`);
}

async function approve(id,profileId,followRedirect=false,launchUrl=null){
  await reloadProfiles();
  const p=pending.get(id);
  if(!p||p.status!=='waiting')return {error:'Request is not waiting for approval'};
  const profile=profiles.find(x=>x.id===profileId);
  if(!profile)return {error:'Selected profile not found. Open Profiles and create a matching one.'};
  if(launchUrl && !(profile.pageUrls||[profile.pageUrl]).includes(launchUrl))
    return {error:'Launch URL is not listed in the chosen saved profile'};
  const match=BridgeProfiles.relation(profile,p.rp);
  if(match==='none')return {error:`Profile ${profile.name} does not permit RP ${p.rp}`};
  if(!await chrome.permissions.contains({origins:[BridgeProfiles.sitePattern(profile.origin)]}))
    return {error:'Site permission missing for '+profile.origin+'. Allow site access in the remote extension’s Chrome settings.'};
  if(!pending.has(id)||p.status!=='waiting')return {error:'Request canceled during profile validation'};
  p.status='verifying-profile';
  if(match==='related'){
    await log('info','related-origin-check',`Checking RP ${p.rp} permits remote origin ${profile.origin}`,id);
    const r=await checkRelatedOrigin(profile,p.rp);
    await log(r.ok?'success':'warn',r.ok?'related-origin-verified':'related-origin-denied',r.reason,id);
    if(!pending.has(id))return {error:'Local request was canceled during RP verification'};
    if(!r.ok){p.status='waiting';return {error:r.reason};}
  }
  if(!pending.has(id))return {error:'Local request was canceled'};
  p.origin=profile.origin;p.pageUrl=launchUrl||profile.pageUrl;
  p.profileId=profile.id;p.profileName=profile.name;p.match=match;
  await log('info','launch-page-selected',
    `${profile.group} / ${profile.name}; entry ${new URL(p.pageUrl).origin}${new URL(p.pageUrl).pathname}; signer ${p.origin}`,id);
  p.status='opening-remote-tab';
  p.followRedirect=followRedirect===true;
  if(p.followRedirect)await log('warn','redirect-test-armed','One-request opt-in: follow only to another saved, origin-verified profile for this exact RP ID',id);
  await log('info','profile-selected',`${profile.name}; ${match}; ${profile.origin}; RP ${p.rp}`,id);
  (async()=>{
    try{
      const autoStart=p.streamlinedAuto===true || profile.autoInvoke===true;
      p.backgroundSigningActive=p.backgroundSigning===true && !p.forceManual && autoStart;
      if(p.backgroundSigning && !p.backgroundSigningActive)
        await log('info','background-signing-manual','Using an active tab because this request requires manual interaction',id);
      const page=await BridgeSigningPage.open(p.pageUrl,p.backgroundSigningActive);
      if(!pending.has(id)){await BridgeSigningPage.close(page);return;}
      p.tabId=page.tabId;p.signingWindowId=page.windowId;
      const tab={id:page.tabId};
      await log('info','signing-page-opened',p.backgroundSigningActive?
        'Small unfocused signing window; native WebAuthn may still require focus':
        'Active signing tab',id);
      const navigation=await waitForOrigin(tab.id,p.origin,60000,id,p.followRedirect,new URL(p.pageUrl).origin);
      if(!pending.has(id))return;
      if(navigation.actualOrigin!==p.origin){
        // A redirect never changes the origin silently. An independently saved
        // second profile for this exact RP and origin must authorize it.
        await reloadProfiles();
        const target=profiles.find(x=>x.rpId===p.rp&&x.origin===navigation.actualOrigin);
        if(!target)throw Error(`Redirect to ${navigation.actualOrigin}; no SAVED profile authorizes RP ${p.rp} at that origin. Add an explicit related-origin profile; nothing was signed.`);
        const targetMatch=BridgeProfiles.relation(target,p.rp);
        if(targetMatch==='none')throw Error('Redirected origin profile does not permit this RP ID');
        if(!await chrome.permissions.contains({origins:[BridgeProfiles.sitePattern(target.origin)]}))
          throw Error('Missing Chrome site permission for redirected origin '+target.origin);
        if(targetMatch==='related'){
          const r=await inspectRelation(target,p.rp);
          await log(r.ok?'success':'warn','redirect-related-origin-check',`${target.name}: ${r.reason}`,id);
          if(!r.ok)throw Error(`Redirected origin not authorized for RP ${p.rp}: ${r.reason}`);
        }
        if(!pending.has(id))return;
        await log('success','redirect-profile-selected',`${profile.name} → ${target.name}; ${target.origin}; ${targetMatch}; same RP ${p.rp}`,id);
        p.origin=target.origin;p.profileId=target.id;p.profileName=target.name;p.match=targetMatch;
      }
      p.status='injecting-site';
      p.diagnosticsTag=crypto.randomUUID();
      await log('info','site-injection-start',`MAIN-world WebAuthn panel requested on ${p.origin}; profile ${p.profileName}`,id);
      // Install a diagnostic-only reporter first; never rely on webpage messages
      // for the origin/RP decision or the returned WebAuthn assertion.
      await chrome.scripting.executeScript({target:{tabId:tab.id},world:'ISOLATED',func:installPageStageRelay,
        args:[id,p.diagnosticsTag,p.origin]});
      const selectedRule=profiles.find(r=>r.id===p.profileId);
      const autoInvoke=p.streamlinedAuto===true || selectedRule?.autoInvoke===true;
      const responses=await chrome.scripting.executeScript({target:{tabId:tab.id},world:'MAIN',func:runSiteCeremony,
        args:[p.options,p.origin,p.rp,p.fingerprint,p.diagnosticsTag,autoInvoke,p.authenticatorPreference,p.streamlinedAuto===true]});
      if(!pending.has(id))return;
      const result=responses?.[0]?.result;
      if(!result||result.ok!==true) {
        const phase=String(result?.phase||'injected script').slice(0,55);
        const name=String(result?.name||'Error').slice(0,40);
        const message=String(result?.error||'No credential returned by remote browser').slice(0,150);
        throw Error(p.backgroundSigningActive?
          `Background signing failed. Turn off background signing in local and retry. [${name}] ${message}`:
          `Remote ${phase} [${name}]: ${message}`);
      }
      if(result.pageOrigin!==p.origin)throw Error('Remote site returned a different origin');
      await BridgeValidate.assertion(result.credential,p.options,p.origin,p.match==='related');
      // Extension output is only trusted after BridgeValidate checks the
      // matching RP or AppID hash and the rest of the signed assertion data.
      const usedLegacyAppId=result.credential.clientExtensionResults?.appid===true;
      await log('success','assertion-validated',
        `Challenge, origin, ${usedLegacyAppId?'legacy AppID':'RP ID'} hash, UP and UV verified; profile ${p.profileName}`,id);
      if(typeof p.options?.extensions?.appid==='string')
        await log('info','webauthn-appid-result',
          `Legacy AppID requested; actually used=${usedLegacyAppId}; hashed scope=${usedLegacyAppId?'AppID URL':'RP ID'}; server acceptance not confirmed`,id);
      if(p.observedTopOrigin&&p.observedTopOrigin!==p.origin)
        await log('warn','observed-origin-differs',
          `Remote assertion origin ${p.origin}; local foreground tab ${p.observedTopOrigin} (NOT verified caller origin). RP may reject this assertion.`,id);
      await finish(id,{ok:true,credential:result.credential});
    }catch(e){
      if(pending.has(id)){
        const message=String(e.message||e).slice(0,170);
        await log('error','remote-sign-failed',message,id);
        await finish(id,{ok:false,error:message});
      }
    }
  })();
  return {ok:true};
}
async function enable(next){
  await profilesReady;
  const cfg={relayUrl:next.relayUrl,pairingKey:next.pairingKey};
  if(enabled && config?.relayUrl===cfg.relayUrl && config?.pairingKey===cfg.pairingKey){
    await log('info','relay-config-unchanged','Keeping existing relay pairing and connection');
    // Do not create another same-role socket while the first is OPEN,
    // CONNECTING, or the scheduled reconnect is still pending.
    if(!ws && !retryTimer) connect();
    checkRelayHealth().catch(()=>{});
    return;
  }
  const ctx=await BridgeCrypto.init(cfg.pairingKey);
  BridgeCrypto.relayURL(cfg.relayUrl,ctx.room,ROLE);
  await cancelAll(false);closeConnection();
  context=ctx;config=cfg;enabled=true;lastError='';retryDelay=1500;
  await chrome.storage.local.set({...cfg,enabled:true});
  await log('info','remote-enabled',`${profiles.length} saved IdP profiles`);
  connect();startMonitor().catch(()=>{});
}
async function disable(){
  enabled=false;await chrome.storage.local.set({enabled:false});
  await cancelAll(true);closeConnection();connectionState='disabled';
  health='unknown';healthAt=0;linkAt=0;healthDetail='Disconnected';updateIndicator();
  await log('info','remote-disabled','Disconnected, pending requests cleared');
}
async function linkTest(silent=false){
  if(!connected()||!peerOnline)return {error:'Both extensions must be online'};
  const id=crypto.randomUUID();
  return new Promise(resolve=>{
    const timer=setTimeout(()=>{pings.delete(id);if(!silent)log('warn','link-test-timeout');linkAt=0;updateIndicator();resolve({error:'No encrypted response within 8 seconds'});},8000);
    pings.set(id,{timer,resolve,started:Date.now()});
    send({kind:'diag-ping',id}).then(()=>{if(!silent)log('info','link-test-sent');}).catch(e=>{clearTimeout(timer);pings.delete(id);resolve({error:e.message});});
  }).then(r=>{if(r.ok&&!silent)log('success','link-test-ok',`Encrypted RTT ${r.rttMs}ms`);return r;});
}
async function handleCommand(msg,sender={}){
  return (async()=>{
    await profilesReady;
    switch(msg?.action){
      case 'capabilityProbeResult':{
        const job=capabilityJobs.get(msg.nonce);
        if(!job||sender?.id!==chrome.runtime.id||
           !sender?.url?.startsWith(chrome.runtime.getURL('capability.html'))||
           (job.tabId!==null&&sender?.tab?.id!==job.tabId))return {ok:false};
        job.resolve({available:msg.available===true,source:String(msg.source||'unknown').slice(0,35),
          error:msg.error?String(msg.error).slice(0,120):null});
        return {ok:true};
      }
      case 'probePlatform':return {ok:true,...await measureRemotePlatform(msg.fresh===true)};
      case 'idpTraceEvent':{
        const d=msg.payload;
        if(!traceOrigin||!sender?.tab||!sender?.url||!d||
           new URL(sender.url).origin!==traceOrigin)return {ok:false};
        const types=['installed','isolated-ready','unavailable','hook-ready','hook-failed','get-start','get-resolved','get-rejected'];
        if(!types.includes(d.kind))return {ok:false};
        const source=['bridge','site'].includes(d.source)?d.source:'unknown';
        const detail=`origin=${traceOrigin} frame=${d.frame==='top'?'top':'subframe'} source=${source} `+
          `mediation=${String(d.mediation||'').slice(0,24)} rp=${String(d.rp||'').slice(0,100)} `+
          `allow=${Number.isInteger(d.allowCount)?d.allowCount:'-'} transports=${String(d.transports||'-').slice(0,64)} `+
          `uv=${String(d.uv||'-').slice(0,20)} hints=${String(d.hints||'-').slice(0,64)} appid=${d.appidPresent===true} `+
          `ms=${Number.isFinite(d.ms)?d.ms:'-'} ${String(d.name||'').slice(0,40)} ${String(d.message||'').slice(0,100)}`;
        await log(d.kind==='get-rejected'?'warn':'info','idp-trace-'+d.kind,detail);
        return {ok:true};
      }
      case 'traceStatus':return {ok:true,...await getTraceStatus()};
      case 'traceEnable':return {ok:true,...await enableTrace(msg.origin)};
      case 'traceDisable':return {ok:true,...await disableTrace()};
      case 'pageStage':{
        // Diagnostic events are generated in an IdP webpage and must be untrusted.
        const p=pending.get(msg.id);
        if(!p||!p.diagnosticsTag||msg.tag!==p.diagnosticsTag||
           sender?.tab?.id!==p.tabId||sender?.frameId!==0)return {ok:false};
        const code=String(msg.stage||'');
        const accepted=['site-overlay-ready','remote-button-clicked','webauthn-get-start',
          'webauthn-context','webauthn-error-source','webauthn-native-busy',
          'webauthn-request-shape','webauthn-transport-warning','webauthn-authenticator',
          'webauthn-hint-applied','webauthn-auto-start','webauthn-auto-fallback','webauthn-ui-style',
          'webauthn-get-resolved','webauthn-get-rejected','webauthn-silent-start','webauthn-isolated-frame','webauthn-isolated-failed','site-setup-rejected','page-canceled'];
        if(!accepted.includes(code))return {ok:false};
        const detail=typeof msg.detail==='string'?msg.detail.slice(0,180):'';
        if(code==='site-overlay-ready')p.status='awaiting-site-click';
        if(code==='remote-button-clicked')p.status='remote-button-clicked';
        if(code==='webauthn-get-start')p.status='browser-webauthn-in-progress';
        await log(code.includes('rejected')?'error':code==='webauthn-transport-warning'?'warn':'info',code,detail,p.id);
        return {ok:true};
      }
      case 'setStreamlinedMode':{
        streamlinedMode=msg.enabled===true;
        await chrome.storage.local.set({streamlinedMode});
        await log('info','remote-flow-mode',streamlinedMode?
          'Automatic authentication for uniquely matched saved RPs; only native authenticator consent remains':
          'Manual profile approval enabled');
        return {ok:true,streamlinedMode};
      }
      case 'enable':await enable(msg);return {ok:true};
      case 'disable':await disable();return {ok:true};
      case 'checkHealth':await checkRelayHealth();return {ok:true,health,healthDetail};
      case 'getConfig':return {ok:true,settings:await chrome.storage.local.get(['relayUrl','pairingKey','streamlinedMode','relayDraftUrl','relayDraftPairingKey'])};
      case 'listProfiles':await reloadProfiles();return {ok:true,profiles,updatedAt:Date.now()};
      case 'saveProfile':{
        await reloadProfiles();
        const p=BridgeProfiles.normalize(msg.profile);
        const requiredOrigins=[BridgeProfiles.sitePattern(p.origin)];
        if(BridgeProfiles.relation(p,p.rpId)==='related')requiredOrigins.push(BridgeProfiles.sitePattern('https://'+p.rpId));
        const missingPermissions=[];
        for(const origin of requiredOrigins){
          if(!await chrome.permissions.contains({origins:[origin]}))missingPermissions.push(origin);
        }
        profiles=profiles.filter(x=>x.id!==p.id).map(x=>
          p.preferredForRp && x.rpId===p.rpId ? {...x,preferredForRp:false} : x).concat(p);
        await chrome.storage.local.set({profiles});
        shareProfileInventory().catch(e=>log('warn','profile-inventory-sync-failed',e.message));
        await log('info','profile-saved',`${p.group} / ${p.name}: ${p.origin}, RP ${p.rpId}, quickStart=${p.quickStart}, launchURLs=${p.pageUrls.length}, mode ${BridgeProfiles.relation(p,p.rpId)}`);
        return {ok:true,profile:p,missingPermissions};
      }
      case 'deleteProfile':{
        await reloadProfiles();
        if(pending.size)throw Error('Cannot delete profiles during a pending login');
        profiles=profiles.filter(p=>p.id!==msg.id);await chrome.storage.local.set({profiles});
        shareProfileInventory().catch(e=>log('warn','profile-inventory-sync-failed',e.message));
        await log('info','profile-deleted','Profile removed');return {ok:true};
      }
      case 'relatedOriginCheck':{
        await reloadProfiles();
        const p=profiles.find(x=>x.id===msg.profileId);
        if(!p)return {error:'Profile not found for selected ID; refresh Profiles and retry',requestedProfileId:String(msg.profileId||'').slice(0,36)};
        const outcome=await inspectRelation(p,p.rpId);
        await log(outcome.ok?'info':'warn','profile-relation-inspected',`${p.name}; ${p.origin}; RP ${p.rpId}; mode ${outcome.mode}; fetched well-known ${outcome.checked}; ${outcome.reason}`);
        return outcome;
      }
      case 'status':return {ok:true,role:ROLE,version:VERSION,enabled,connectionState,connected:connected(),peerOnline,
        health,healthDetail,healthAt,linkAt,indicator:BridgeIndicator.state(indicatorInput()),
        relayHost:relayHost(),attempts,connectedAt:attachedAt,lastError,profileCount:profiles.length,
        lastLocalRp:lastLocalRp&&Date.now()-lastLocalRpAt<1800000?lastLocalRp:null,
        remotePlatform:remotePlatformResult,
        streamlinedMode,activeRequestId:activeRequestId?.slice(0,8)||null,queueDepth:requestQueue.length,
        pending:Array.from(pending.values()).map(p=>({id:p.id.slice(0,8),rp:p.rp,fingerprint:p.fingerprint,status:p.status,queuePosition:queuedPosition(p.id),
          profile:p.profileName||null,match:p.match||null,ageSeconds:Math.round((Date.now()-p.started)/1000)})),
        events:(await BridgeDiag.snapshot()).slice(-12)};
      case 'diagnostics':await reloadProfiles();return {ok:true,role:ROLE,version:VERSION,enabled,connected:connected(),peerOnline,connectionState,lastError,
        health,healthDetail,healthAt,linkAt,indicator:BridgeIndicator.state(indicatorInput()),
        relayHost:relayHost(),streamlinedMode,remotePlatform:remotePlatformResult,trace:await getTraceStatus(),
        profiles:profiles.map(p=>({name:p.name,origin:p.origin,rpId:p.rpId,mode:BridgeProfiles.relation(p,p.rpId)})),
        queueDepth:requestQueue.length,activeRequestId:activeRequestId?.slice(0,8)||null,events:await BridgeDiag.snapshot()};
      case 'clearLogs':await BridgeDiag.clear();return {ok:true};
      case 'linkTest':return await linkTest();
      case 'pending':{
        await reloadProfiles();
        const p=pending.get(msg.id);
        if(!p)return {error:'No longer pending'};
        return {ok:true,id:p.id,rp:p.rp,origin:p.origin||'',status:p.status,
          queuePosition:queuedPosition(p.id),queueDepth:requestQueue.length,activeRequestId:activeRequestId?.slice(0,8)||null,
          uv:p.options.userVerification||'preferred',authenticatorPreference:p.authenticatorPreference,
          fingerprint:p.fingerprint,selectedProfile:p.profileName||'',observedTopOrigin:p.observedTopOrigin,
          savedProfiles:profiles.map(pr=>profileSummary(pr,p.rp)),profileCount:profiles.length,
          matches:BridgeProfiles.candidates(profiles,p.rp).map(c=>({id:c.id,name:c.name,group:c.group,
            origin:c.origin,mode:c.match,pageUrls:c.pageUrls||[c.pageUrl],quickStart:c.quickStart}))};
      }
      case 'approve':return await approve(msg.id,msg.profileId,msg.followRedirect===true,msg.launchUrl||null);
      case 'deny':await finish(msg.id,{ok:false,error:'Denied on remote computer'});return {ok:true};
      default:return {error:'Unknown action'};
    }
  })();
}
chrome.runtime.onMessage.addListener((msg,sender,reply)=>{
  handleCommand(msg,sender).then(reply,e=>{lastError=String(e.message||e);log('error','command-error',lastError);reply({error:lastError});});
  return true;
});
chrome.windows.onRemoved.addListener(windowId=>{
  for(const p of pending.values())if(p.signingWindowId===windowId){
    finish(p.id,{ok:false,error:'Signing window closed before completion'}).catch(()=>{});break;
  }else if(p.windowId===windowId&&p.status==='waiting'){
    finish(p.id,{ok:false,error:'Approval window closed'}).catch(()=>{});break;
  }
});
chrome.tabs.onRemoved.addListener(tabId=>{
  for(const p of pending.values())if(p.tabId===tabId){
    finish(p.id,{ok:false,error:'Remote login tab closed before completion'}).catch(()=>{});break;
  }
});
(async()=>{
  await profilesReady;
  const saved=await chrome.storage.local.get(['enabled','relayUrl','pairingKey','streamlinedMode']);
  streamlinedMode=saved.streamlinedMode!==false;
  if(saved.enabled&&saved.relayUrl&&saved.pairingKey){
    try{await enable(saved);}catch(e){lastError=e.message;enabled=false;connectionState='error';await log('error','remote-restore-failed',e.message);}
  }
})();

getTraceStatus().then(t=>{if(t.registered)traceOrigin=t.origin;}).catch(()=>{});

// Keep the yellow badge visible even before the first successful connection.
updateIndicator();
