const $=id=>document.getElementById(id);
const ask=(action,params={})=>chrome.runtime.sendMessage({action,...params});
let latest=null,loading=false,profiles=[];
function cell(t,c){const e=document.createElement('div');e.className=c||'';e.textContent=String(t??'');return e;}
function fmt(t){try{return new Date(t).toLocaleString();}catch{return t;}}
// Focus on lifecycle, acceptance, and actionable errors. Full raw telemetry
// remains available in Everything and in the complete JSON export.
const importantStages=new Set([
  'relay-connected','relay-closed','relay-heartbeat-stale','relay-socket-error',
  'peer-state','remote-enabled','local-enabled','remote-disabled','local-disabled',
  'challenge-received','local-challenge','request-dequeued','auto-profile-selected',
  'auto-profile-unavailable','auto-profile-failed','profile-selected','quickstart-selected',
  'related-origin-denied','related-origin-verified','site-injection-start',
  'webauthn-silent-start','webauthn-auto-start','webauthn-get-start',
  'webauthn-get-resolved','webauthn-get-rejected','webauthn-authenticator',
  'webauthn-appid-result','webauthn-transport-warning','assertion-validated',
  'assertion-forwarded','assertion-complete','assertion-rejected',
  'remote-sign-failed','request-ended','local-webAuthn-complete',
  'rp-challenge-repeated','remote-queue-full','relay-reclaiming-stale-role',
  'native-ceremony-settling'
]);
const focusEvents=events=>events.filter(e=>['error','warn','success'].includes(e.level)||importantStages.has(e.code));
const explanations=[
  [/no-profile-match|RP ID is incompatible/i,'No saved profile matches the requested RP ID. In Profiles, use the RP from the log (not the application hostname) and select a correct HTTPS remote origin.'],
  [/related-origin-denied|preflight-related-origin/i,'A different remote origin can only sign for this RP if the RP explicitly lists it at /.well-known/webauthn. The browser independently enforces this relationship.'],
  [/remote-origin-redirect/i,'The remote IdP page redirected to another HTTPS origin. Try a stable URL on the configured origin; do not force or spoof the origin.'],
  [/remote-sign-failed/i,'The remote site invocation or Chrome WebAuthn prompt failed. Check the error detail, key enrollment, PIN prompts, and whether the IdP accepts the remote origin.'],
  [/rp-challenge-repeated|retry-loop/i,'The local website repeatedly issued NEW challenges. The bridge delivered earlier credentials, but this is not evidence that the site accepted them. Inspect the signed origin and the IdP login error.'],
  [/relay-socket-error|relay-closed/i,'The WebSocket transport disconnected. Compare relay URL, pairing secret, outbound WSS policy, and duplicate-role sessions.'],
  [/host-permission/i,'Required Chrome extension host permission is missing. Open Profiles, edit and Save the profile, then grant Chrome site access.'],
  [/origin-preflight-failed/i,'The configured remote login page or script-injection preflight failed. A page redirect, browser policy, or missing API can cause this.']
];
function renderExplanation(items){
  const last=items.slice().reverse().find(e=>['error','warn'].includes(e.level)&&!/relay-retry/.test(e.code));
  if(!last){$('analysis').textContent='No warnings or errors logged yet.';return;}
  const matched=explanations.find(([pattern])=>pattern.test(last.code+' '+last.detail));
  $('analysis').textContent=`Last issue: ${last.code} (${fmt(last.t)})\n${last.detail}\n\n${matched?matched[1]:'Use the stage and challenge fingerprint to correlate the VM and remote traces. Errors from the identity provider after WebAuthn completion may not be observable here.'}`;
}
function renderEvents(items){
  const q=$('query').value.trim().toLowerCase();
  const filtered=items.filter(e=>($('verbosity').value==='all'||focusEvents([e]).length>0)&&($('filter').value==='all'||($('filter').value==='warn'&&['warn','error'].includes(e.level))||e.level==='error')&&
    (!q||(e.code+' '+e.id+' '+e.detail).toLowerCase().includes(q)));
  $('count').textContent=`${items.length} events · ${filtered.length} visible`;
  const root=$('logs');root.replaceChildren();
  const header=document.createElement('div');header.className='logrow loghead';
  for(const name of ['Timestamp','Severity','Stage / request','Detail'])header.append(cell(name));root.append(header);
  for(const e of filtered.slice().reverse()){
    const row=document.createElement('div');row.className='logrow';row.dataset.level=e.level;
    row.append(cell(fmt(e.t),'mono'),cell(e.level.toUpperCase()),cell(e.code+(e.id?' · '+e.id:''),'mono'),cell(e.detail,'detail'));root.append(row);
  }
}
async function loadProfiles(){
  const result=await ask('listProfiles');profiles=result.profiles||[];
  const select=$('profileSelect'),old=select.value;select.replaceChildren();
  for(const p of profiles){const o=document.createElement('option');o.value=p.id;o.textContent=p.name+' · RP '+p.rpId;select.append(o);}
  if(profiles.some(x=>x.id===old))select.value=old;
  if(!profiles.length){const o=document.createElement('option');o.textContent='No saved profiles';o.value='';select.append(o);}
}
async function refresh(){
  if(loading)return;loading=true;
  try{
    const [r,st]=await Promise.all([ask('diagnostics'),ask('status')]);latest=r;
    $('version').textContent=`v${r.version} · ${r.role}`;
    $('role').textContent=r.role==='remote'?'Remote browser':'Local browser';
    $('enabled').textContent=r.role==='local'?(st.attached?'Proxy attached':'Detached'):(r.enabled?'Client active':'Disabled');
    $('connection').textContent=r.connectionState||'Unavailable';
    $('peer').textContent=r.peerOnline?'Online':'Offline';
    $('relayHost').textContent=r.relayHost||'Not configured';
    $('pending').textContent=st.pending?.length||0;
    $('healthState').textContent=r.health==='ok'?'200 ok':r.health==='bad'?'FAILED: '+r.healthDetail:'Not checked';
    $('tunnel').textContent=r.linkAt&&r.peerOnline?'Encrypted peer ping verified':'Not yet verified';
    $('indicatorStatus').textContent=(r.indicator||'yellow').toUpperCase();
    $('lastError').textContent=r.lastError||'';
    const items=(st.pending||[]).map(p=>JSON.stringify(p)).join('\n');
    $('pendingInfo').textContent=items||'No pending requests.';
    $('health').href=r.relayHost?'https://'+r.relayHost+'/health':'#';
    $('health').textContent=r.relayHost?'Check relay /health ↗':'No relay host configured';
    $('profilesPanel').hidden=false;$('originPreflight').hidden=false;
    await loadProfiles();
    renderEvents(r.events||[]);renderExplanation(r.events||[]);
  }catch(e){$('testResult').textContent='Inspector unavailable: '+e.message;}
  finally{loading=false;}
}
async function runTest(action,params={}){
  $('testResult').textContent='Running '+action+'...';
  try{const r=await ask(action,params);$('testResult').textContent=JSON.stringify(r,null,2);await refresh();}
  catch(e){$('testResult').textContent='Test failed: '+e.message;}
}
$('linkTest').onclick=()=>runTest('linkTest');
$('originPreflight').onclick=async()=>{
  try{
    const profile=profiles.find(p=>p.id===$('profileSelect').value);
    const result=await BridgePreflightUI.run(profile);
    $('testResult').textContent=JSON.stringify(result,null,2);
  }catch(e){$('testResult').textContent=e.message;}
};
$('rorCheck').onclick=()=>runTest('relatedOriginCheck',{profileId:$('profileSelect').value});
$('profilesOpen').onclick=()=>chrome.tabs.create({url:chrome.runtime.getURL('profiles.html')});
$('refresh').onclick=refresh;
$('clear').onclick=async()=>{await ask('clearLogs');await refresh();};
$('filter').onchange=()=>renderEvents(latest?.events||[]);
$('verbosity').onchange=()=>renderEvents(latest?.events||[]);
$('query').oninput=()=>renderEvents(latest?.events||[]);
$('copySummary').onclick=async()=>{
  const r=await ask('diagnostics');
  const events=focusEvents(r.events||[]).slice(-100);
  const lines=[
    `YubiKey WSS bridge ${r.version} — ${r.role} — ${new Date().toISOString()}`,
    `Status: enabled=${r.enabled} connected=${r.connected} peer=${r.peerOnline} state=${r.connectionState}`,
    `Relay: ${r.relayHost||'unknown'} health=${r.health||'unknown'} (${r.healthDetail||''}); encryptedPing=${r.linkAt?'yes':'no'}`,
    `Pending: ${r.activeRequestId||'none'}; queue=${r.queueDepth??0}`,
    `Last error: ${r.lastError||'none'}`,
    'Recent key events (timestamps, request IDs, RP/origin and browser errors):',
    ...events.map(e=>`${e.t} [${String(e.level).toUpperCase()}] ${e.code}${e.id?' #'+e.id:''} — ${e.detail}`),
    'Note: browser/IdP acceptance after a delivered assertion cannot be confirmed by this relay.'
  ];
  if(r.role==='remote'){
    lines.splice(5,0,'Remote mode: '+(r.streamlinedMode?'automatic for saved RPs':'manual approval'));
    lines.splice(6,0,'Profiles: '+(r.profiles||[]).map(p=>`${p.name} [RP ${p.rpId} → ${p.origin}]`).join('; '));
  }
  try{await navigator.clipboard.writeText(lines.join('\n'));
    $('testResult').textContent='Shareable troubleshooting report copied. It includes RP/origin names and errors, but not raw challenges or pairing keys.';
  }catch(e){$('testResult').textContent='Copy failed: '+e.message;}
};
$('copy').onclick=async()=>{
  const r=await ask('diagnostics');
  const bundle=JSON.stringify({...r,exportedAt:new Date().toISOString(),note:'Redacted metadata only: no pairing key, raw challenge, credential, signature or encrypted packet.'},null,2);
  try{await navigator.clipboard.writeText(bundle);$('testResult').textContent='Redacted JSON copied. Review RP IDs/origins before sharing.';}
  catch(e){$('testResult').textContent='Copy failed: '+e.message;}
};
refresh();setInterval(refresh,3000);
