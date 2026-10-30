const $=id=>document.getElementById(id);
const ask=(action,values={})=>chrome.runtime.sendMessage({action,...values});
const label=(on,t)=>`${on?'●':'○'} ${t}`;
// Probe asynchronously when the UI opens or changes. The actual permission
// request must be invoked directly from Connect's click (no prior await).
const relayGrant={pattern:null,granted:false};
function relayPattern(wss){
  const url=new URL(wss);
  if(url.protocol!=='wss:'||url.pathname!=='/'||url.search||url.hash)
    throw Error('Use a WSS origin ending in /');
  return `https://${url.host}/*`;
}
async function probeRelayGrant(){
  const current=$('relay').value.trim();
  let pattern;try{pattern=relayPattern(current);}catch{return;}
  const granted=await chrome.permissions.contains({origins:[pattern]});
  if($('relay').value.trim()===current)Object.assign(relayGrant,{pattern,granted});
}
function requestRelayHealthPermission(wss){
  const pattern=relayPattern(wss);
  if(relayGrant.pattern===pattern && relayGrant.granted)return Promise.resolve(true);
  return chrome.permissions.request({origins:[pattern]}).then(granted=>{
    if(granted)Object.assign(relayGrant,{pattern,granted:true});
    return granted;
  });
}

function showEvents(items){
  const root=$('events');root.replaceChildren();
  if(!items?.length){root.textContent='No events yet.';return;}
  for(const e of items.slice(-4).reverse()){
    const d=document.createElement('div');d.className='event';d.dataset.level=e.level;
    const a=document.createElement('span');a.className='title';a.textContent=e.code+(e.id?' · '+e.id:'');
    const b=document.createElement('span');b.className='meta';b.textContent=new Date(e.t).toLocaleTimeString();
    const c=document.createElement('span');c.className='detail';c.textContent=e.detail;
    d.append(a,b,c);root.append(d);
  }
}
async function refresh(){
  try{
    const [r,p]=await Promise.all([ask('status'),ask('listProfiles')]);
    $('enabled').textContent=label(r.enabled,r.enabled?'Active':'Inactive');
    $('relayStatus').textContent=label(r.connected,r.connectionState||'Offline');
    $('peer').textContent=label(r.peerOnline,r.peerOnline?'Online':'Offline');
    $('profileCount').textContent=String(p.profiles?.length||0);
    $('streamlined').checked=r.streamlinedMode!==false;
    $('queued').textContent=String(r.queueDepth??0);
    $('lastError').textContent=r.lastError||'';
    $('health').textContent=r.health==='ok'?'200 ok':r.health==='bad'?'FAILED: '+r.healthDetail:'Not checked: '+(r.healthDetail||'unknown');
    $('indicator').textContent=(r.indicator||'yellow').toUpperCase()+(r.linkAt?' · E2EE ping verified':' · peer ping pending');
    $('profileSummary').textContent=p.profiles?.length?p.profiles.map(p=>`${p.name}: ${p.rpId} → ${p.origin}`).join('\n'):'No IdP profiles saved. Add one in local Manage profiles.';
    $('profileSummary').style.whiteSpace='pre-wrap';
    showEvents(r.events);
  }catch(e){$('lastError').textContent=e.message;}
}
async function loadSettings(){const r=await ask('getConfig');const c=r.settings||{};
  $('relay').value=c.relayDraftUrl||c.relayUrl||'';
  $('secret').value=c.relayDraftPairingKey||c.pairingKey||'';
}
function notice(t){$('notice').textContent=t;}
const saveDraft=()=>chrome.storage.local.set({relayDraftUrl:$('relay').value.trim(),
  relayDraftPairingKey:$('secret').value.trim()}).catch(()=>{});
let draftTimer=null;
for(const input of [$('relay'),$('secret')])input.addEventListener('input',()=>{
  clearTimeout(draftTimer);draftTimer=setTimeout(saveDraft,150);
});
$('connect').onclick=async()=>{
  try{
    const relayUrl=$('relay').value.trim(),pairingKey=$('secret').value.trim();
    saveDraft(); // Persist before opening a Chrome permission prompt.
    // Dispatch the service-worker enable immediately; it can finish even if
    // Chrome closes this popup for the permission prompt.
    const enablePromise=ask('enable',{relayUrl,pairingKey});
    const permissionPromise=requestRelayHealthPermission(relayUrl);
    const [r,granted]=await Promise.all([enablePromise,permissionPromise]);
    notice(r.error?'Cannot connect: '+r.error:(granted?'Connected; verifying relay and peer.':'Connected; HTTPS health permission denied, badge stays yellow.'));
    if(granted && !r.error)ask('checkHealth').catch(()=>{});
  }catch(e){notice('Connect failed: '+e.message);}
  await refresh();
};
$('disconnect').onclick=async()=>{const r=await ask('disable');notice(r.error||'Disconnected.');await refresh();};
function inspect(){chrome.tabs.create({url:chrome.runtime.getURL('diagnostics.html')});}
$('diagnostics').onclick=inspect;$('more').onclick=inspect;
$('setup').onclick=()=>chrome.tabs.create({url:chrome.runtime.getURL('setup.html')});
$('streamlined').onchange=async()=>{
  const r=await ask('setStreamlinedMode',{enabled:$('streamlined').checked});
  notice(r.error||($('streamlined').checked?'Saved: automatic sign-in for known RPs.':'Saved: manual profile approval.'));
  await refresh();
};
$('relay').addEventListener('input',()=>probeRelayGrant().catch(()=>{}));
loadSettings().then(probeRelayGrant).catch(e=>notice(e.message));refresh();setInterval(refresh,2800);

