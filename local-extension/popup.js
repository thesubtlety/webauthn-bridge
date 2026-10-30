const $=id=>document.getElementById(id);
const ask=(action,values={})=>chrome.runtime.sendMessage({action,...values});
const statusText=(on,label)=>`${on?'●':'○'} ${label}`;
// Probe before Connect. Calling permissions.request after awaiting an API
// can lose Chrome's user gesture; never await a permission probe on click.
const relayGrant={pattern:null,granted:false};
function relayPattern(wss){
  const url=new URL(wss);
  if(url.protocol!=='wss:'||url.pathname!=='/'||url.search||url.hash)
    throw Error('Use a WSS relay origin ending in /');
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

function showEvents(events){
  const root=$('events');root.replaceChildren();
  if(!events?.length){root.textContent='No events yet.';return;}
  for(const e of events.slice(-4).reverse()){
    const div=document.createElement('div');div.className='event';div.dataset.level=e.level;
    for(const [txt,cls]of [[e.code+(e.id?' · '+e.id:''),'title'],[new Date(e.t).toLocaleTimeString(),'meta'],[e.detail,'detail']]){
      const span=document.createElement('span');span.className=cls;span.textContent=txt;div.append(span);
    }
    root.append(div);
  }
}
async function refresh(){
  try{
    const r=await ask('status');
    $('enabled').textContent=statusText(r.attached,r.attached?'Attached':'Detached');
    $('relayStatus').textContent=statusText(r.connected,r.connectionState||'Offline');
    $('peer').textContent=statusText(r.peerOnline,r.peerOnline?'Online':'Offline');
    if(!$('backgroundSigning').disabled)$('backgroundSigning').checked=r.backgroundSigning===true;
    $('pending').textContent=r.pending?.length||'0';
    $('lastError').textContent=r.lastError||'';
    $('health').textContent=r.health==='ok'?'200 ok':r.health==='bad'?'FAILED: '+r.healthDetail:'Not checked: '+(r.healthDetail||'unknown');
    $('indicator').textContent=(r.indicator||'yellow').toUpperCase()+(r.linkAt?' · E2EE ping verified':' · peer ping pending');
    showEvents(r.events);
    const picker=$('profileChoice'),old=picker.value;
    const rules=r.localProfiles||[];
    picker.replaceChildren();
    const empty=document.createElement('option');empty.value='';empty.textContent='Choose a remotely saved profile';
    picker.append(empty);
    for(const p of rules){
      const opt=document.createElement('option');opt.value=p.id;
      opt.textContent=`${p.group||p.name} · RP ${p.rpId} → ${p.origin}`+
        (p.quickStart?'':' (enable Quick-start remotely)');
      picker.append(opt);
    }
    if(rules.some(p=>p.id===old))picker.value=old;
    const selected=rules.find(p=>p.id===picker.value);
    $('profileSync').textContent=selected?
      `RP ${selected.rpId}: ${r.preferredProfileByRp?.[selected.rpId]===selected.id?'selected for future logins':'not selected'}. Auto-start on remote Chrome: ${selected.autoInvoke}.`:
      `${rules.length} rule(s) synced over E2EE. Select one to override the default for its RP.`;
  }catch(e){$('lastError').textContent=e.message;}
}
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
    $('notice').textContent=r.error|| (granted?'Local proxy enabled; checking health and tunnel.':'Local proxy enabled; health grant denied, badge stays yellow.');
    if(granted && !r.error)ask('checkHealth').catch(()=>{});
    await refresh();
  }catch(e){$('notice').textContent=e.message;}
};
$('disconnect').onclick=async()=>{const r=await ask('disable');$('notice').textContent=r.error||'Local proxy disabled.';await refresh();};
$('diagnostics').onclick=$('more').onclick=()=>chrome.tabs.create({url:chrome.runtime.getURL('diagnostics.html')});
$('setup').onclick=()=>chrome.tabs.create({url:chrome.runtime.getURL('setup.html')});
$('grantAll').onclick=async()=>{
  try{
    const allowed=await chrome.permissions.request({origins:['https://*/*']});
    $('notice').textContent=allowed?'All HTTPS access granted once for future relay URLs.':
      'Broad access declined; relay host can be approved individually.';
    await probeRelayGrant();
  }catch(e){$('notice').textContent=e.message;}
};
$('relay').addEventListener('input',()=>probeRelayGrant().catch(()=>{}));
ask('getConfig').then(r=>{const c=r.settings||{};$('relay').value=c.relayDraftUrl||c.relayUrl||'';$('secret').value=c.relayDraftPairingKey||c.pairingKey||'';return probeRelayGrant();}).catch(()=>{});
refresh();setInterval(refresh,2500);

$('clearRetry').onclick=async()=>{const r=await ask('clearRetryGuard');$('notice').textContent=r.error||'Retry history cleared.';await refresh();};
ask('authenticatorPreference').then(r=>{if(r?.ok)$('authenticator').value=r.preference||'default';}).catch(()=>{});
$('authenticator').onchange=async()=>{
  const r=await ask('setAuthenticatorPreference',{preference:$('authenticator').value});
  $('notice').textContent=r.error||`Chrome chooser preference saved: ${r.preference} (applies to next WebAuthn request)`;
};
$('manualNext').onclick=async()=>{
  const r=await ask('manualNext');
  $('notice').textContent=r.error||'Next login will require manual remote profile selection.';
};
$('nativeVm').onclick=async()=>{
  if(!confirm('Disable the local proxy and retry the website login using WebAuthn devices available on the local computer?'))return;
  const r=await ask('disable');
  $('notice').textContent=r.error||'Proxy detached. Retry sign-in in the local browser.';
  await refresh();
};

$('chooseProfile').onclick=async()=>{
  const r=await ask('setLocalProfile',{profileId:$('profileChoice').value});
  $('notice').textContent=r.error||'Saved: this profile will be preselected on future requests for its RP.';
  await refresh();
};
$('clearProfile').onclick=async()=>{
  const picker=$('profileChoice');
  const status=await ask('status');
  const rule=(status.localProfiles||[]).find(p=>p.id===picker.value);
  if(!rule){$('notice').textContent='Select a profile first';return;}
  const r=await ask('clearLocalProfile',{rpId:rule.rpId});
  $('notice').textContent=r.error||`Removed override for ${rule.rpId}; remote preferred/default rule applies.`;
  await refresh();
};

$('profiles').onclick=()=>chrome.tabs.create({url:chrome.runtime.getURL('profiles.html')});

$('generate').onclick=()=>{$('secret').value=BridgeCrypto.generate();saveDraft();$('notice').textContent='Copy this secret and relay URL to the remote extension.';};

$('copy').onclick=async()=>{
  try{
    const secret=$('secret').value.trim();
    if(!secret)throw Error('Generate a pairing secret first');
    await navigator.clipboard.writeText(secret);
    $('notice').textContent='Pairing secret copied. Paste it into the remote bridge.';
  }catch(e){$('notice').textContent='Could not copy: '+e.message;}
};

$('backgroundSigning').onchange=async()=>{
  const input=$('backgroundSigning');input.disabled=true;
  try{
    const r=await ask('setBackgroundSigning',{enabled:input.checked});
    if(r.error)throw Error(r.error);
    input.checked=r.backgroundSigning===true;
    $('notice').textContent=r.backgroundSigning?
      'Saved. Next automatic login uses a small unfocused temporary window on remote.':
      'Saved. Next login uses an active signing tab.';
  }catch(e){$('notice').textContent=e.message;}
  finally{input.disabled=false;await refresh();}
};
