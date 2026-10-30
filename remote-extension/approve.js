const $=id=>document.getElementById(id);
const id=new URL(location.href).searchParams.get('id');
const ask=(action,extra={})=>chrome.runtime.sendMessage({action,id,...extra});
let pending=null,refreshing=false;
function buttons(){
  $('approve').disabled=!pending||pending.status!=='waiting'||!$('verified').checked||!$('profile').value;
  $('redirect').disabled=!pending||pending.status!=='waiting';
}
function updateLaunchOptions(){
  const p=(pending?.matches||[]).find(x=>x.id===$('profile').value);
  const original=$('launch').value;
  $('launch').replaceChildren();
  for(const url of p?.pageUrls||[]){
    const option=document.createElement('option');option.value=url;
    const u=new URL(url);option.textContent=u.origin+u.pathname+(u.search?' (with query)':'');
    $('launch').append(option);
  }
  if((p?.pageUrls||[]).includes(original))$('launch').value=original;
}
function updateMatches(list){
  // Always rebuild the select: an older approval window must not cache a
  // pre-save snapshot or silently reuse the wrong profile selection.
  const previous=$('profile').value;
  $('profile').replaceChildren();
  for(const p of list){
    const option=document.createElement('option');option.value=p.id;
    option.textContent=`${p.group||p.name} / ${p.name} · ${p.origin} (${p.mode==='related'?'related-origin required':'direct'})`;
    $('profile').append(option);
  }
  if(list.some(p=>p.id===previous))$('profile').value=previous;
  updateLaunchOptions();
  buttons();
}
async function refresh(){
  if(refreshing)return;
  refreshing=true;
  try{
    const p=await ask('pending');
    if(!p?.ok){$('progress').textContent=p?.error||'Request completed or expired.';pending=null;buttons();return;}
    pending=p;
    $('rp').textContent=p.rp;$('uv').textContent=p.uv;$('fingerprint').textContent=p.fingerprint;
    $('authPreference').textContent=p.authenticatorPreference||'default';
    $('observed').textContent=p.observedTopOrigin||'Unavailable';
    $('progress').textContent=p.status==='queued' ?
      `Queued for remote YubiKey (position ${p.queuePosition} of ${p.queueDepth}). Browser authentication is serialized.` :
      'Stage: '+p.status+(p.selectedProfile?' · selected '+p.selectedProfile:'');
    updateMatches(p.matches||[]);
    const notMatched=(p.savedProfiles||[]).filter(x=>x.mode==='none');
    $('matchDetail').textContent=`${p.profileCount??0} saved profile(s); ${(p.matches||[]).length} match RP ${p.rp}. `+
      ((p.matches||[]).length?'Choose the origin actually used by the remote browser.':
      'No matching profile yet; save one using local Manage profiles, then click Refresh.');
    $('inventory').textContent=notMatched.length?'Other saved profiles (not eligible):\n'+
      notMatched.map(x=>`${x.name}: RP ${x.rpId} → ${x.origin} [${x.reason}]`).join('\n'):
      'No other RP mismatches in saved profiles.';
    if(p.status!=='waiting'){
      $('verified').disabled=true;
      $('notice').textContent='This request has already been approved. Profile selection is locked. For a new profile, start a NEW local login attempt.';
    }
    buttons();
  }finally{refreshing=false;}
}
$('verified').onchange=buttons;$('profile').onchange=()=>{updateLaunchOptions();buttons();};
$('approve').onclick=async()=>{
  if(!$('verified').checked||!pending||pending.status!=='waiting')return;
  $('approve').disabled=true;
  const r=await ask('approve',{profileId:$('profile').value,
    launchUrl:$('launch').value,followRedirect:$('redirect').checked});
  $('notice').textContent=r.ok?'Opening remote IdP page. Check its origin in the overlay before touching the key.':
    (r.error||'Unable to approve');
  if(r.error)buttons();
};
$('deny').onclick=async()=>{await ask('deny');window.close();};
$('refresh').onclick=()=>refresh().catch(e=>$('notice').textContent=e.message);
chrome.storage.onChanged.addListener((changes,area)=>{
  if(area==='local'&&changes.profiles)refresh().catch(e=>$('notice').textContent=e.message);
});
refresh().catch(e=>$('notice').textContent=e.message);setInterval(()=>refresh().catch(()=>{}),2000);
