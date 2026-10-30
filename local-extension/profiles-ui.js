/* global BridgeProfiles */
const $=id=>document.getElementById(id),ask=(action,details={})=>chrome.runtime.sendMessage({action,...details});
let list=[];
let grantCache={key:'',missing:[]};
$('grantAllHttps').hidden=true;
$('grantAllStatus').textContent='Preflight checks the local sign-in page and may ask for local site access. The remote bridge separately requires HTTPS access for signing.';

let recentLocalRp=null;
const advancedKeys=['name','group','rp','origin','page','related'];
function inferredDirect(host,rp){return host===rp||host.endsWith('.'+rp);}
function syncBasicToAdvanced(){
  const provider=$('provider').value.trim();
  const login=$('loginUrl').value.trim();
  if(!$('name').dataset.manual)$('name').value=provider;
  if(!$('group').dataset.manual)$('group').value=provider;
  if(!$('page').dataset.manual)$('page').value=login;
  let parsed=null;
  try{parsed=new URL(login);}catch{}
  if(parsed&&parsed.protocol==='https:'){
    if(!$('origin').dataset.manual)$('origin').value=parsed.origin;
    if(!$('rp').dataset.manual){
      const host=parsed.hostname;
      $('rp').value=recentLocalRp&&inferredDirect(host,recentLocalRp)?recentLocalRp:host;
    }
  }
  const current=$('rp').value.trim(),actual=$('origin').value.trim();
  let mode='not configured';
  if(current&&actual){
    try{const host=new URL(actual).hostname;
      mode=inferredDirect(host,current)?'direct match':'related-origin authorization required';
      if(!$('related').dataset.manual)$('related').checked=!inferredDirect(host,current);
    }catch{}
  }
  $('inference').textContent=`Suggested RP: ${current||'(enter URL)'} · signing origin: ${actual||'(unknown)'} · ${mode}.`+
    (recentLocalRp?` Last local challenge RP: ${recentLocalRp}.`: ' Start a local login to discover the RP automatically.');
  probeProfileGrants().catch(()=>{});
}

function requiredPatterns(p){
  const result=[BridgeProfiles.sitePattern(p.origin)];
  if(BridgeProfiles.relation(p,p.rpId)==='related')
    result.push(BridgeProfiles.sitePattern('https://'+p.rpId));
  return [...new Set(result)];
}
async function probeProfileGrants(){
  let patterns;try{patterns=requiredPatterns(BridgeProfiles.normalize(fields()));}
  catch{return;}
  const key=patterns.join('|'),missing=[];
  for(const pattern of patterns)
    if(!await chrome.permissions.contains({origins:[pattern]}))missing.push(pattern);
  // A queued response for an older editing state must not overwrite the cache.
  try{if(requiredPatterns(BridgeProfiles.normalize(fields())).join('|')===key)
    grantCache={key,missing};}catch{}
}
function report(msg){$('result').textContent=msg;}
function fields(){return {id:$('id').value,name:$('name').value,group:$('group').value,
  rpId:$('rp').value,origin:$('origin').value,pageUrl:$('page').value,
  pageUrls:$('extraPages').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean),
  quickStart:$('quickStart').checked,autoInvoke:$('autoInvoke').checked,
  autoRedirect:$('autoRedirect').checked,preferredForRp:$('preferredForRp').checked,
  allowRelatedOrigins:$('related').checked};}
function fill(p){
  for(const field of advancedKeys)delete $(field).dataset.manual;
  $('provider').value=p.group||p.name||'';
  $('loginUrl').value=p.pageUrl||'';
  // Existing RP/origin associations must never silently change when the user edits the launch URL.
  if(p.id||p.rpId){for(const field of ['name','rp','origin','related'])$(field).dataset.manual='1';}
  $('id').value=p.id||'';$('name').value=p.name||'';$('group').value=p.group||p.name||'';
  $('rp').value=p.rpId||'';$('origin').value=p.origin||'';
  $('page').value=p.pageUrl||'';
  $('extraPages').value=(p.pageUrls||[]).filter(u=>u!==p.pageUrl).join('\n');
  $('quickStart').checked=p.quickStart===true;
  $('autoInvoke').checked=p.autoInvoke===true;
  $('autoRedirect').checked=p.autoRedirect===true;
  $('preferredForRp').checked=p.preferredForRp===true;
  $('related').checked=!!p.allowRelatedOrigins;
  $('simpleAuto').checked=p.quickStart===true&&p.autoInvoke===true;
  syncBasicToAdvanced();
  probeProfileGrants().catch(()=>{});
  $('formTitle').textContent=p.id?'Edit '+p.name:'Add an IdP profile';window.scrollTo({top:document.getElementById('formTitle').offsetTop-16,behavior:'smooth'});
}
async function refresh(){
  const r=await ask('listProfiles');if(!r.ok)throw Error(r.error||'Profile list unavailable');list=r.profiles||[];
  const root=$('list');root.replaceChildren();
  if(!list.length){root.textContent='No saved profiles. Create one below.';return;}
  let previousGroup=null;
  for(const p of [...list].sort((a,b)=>(a.group||a.name).localeCompare(b.group||b.name)||a.name.localeCompare(b.name))){
    const group=p.group||p.name;
    if(group!==previousGroup){
      const heading=document.createElement('h3');heading.textContent=group;
      heading.style.marginTop='18px';root.append(heading);previousGroup=group;
    }
    const article=document.createElement('article');article.className='profile';
    const line=document.createElement('div');line.className='line';
    const name=document.createElement('strong');name.textContent=p.name;
    const info=document.createElement('code');info.textContent=`RP ${p.rpId} → ${p.origin}`;
    const mode=document.createElement('span');mode.className='pill';mode.textContent=BridgeProfiles.relation(p,p.rpId)==='related'?'RELATED · needs live check':'DIRECT · no related-origin check';
    const url=document.createElement('div');url.className='hint';
    url.textContent='Launch: '+new URL(p.pageUrl).origin+new URL(p.pageUrl).pathname+
      ((p.pageUrls||[]).length>1?' · '+(p.pageUrls.length-1)+' alternate(s)':'')+
      (p.quickStart?' · quick-start enabled':'')+
      (p.autoInvoke?' · auto opens remote Chrome chooser':'')+
      (p.autoRedirect?' · verified redirect opt-in':'')+
      (p.preferredForRp?' · preferred RP rule':'');
    const actions=document.createElement('div');actions.className='actions';
    function button(label,callback){const b=document.createElement('button');b.textContent=label;b.onclick=callback;actions.append(b);}
    button('Edit',()=>fill(p));
    button('Add rule to group',()=>fill({group,name:'',origin:'',rpId:'',pageUrl:''}));
    button('Preflight',async()=>{report('Preflight for '+p.name+'...');const r=await BridgePreflightUI.run(p);report(JSON.stringify(r,null,2));});
    button('Explain origin check',async()=>{const r=await ask('relatedOriginCheck',{profileId:p.id});report(JSON.stringify(r,null,2));});
    if(BridgeProfiles.relation(p,p.rpId)==='related')button('Verify related origins',async()=>{const r=await ask('relatedOriginCheck',{profileId:p.id});report(JSON.stringify(r,null,2));});
    button('Delete',async()=>{if(!confirm('Delete profile '+p.name+'?'))return;const r=await ask('deleteProfile',{id:p.id});report(r.error||'Deleted');refresh();});
    line.append(name,mode,info);article.append(line,url,actions);root.append(article);
  }
}
for(const field of ['provider','loginUrl']){
  $(field).addEventListener('input',syncBasicToAdvanced);
  $(field).addEventListener('change',syncBasicToAdvanced);
}
for(const field of advancedKeys){
  $(field).addEventListener('input',()=>{$(field).dataset.manual='1';syncBasicToAdvanced();});
  $(field).addEventListener('change',()=>{$(field).dataset.manual='1';syncBasicToAdvanced();});
}
$('simpleAuto').addEventListener('change',()=>{
  const on=$('simpleAuto').checked;
  $('quickStart').checked=on;
  $('autoInvoke').checked=on;
  $('autoRedirect').checked=on;
  $('preferredForRp').checked=on;
});
$('useLastRp').onclick=()=>{
  if(!recentLocalRp)return;
  $('rp').dataset.manual='1';$('rp').value=recentLocalRp;
  $('related').dataset.manual='1';
  try{$('related').checked=!inferredDirect(new URL($('origin').value).hostname,recentLocalRp);}catch{}
  $('advanced').open=true;
  syncBasicToAdvanced();
  report('The RP was filled from the recent local challenge. Confirm the origin relationship before saving.');
};
$('form').onsubmit=async e=>{
  e.preventDefault();
  try{
    syncBasicToAdvanced();
    const p=BridgeProfiles.normalize(fields());
    const result=await ask('saveProfile',{profile:p});
    if(result.error)throw Error(result.error);
    fill({});await refresh();
    report(result.missingPermissions?.length ?
      'Saved '+p.name+'. Remote site access is needed for '+result.missingPermissions.join(', ')+'. Allow the site in the remote extension’s Chrome site-access settings, then run Preflight here.' :
      'Saved '+p.name+'. Run Preflight before testing with a YubiKey.');
  }catch(error){report('Could not save: '+error.message);}
};
$('reset').onclick=()=>{fill({});report('');};
for(const field of ['origin','rp','related']){
  $(field).addEventListener('input',()=>probeProfileGrants().catch(()=>{}));
  $(field).addEventListener('change',()=>probeProfileGrants().catch(()=>{}));
}
$('microsoft').onclick=()=>{
  fill({name:'Microsoft Entra · trial',group:'Microsoft 365',rpId:'login.microsoft.com',origin:'https://login.microsoft.com',pageUrl:'https://login.microsoft.com/',allowRelatedOrigins:false});
  report('Example only. Confirm the local RP ID, and run preflight to check for redirects.');
};
$('microsoftOnline').onclick=()=>{
  fill({name:'Microsoft Online · redirect trial',group:'Microsoft 365',rpId:'login.microsoft.com',origin:'https://login.microsoftonline.com',pageUrl:'https://login.microsoftonline.com/',allowRelatedOrigins:true});
  report('Redirected-origin trial. Saving is not proof that Microsoft authorizes this origin for RP login.microsoft.com. Click Explain origin check to obtain verified details.');
};
$('inspect').onclick=()=>chrome.tabs.create({url:chrome.runtime.getURL('diagnostics.html')});
const rpFromLink=new URL(location.href).searchParams.get('rp');
if(rpFromLink&&/^[a-zA-Z0-9.-]{4,253}$/.test(rpFromLink)){
  $('rp').value=rpFromLink; $('rp').dataset.manual='1';
  report('RP ID prefilled from pending request. Enter the correct REMOTE login origin after verifying it independently.');
}
probeProfileGrants().catch(()=>{});
refresh().catch(e=>report(e.message));
ask('status').then(r=>{
  if(r?.lastLocalRp){recentLocalRp=r.lastLocalRp;$('useLastRp').hidden=false;
    $('useLastRp').textContent='Use recent RP: '+recentLocalRp;syncBasicToAdvanced();}
}).catch(()=>{});

