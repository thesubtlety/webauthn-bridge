/* global chrome, BridgeProfiles */
var BridgePreflight = (() => {
  const patterns=p=>[...new Set([BridgeProfiles.sitePattern(p.origin),
    ...(BridgeProfiles.relation(p,p.rpId)==='related'?[BridgeProfiles.sitePattern('https://'+p.rpId)]:[])])];
  async function waitForPage(tabId,origin){
    const started=Date.now();
    while(Date.now()-started<60000){
      const tab=await chrome.tabs.get(tabId);
      if(tab.status==='complete'){
        const actual=new URL(tab.url).origin;
        if(actual!==origin)throw Error(`Local page redirected to ${actual}; expected ${origin}`);
        return;
      }
      await new Promise(resolve=>setTimeout(resolve,200));
    }
    throw Error('Local sign-in page did not finish loading within 60 seconds');
  }
  async function run(profile){
    const p=BridgeProfiles.normalize(profile);
    const relation=BridgeProfiles.relation(p,p.rpId);
    if(relation==='none')return {ok:false,checkedOn:'local',error:'Profile does not authorize this RP ID and origin'};
    for(const origin of patterns(p)){
      if(!await chrome.permissions.contains({origins:[origin]}))
        return {ok:false,checkedOn:'local',error:'Local site permission missing for '+origin+'. Click Preflight in local Manage profiles to grant it.'};
    }
    let tab;
    try{
      tab=await chrome.tabs.create({url:p.pageUrl,active:true});
      await waitForPage(tab.id,p.origin);
      const results=await chrome.scripting.executeScript({target:{tabId:tab.id},world:'MAIN',func:()=>({
        origin:location.origin,secure:window.isSecureContext,topLevel:window===window.top,
        hasGet:typeof navigator.credentials?.get==='function',
        hasParser:typeof window.PublicKeyCredential?.parseRequestOptionsFromJSON==='function'
      })});
      const report=results?.[0]?.result;
      if(!report||report.origin!==p.origin||!report.secure||!report.topLevel||!report.hasGet||!report.hasParser)
        throw Error('Local page readiness check failed: '+JSON.stringify(report));
      let relatedOrigin={ok:true,checked:false,reason:'Direct RP/origin match'};
      if(relation==='related'){
        const response=await fetch('https://'+p.rpId+'/.well-known/webauthn',{
          credentials:'omit',cache:'no-store',redirect:'follow',signal:AbortSignal.timeout(8000)});
        if(!response.ok||!response.headers.get('content-type')?.toLowerCase().includes('application/json'))
          throw Error('Related-origin declaration could not be read as JSON (HTTP '+response.status+')');
        const body=await response.json();
        relatedOrigin={ok:Array.isArray(body.origins)&&body.origins.includes(p.origin),checked:true};
        if(!relatedOrigin.ok)throw Error('RP does not list '+p.origin+' in /.well-known/webauthn');
      }
      return {ok:true,checkedOn:'local',profile:p.name,rpId:p.rpId,relation,relatedOrigin,report,
        note:'Checked the local page only. No YubiKey operation was requested. Remote readiness and website acceptance are checked during sign-in.'};
    }catch(e){return {ok:false,checkedOn:'local',error:String(e?.message||e)};}
    finally{if(Number.isInteger(tab?.id))await chrome.tabs.remove(tab.id).catch(()=>{});}
  }
  return {run,patterns};
})();
