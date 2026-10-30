/* global chrome */
var BridgePreflightUI = (() => {
  async function run(profile){
    try{
    if(!profile)return {ok:false,error:'Select a saved profile first'};
    const origins=[new URL(profile.origin).origin+'/*'];
    if(profile.allowRelatedOrigins)origins.push('https://'+profile.rpId+'/*');
    // Start from the Preflight click: Chrome requires a local user gesture.
    const granted=await chrome.permissions.request({origins:[...new Set(origins)]});
    if(!granted)return {ok:false,checkedOn:'local',error:'Local site permission was declined'};
    return await chrome.runtime.sendMessage({action:'originPreflight',profileId:profile.id});
    }catch(e){return {ok:false,checkedOn:'local',error:String(e?.message||e)};}
  }
  return {run};
})();
