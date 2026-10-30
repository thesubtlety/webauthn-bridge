/* Shared status model for remote and local extension. No secrets or page data. */
var BridgeIndicator = (() => {
  const MAX_AGE_MS = 90000;
  const spec = {
    green:{color:'#15803d',badge:'OK',text:'Relay healthy; encrypted peer link verified'},
    yellow:{color:'#d5a000',badge:'...',text:'Health or encrypted peer link not fully established'},
    red:{color:'#c92b36',badge:'!',text:'Relay /health check failed'}
  };
  function healthUrl(raw){
    const u=new URL(raw);
    if(u.protocol!=='wss:'||u.username||u.password)throw Error('Expected secure WSS relay origin');
    const h=new URL(u.toString());h.protocol='https:';h.pathname='/health';h.search='';h.hash='';
    return h.toString();
  }
  function permissionPattern(raw){return new URL(healthUrl(raw)).origin+'/*';}
  function state(v,now=Date.now()){
    if(v.health==='bad')return 'red';
    if(v.enabled&&v.health==='ok'&&now-v.healthAt<MAX_AGE_MS&&
       v.connected&&v.peerOnline&&v.linkAt>0&&now-v.linkAt<MAX_AGE_MS&&
       v.proxyReady!==false)return 'green';
    return 'yellow';
  }
  let lastIcon='';let lastTitle='';
  async function update(v){
    if(!chrome.action?.setBadgeText)return state(v);
    const status=state(v);
    const hint=[spec[status].text,v.healthDetail||''].filter(Boolean).join(' | ').slice(0,190);
    const title=`YubiKey WSS (${v.role}): ${status.toUpperCase()} - ${hint}`;
    if(status===lastIcon&&title===lastTitle)return status;
    lastIcon=status;lastTitle=title;
    try {
      await Promise.all([
        chrome.action.setIcon({path:{'16':`icons/${status}-16.png`,'32':`icons/${status}-32.png`,'48':`icons/${status}-48.png`}}),
        chrome.action.setBadgeText({text:spec[status].badge}),
        chrome.action.setBadgeBackgroundColor({color:spec[status].color}),
        chrome.action.setTitle({title})
      ]);
    } catch(e){ console.warn('[yk-bridge] icon-status-failed',e?.message||e); }
    return status;
  }
  return {healthUrl,permissionPattern,state,update};
})();
