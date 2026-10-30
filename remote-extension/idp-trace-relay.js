// ISOLATED-world bridge. Treat all page-originated events as UNTRUSTED metadata.
(() => {
  const EVENT = 'ykwss-bridge-trace-047';
  const VALID = new Set(['installed','unavailable','hook-ready','hook-failed','get-start','get-resolved','get-rejected']);
  chrome.runtime.sendMessage({action:'idpTraceEvent',payload:{kind:'isolated-ready',frame:window===window.top?'top':'subframe',origin:location.origin}}).catch(()=>{});
  window.addEventListener(EVENT, event => {
    const d = event.detail;
    if (!d || !VALID.has(d.kind)) return;
    const payload = {
      kind: String(d.kind),
      frame: d.frame === 'top' ? 'top' : 'subframe',
      origin: location.origin,
      source: d.source === 'bridge' ? 'bridge' : d.source === 'site' ? 'site' : 'unknown',
      mediation: typeof d.mediation === 'string' ? d.mediation.slice(0,24) : '',
      rp: typeof d.rp === 'string' ? d.rp.slice(0,100) : '',
      allowCount:Number.isInteger(d.allowCount) && d.allowCount>=0 ? Math.min(d.allowCount,1000) : null,
      transports:typeof d.transports==='string' ? d.transports.slice(0,64) : '',
      hints:typeof d.hints==='string' ? d.hints.slice(0,64) : '',
      uv:typeof d.uv==='string' ? d.uv.slice(0,20) : '',
      appidPresent:d.appidPresent===true,
      ms: Number.isFinite(d.ms) ? Math.max(0,Math.min(Math.round(d.ms),600000)) : null,
      name: typeof d.name === 'string' ? d.name.slice(0,40) : '',
      message: typeof d.message === 'string' ? d.message.slice(0,100) : ''
    };
    chrome.runtime.sendMessage({action:'idpTraceEvent',payload}).catch(()=>{});
  });
})();
