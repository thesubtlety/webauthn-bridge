/* Remote profile matching only. A local challenge must never choose its own origin. */
var BridgeProfiles = (() => {
  function rpId(raw) {
    if (typeof raw !== 'string') throw Error('RP ID must be a hostname');
    const value=raw.trim().toLowerCase();
    if (value.length>253 || !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(value) || value.split('.').some(x=>x.startsWith('-')||x.endsWith('-')))
      throw Error('RP ID must be a fully qualified DNS hostname (without https://)');
    return value;
  }
  function origin(raw) {
    const u=new URL(raw);
    if(u.protocol!=='https:' || u.username || u.password || u.search || u.hash || u.pathname!=='/' || (raw!==u.origin && raw!==u.origin+'/'))
      throw Error('Origin must be an exact HTTPS origin without path');
    return u.origin;
  }
  function sitePattern(raw) {const u=new URL(raw);return u.origin+'/*';}
  function normalize(raw) {
    if(!raw||typeof raw!=='object')throw Error('Profile is required');
    const id=typeof raw.id==='string'&&/^[a-f0-9-]{36}$/.test(raw.id)?raw.id:crypto.randomUUID();
    const name=String(raw.name||'').trim().slice(0,60);
    if(!name)throw Error('Profile name is required');
    if((raw.autoInvoke===true||raw.autoRedirect===true)&&raw.quickStart!==true)
      throw Error('Trusted-VM Auto-start and automatic redirect require Quick-start on this exact RP rule');
    const o=origin(String(raw.origin||'').trim());
    const rp=rpId(raw.rpId);
    // This is a launch/navigation URL, not the origin used for WebAuthn.
    // A login flow may legitimately begin on an app and redirect to its IdP.
    const u=new URL(String(raw.pageUrl||o+'/').trim());
    const loopback=['localhost','127.0.0.1','[::1]'].includes(u.hostname);
    if(!(u.protocol==='https:'||(u.protocol==='http:'&&loopback))||u.username||u.password)
      throw Error('Launch URL must use HTTPS (or HTTP localhost for development), without embedded credentials');
    const mode=relation({origin:o,rpId:rp,allowRelatedOrigins:!!raw.allowRelatedOrigins},rp);
    if(mode==='none')throw Error('Origin does not match RP ID. Enable the related-origin check explicitly, or choose a matching origin.');
    // A provider group is organizational. Every route retains its own exact
    // RP ID and signer origin; no wildcard or implicit cross-RP authorization.
    const group=String(raw.group || name).trim().slice(0,60) || name;
    const extras=Array.isArray(raw.pageUrls)?raw.pageUrls:[];
    const urls=[u.toString()];
    for(const value of extras){
      if(urls.length>=8)throw Error('At most eight alternate launch URLs per route');
      const entry=new URL(String(value||'').trim());
      const remote=['localhost','127.0.0.1','[::1]'].includes(entry.hostname);
      if(!(entry.protocol==='https:'||(entry.protocol==='http:'&&remote))||entry.username||entry.password)
        throw Error('Alternate launch URLs must be HTTPS (or localhost HTTP), without embedded credentials');
      if(!urls.includes(entry.toString()))urls.push(entry.toString());
    }
    return {id,name,group,origin:o,pageUrl:urls[0],pageUrls:urls,
      rpId:rp,allowRelatedOrigins:!!raw.allowRelatedOrigins,
      quickStart:raw.quickStart===true,
      // Auto-start is opt-in per exact RP and signer origin. Never accepts an
      // arbitrary destination. Even in this mode, Chrome/OS consent remains.
      autoInvoke:raw.quickStart===true && raw.autoInvoke===true,
      autoRedirect:raw.quickStart===true && raw.autoRedirect===true,
      preferredForRp:raw.preferredForRp===true};
  }
  function relation(p,requestRp) {
    if(!p || requestRp!==p.rpId)return 'none';
    const host=new URL(p.origin).hostname;
    if(host===requestRp||host.endsWith('.'+requestRp))return 'direct';
    return p.allowRelatedOrigins?'related':'none';
  }
  function candidates(profiles,requestRp) {
    return profiles.map(p=>({...p,match:relation(p,requestRp)})).filter(p=>p.match!=='none');
  }
  return {normalize,rpId,origin,sitePattern,relation,candidates};
})();
