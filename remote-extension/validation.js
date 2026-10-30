/* WebAuthn JSON validation. Never log challenges, credentials or signatures. */
var BridgeValidate = (() => {
  const te=new TextEncoder(),td=new TextDecoder('utf-8',{fatal:true});
  function rawB64(value){
    if(typeof value!=='string'||!/^[A-Za-z0-9_-]+={0,2}$/.test(value))throw Error('Malformed base64url data');
    const s=value.replace(/-/g,'+').replace(/_/g,'/');
    return Uint8Array.from(atob(s+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
  }
  function hex(bytes){return Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');}
  async function fingerprint(value){return hex(new Uint8Array(await crypto.subtle.digest('SHA-256',rawB64(value)))).slice(0,12);}
  function request(options){
    if(!options||typeof options!=='object'||typeof options.challenge!=='string'||options.challenge.length>4096)
      throw Error('Invalid WebAuthn challenge');
    const challenge=rawB64(options.challenge);
    if(!challenge.length||challenge.length>3072)throw Error('Invalid challenge size');
    // RP omitted on local WebAuthn calls cannot be safely inferred from the Chrome proxy API.
    if(!options.rpId)throw Error('Local request omitted rpId; caller origin unavailable; refusing to guess');
    const rp=BridgeProfiles.rpId(options.rpId);
    if(options.mediation==='conditional')throw Error('Conditional mediation is not supported');
    return {rp};
  }
  function validRequest(options,origin,allowRelatedOrigins=false){
    const {rp}=request(options);
    const u=new URL(origin);
    if(u.protocol!=='https:'||u.origin!==origin)throw Error('Configured origin must be HTTPS');
    if(!(rp===u.hostname||u.hostname.endsWith('.'+rp))&&!allowRelatedOrigins)
      throw Error('RP ID is incompatible with the configured HTTPS origin');
    return {rp,origin};
  }
  async function assertion(credential,options,origin,allowRelatedOrigins=false){
    if(!credential||credential.type!=='public-key'||typeof credential.id!=='string'||typeof credential.rawId!=='string'||!credential.response||
       typeof credential.response.clientDataJSON!=='string'||typeof credential.response.authenticatorData!=='string'||typeof credential.response.signature!=='string')
      throw Error('Missing fields in WebAuthn assertion');
    const client=JSON.parse(td.decode(rawB64(credential.response.clientDataJSON)));
    if(client.type!=='webauthn.get')throw Error('Unexpected WebAuthn assertion type');
    if(client.origin!==origin)throw Error('WebAuthn clientDataJSON origin mismatch');
    if(client.crossOrigin===true)throw Error('Unexpected cross-origin WebAuthn assertion');
    if(hex(rawB64(client.challenge))!==hex(rawB64(options.challenge)))throw Error('Challenge mismatch');
    const authData=rawB64(credential.response.authenticatorData);
    if(authData.length<37)throw Error('Missing authenticator data');
    const {rp}=validRequest(options,origin,allowRelatedOrigins);
    // FIDO U2F/AppID compatibility: the browser, not this bridge, decides if
    // the legacy AppID was actually used. A requested AppID alone is NOT proof.
    // When the browser reports appid:true, the signed authenticator data MUST
    // contain SHA-256 of the *exact AppID URL* supplied by the RP, not rpId.
    const extensionResults=credential.clientExtensionResults;
    if(extensionResults!=null && (typeof extensionResults!=='object'||Array.isArray(extensionResults)))
      throw Error('Invalid WebAuthn client extension results');
    const appidResult=extensionResults?.appid;
    if(appidResult!==undefined&&typeof appidResult!=='boolean')
      throw Error('Invalid AppID extension result type');
    const usedLegacyAppId=appidResult===true;
    let hashIdentifier=rp;
    if(usedLegacyAppId){
      const appid=options?.extensions?.appid;
      if(typeof appid!=='string'||!appid||appid.length>2048)
        throw Error('Browser reported legacy AppID use, but RP did not request a valid AppID');
      // Require a valid HTTPS AppID as a defense in depth; the browser also
      // enforces the AppID's own authorized-origin/facet restrictions.
      let url;
      try{url=new URL(appid);}catch{throw Error('Invalid requested legacy AppID URL');}
      if(url.protocol!=='https:'||!url.hostname||url.username||url.password||url.hash)
        throw Error('Legacy AppID must be an HTTPS URL without credentials or fragment');
      hashIdentifier=appid; // DO NOT normalize: AppID hashes cover the exact string.
    }
    const expectedHash=new Uint8Array(await crypto.subtle.digest('SHA-256',te.encode(hashIdentifier)));
    if(hex(authData.slice(0,32))!==hex(expectedHash))
      throw Error(usedLegacyAppId?'AppID hash mismatch in authenticator data':'RP ID hash mismatch in authenticator data');
    if((authData[32]&0x01)===0)throw Error('User presence flag missing');
    if(options.userVerification==='required'&&(authData[32]&0x04)===0)throw Error('Required user verification flag missing');
    return credential;
  }
  return {fingerprint,request,validRequest,assertion};
})();
