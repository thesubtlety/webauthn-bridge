const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');
const root = path.resolve(__dirname,'..');
const b64 = b => Buffer.from(b).toString('base64url');
const enc = x => new TextEncoder().encode(x);
const sha = async value => new Uint8Array(await webcrypto.subtle.digest('SHA-256',enc(value)));
const rp='trial-1234.okta.com';
const origin='https://trial-1234.okta.com';
const appid='https://trial-1234.okta.com/legacy/appid.json';
const challenge=b64(enc('a synthetic challenge used only in remote tests'));
const options={rpId:rp,challenge,userVerification:'required',extensions:{appid}};

const context={
  URL,TextEncoder,TextDecoder,Uint8Array,atob,crypto:webcrypto,
  BridgeProfiles:{rpId(value){return String(value).toLowerCase();}}
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(root,'remote-extension/validation.js'),'utf8'),context);
const BridgeValidate=context.BridgeValidate;

async function makeAssertion(identifier,extensionResults,flags=5,originOverride=origin,challengeOverride=challenge){
  const hash=await sha(identifier);
  const auth=new Uint8Array(37);
  auth.set(hash,0);auth[32]=flags;auth[36]=1;
  const credential={type:'public-key',id:'synthetic-credential',rawId:'c3ludGhldGljLWNyZWRlbnRpYWw',
    response:{clientDataJSON:b64(JSON.stringify({type:'webauthn.get',challenge:challengeOverride,origin:originOverride})),
      authenticatorData:b64(auth),signature:'c3ludGhldGljLXNpZ25hdHVyZQ'}};
  if(extensionResults!==undefined)credential.clientExtensionResults=extensionResults;
  return credential;
}
async function accept(cred, opts=options){
  assert.equal(await BridgeValidate.assertion(cred,opts,origin,false),cred);
}
async function reject(cred,opts,reason){
  await assert.rejects(BridgeValidate.assertion(cred,opts,origin,false),reason);
}
(async()=>{
  // Normal assertion with and without a false appid output should stay supported.
  await accept(await makeAssertion(rp,undefined));
  await accept(await makeAssertion(rp,{appid:false}));
  // Only an explicit browser extension result can authorize hashing an AppID.
  await accept(await makeAssertion(appid,{appid:true}));
  await reject(await makeAssertion(appid,{appid:false}),options,/RP ID hash mismatch/);
  await reject(await makeAssertion(appid,undefined),options,/RP ID hash mismatch/);
  await reject(await makeAssertion(rp,{appid:true}),options,/AppID hash mismatch/);
  await reject(await makeAssertion(appid,{appid:true}),{...options,extensions:{}},/did not request a valid AppID/);
  await reject(await makeAssertion(appid,{appid:'true'}),options,/Invalid AppID extension result type/);
  await reject(await makeAssertion(appid,{appid:true}),{...options,extensions:{appid:'http://trial-1234.okta.com/legacy'}},/Legacy AppID must be an HTTPS/);
  // Continue to enforce RP origin, request challenge and UV/UP. Legacy U2F
  // (normally lacking UV) must NOT be allowed to satisfy UV=required.
  await reject(await makeAssertion(appid,{appid:true},1),options,/Required user verification flag missing/);
  await reject(await makeAssertion(appid,{appid:true},4),options,/User presence flag missing/);
  await reject(await makeAssertion(appid,{appid:true},5,'https://attacker.example'),options,/origin mismatch/);
  await reject(await makeAssertion(appid,{appid:true},5,origin,b64(enc('other challenge'))),options,/Challenge mismatch/);
  console.log('v0.4.8 legacy AppID + normal RP, rejection and UV/UP tests passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
