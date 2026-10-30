const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const read=f=>fs.readFileSync(path.join(root,f),'utf8');

async function testSilent({fail=null,origin='https://gitlab.com'}={}){
  const calls=[],reports=[],created=[];
  const fakeDoc={documentElement:{appendChild:()=>{throw Error('Silent mode must not inject a page overlay');}},
    createElement(tag){created.push(tag);throw Error('Silent mode must not create '+tag);}};
  const win={isSecureContext:true,postMessage(o){reports.push(o)},addEventListener(){}};
  win.top=win.self=win;
  const fakeNavigator={credentials:{get:async(arg)=>{
    calls.push(arg);
    if(fail){const e=new Error(fail.message);e.name=fail.name;throw e;}
    return {type:'public-key',authenticatorAttachment:'cross-platform',
      getClientExtensionResults:()=>({appid:false}),
      toJSON:()=>({id:'redacted-test-id',type:'public-key',response:{authenticatorData:'fixture'}})};
  }}};
  const context={navigator:fakeNavigator,document:fakeDoc,window:win,
    location:{origin},URL,AbortController,Promise,Error,String,Object,Array,
    PublicKeyCredential:{parseRequestOptionsFromJSON:x=>({...x,allowCredentials:x.allowCredentials||[]})}};
  win.PublicKeyCredential=context.PublicKeyCredential;
  vm.createContext(context);vm.runInContext(read('remote-extension/site-page.js'),context);
  const options={rpId:'gitlab.com',challenge:'pretend-not-secret',userVerification:'required',
    allowCredentials:[{id:'one',transports:['usb','nfc']}],hints:[]};
  const result=await context.runSiteCeremony(options,origin,'gitlab.com','fp','tag',true,'security-key',true);
  return {result,calls,reports,created};
}
(async()=>{
  const success=await testSilent();
  assert.equal(success.result.ok,true);
  assert.equal(success.calls.length,1);
  assert.equal(success.created.length,0,'no overlay DOM elements in silent sign-in');
  assert.equal(success.calls[0].publicKey.userVerification,'required');
  assert.equal(success.calls[0].publicKey.hints[0],'security-key');
  assert.equal(success.calls[0].publicKey.allowCredentials[0].id,'one',
    'allowed-credentials must not be substituted to choose a different device');
  assert.equal(success.reports.some(x=>x.stage==='webauthn-silent-start'),true);
  assert.equal(success.reports.some(x=>x.stage==='webauthn-get-resolved'),true);
  const failed=await testSilent({fail:{name:'NotAllowedError',message:'User gesture required'}});
  assert.equal(failed.result.ok,false);
  assert.equal(failed.result.name,'NotAllowedError');
  assert.equal(failed.created.length,0,'failed auto attempt must not silently open old overlay');
  assert.equal(failed.reports.some(x=>x.stage==='webauthn-get-rejected'),true);

  const remote=read('remote-extension/background.js');
  assert.match(remote,/let streamlinedMode=true/);
  assert.match(remote,/if\(streamlinedMode && !p.forceManual\)/);
  assert.match(remote,/p\.streamlinedAuto=true/);
  assert.match(remote,/args:\[p\.options,p\.origin,p\.rp,p\.fingerprint,p\.diagnosticsTag,autoInvoke,p\.authenticatorPreference,p\.streamlinedAuto===true\]/);
  assert.match(remote,/const selected=explicit \|\|/);
  assert.match(remote,/case 'setStreamlinedMode'/);
  assert.match(remote,/auto-profile-unavailable/);
  assert.match(remote,/BridgeProfiles\.relation\(profile,p\.rp\)/);
  assert.match(remote,/BridgeValidate\.assertion\(result\.credential,p\.options,p\.origin/);
  assert.match(remote,/await checkRelatedOrigin\(profile,p\.rp\)/);

  for(const ext of ['remote-extension','local-extension']){
    const popup=read(`${ext}/popup.js`),html=read(`${ext}/setup.html`);
    assert.match(popup,/const enablePromise=ask\('enable'/);
    assert.match(popup,/const permissionPromise=requestRelayHealthPermission/);
    assert.match(popup,/relayDraftUrl/);
    if(ext==='local-extension')assert.match(popup,/chrome\.permissions\.request/);
    if(ext==='local-extension')assert.match(html,/id="grantAll"/);
    assert.match(read(`${ext}/diagnostics.html`),/id="copySummary"/);
    assert.match(read(`${ext}/diagnostics.html`),/id="verbosity"/);
  }
  assert.match(read('local-extension/profiles.html'),/id="grantAllHttps"/);
  assert.deepEqual(JSON.parse(read('remote-extension/manifest.json')).host_permissions,['https://*/*']);
  assert.match(read('remote-extension/diagnostics.js'),/importantStages/);
  assert.match(read('local-extension/diagnostics.js'),/importantStages/);
  console.log('v0.4.9 silent sign-in, no-overlay failure, host permission, setup persistence, and focused logging smoke checks passed');
})().catch(e=>{console.error(e);process.exitCode=1});
