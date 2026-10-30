const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const ROOT=path.resolve(__dirname,'..');
const load=f=>fs.readFileSync(path.join(ROOT,f),'utf8');

function makeDom({failFirst=false, busyFirst=false, manual=false, stylesheetWorks=true}={}){
  const reports=[],nodes=[], calls=[];
  class Element {
    constructor(tag){this.tag=tag;this.style={};this.children=[];this.events={};this.attributes={};this.disabled=false;this.textContent='';}
    setAttribute(n,v){this.attributes[n]=v;}
    attachShadow(){this.shadow=new Element('shadow');this.shadow.adoptedStyleSheets=[];return this.shadow;}
    append(...elements){this.children.push(...elements);}
    appendChild(e){this.children.push(e);return e;}
    remove(){this.removed=true;}
    addEventListener(name,fn){this.events[name]=fn;}
  }
  const doc={
    createElement(tag){
      const e=new Element(tag);
      // v0.4.7 added an isolated-frame retry after Chrome reports a pending
      // WebAuthn request. The test fixture needs a same-origin child frame.
      if(tag==='iframe')e.contentWindow={
        origin:'https://gitlab.com',isSecureContext:true,
        document:{permissionsPolicy:{allowsFeature:()=>true}},
        PublicKeyCredential:{parseRequestOptionsFromJSON(x){return {...x};}},
        AbortController,navigator
      };
      nodes.push(e);return e;
    },
    hasFocus(){return true;},
    documentElement:new Element('html')
  };
  let call=0;
  const navigator={credentials:{get:async arg=>{
    calls.push(arg);call++;
    if(call===1&&failFirst){const e=new Error('Interaction requires user gesture');e.name='NotAllowedError';throw e;}
    if(call===1&&busyFirst){const e=new Error('A request is already pending');e.name='OperationError';throw e;}
    return {type:'public-key',authenticatorAttachment:'cross-platform',toJSON:()=>({id:'dummy',type:'public-key',response:{authenticatorData:'fixture'}})};
  }}};
  const w={isSecureContext:true,postMessage(msg){reports.push(msg);},addEventListener(){}};
  w.top=w.self=w;
  const ctx={document:doc,navigator,window:w,location:{origin:'https://gitlab.com'},
    PublicKeyCredential:{parseRequestOptionsFromJSON(x){return {...x};}},
    CSSStyleSheet:class{replaceSync(x){if(!stylesheetWorks)throw Error('CSP');this.text=x;}},
    AbortController,URL,Error,Promise,Object,String,Array};
  w.PublicKeyCredential=ctx.PublicKeyCredential;
  vm.createContext(ctx);
  vm.runInContext(load('remote-extension/site-page.js'),ctx);
  function click(){const b=nodes.find(x=>x.tag==='button'&&x.id==='go');assert(b);return b.events.click();}
  return {ctx,reports,calls,click,nodes};
}

(async()=>{
  const profilesCtx={URL,crypto:{randomUUID:()=> '11111111-1111-4111-8111-111111111111'}};
  vm.createContext(profilesCtx);
  vm.runInContext(load('remote-extension/profiles.js'),profilesCtx);
  const prof=profilesCtx.BridgeProfiles.normalize({name:'GitLab',group:'GitLab',rpId:'gitlab.com',
    origin:'https://gitlab.com',pageUrl:'https://gitlab.com/users/sign_in',
    quickStart:true,autoInvoke:true,autoRedirect:true,preferredForRp:true});
  assert.equal(prof.autoInvoke,true);
  assert.equal(prof.autoRedirect,true);
  assert.equal(prof.preferredForRp,true);
  assert.throws(()=>profilesCtx.BridgeProfiles.normalize({...prof,quickStart:false}),
    /require Quick-start/);
  assert.equal(profilesCtx.BridgeProfiles.relation(prof,'gitlab.com'),'direct');
  assert.equal(profilesCtx.BridgeProfiles.relation(prof,'evil.com'),'none');

  const opt={challenge:'AA',rpId:'gitlab.com',hints:['client-device']};
  const d=makeDom();
  const r=await d.ctx.runSiteCeremony(opt,'https://gitlab.com','gitlab.com','fp','tag',true,'security-key');
  assert.equal(r.ok,true,'automatic native get succeeded');
  assert.equal(d.calls.length,1);
  assert.equal(d.calls[0].publicKey.hints[0],'security-key');
  assert.equal(d.reports.some(x=>x.stage==='webauthn-auto-start'),true);
  assert.equal(d.reports.some(x=>x.stage==='webauthn-get-resolved'),true);
  assert.equal(d.reports.some(x=>x.stage==='webauthn-ui-style'),true);
  assert.equal(d.nodes.find(x=>x.tag==='section').style.fontFamily,'system-ui, sans-serif');

  const m=makeDom({manual:true,stylesheetWorks:false});
  const p=m.ctx.runSiteCeremony(opt,'https://gitlab.com','gitlab.com','fp','tag',false,'default');
  await Promise.resolve();assert.equal(m.calls.length,0,'manual mode does not auto request');
  await m.click();assert.equal((await p).ok,true);
  assert.equal(m.calls[0].publicKey.hints[0],'client-device','default preserves RP hints');

  const f=makeDom({failFirst:true});
  const pp=f.ctx.runSiteCeremony(opt,'https://gitlab.com','gitlab.com','fp','tag',true,'hybrid');
  await new Promise(r=>setTimeout(r,0));
  assert.equal(f.calls.length,1);
  assert.equal(f.reports.some(x=>x.stage==='webauthn-auto-fallback'),true);
  await f.click();assert.equal((await pp).ok,true);
  assert.equal(f.calls.length,2);

  const b=makeDom({busyFirst:true});
  const bp=b.ctx.runSiteCeremony(opt,'https://gitlab.com','gitlab.com','fp','tag',true,'security-key');
  await new Promise(r=>setTimeout(r,0));
  assert.equal(b.reports.some(x=>x.stage==='webauthn-native-busy'),true);
  await b.click();assert.equal((await bp).ok,true);

  const popup=load('local-extension/popup.html');
  assert.equal((popup.match(/id="health"/g)||[]).length,1);
  assert.equal((popup.match(/id="clearRetry"/g)||[]).length,1);
  assert.match(popup,/value="security-key"/);
  assert.match(popup,/value="client-device"/);
  assert.match(popup,/value="hybrid"/);
  assert.match(load('local-extension/background.js'),/authenticatorPreference,forceManual:manual/);
  console.log('v0.4.6 remote signing, auto fallback, native busy, profile and UI smoke tests passed');
})().catch(e=>{console.error(e);process.exitCode=1});
