// Runs in the trusted login website's MAIN world via chrome.scripting.executeScript.
// Self-contained function: Chromium serializes it into the real page context.
// No DOM innerHTML: strict Trusted Types / CSP sites may reject innerHTML assignment.
function runSiteCeremony(options, expectedOrigin, rpId, displayId, diagnosticsTag, autoInvoke=false, preferredHint="default", quietMode=false) {
  return new Promise(resolve => {
    let done = false;
    let host = null;
    let controller = null;
    let isolatedFrame = null;
    let tryIsolatedOnNextClick = false;
    let phase = 'initializing';
    // For diagnostics only. Never use messages from a webpage as authentication evidence.
    // No challenges, cookies, credential bytes or signatures appear in telemetry.
    function report(stage, detail = '') {
      try {
        window.postMessage({channel:'ykwss-page-stage-v1', tag:diagnosticsTag, stage,
          detail:String(detail).slice(0,180)}, location.origin);
      } catch {}
    }
    function finish(result) {
      if (done) return;
      done = true;
      // Release any outstanding WebAuthn ceremony when denying or canceling.
      // Chrome may still take a moment to settle the abort.
      if (!result?.ok) {
        try { controller?.abort(); } catch {}
      }
      if (host) host.remove();
      try { isolatedFrame?.remove(); } catch {}
      isolatedFrame = null;
      resolve(result);
    }
    try {
      if (location.origin !== expectedOrigin) throw Error('Page navigated to a different origin');
      if (!window.isSecureContext) throw Error('The login page is not a secure context');
      if (window.top !== window.self) throw Error('A top-level login page is required');
      if (!navigator.credentials?.get || !window.PublicKeyCredential?.parseRequestOptionsFromJSON)
        throw Error('This browser does not support WebAuthn JSON requests');
      phase = 'parse-options';
      const parsed = PublicKeyCredential.parseRequestOptionsFromJSON(options);
      // A WebAuthn hint only influences Chrome's UI. It NEVER changes RP ID,
      // challenge, credential allow-list, user-verification or origin checks.
      if (['security-key','client-device','hybrid'].includes(preferredHint)) {
        const original=Array.isArray(parsed.hints)?parsed.hints:[];
        parsed.hints=[preferredHint,...original.filter(x=>x!==preferredHint)];
        report('webauthn-hint-applied',`Remote Chrome preference ${preferredHint}; original RP hints ${(options.hints||[]).join(',')||'none'}`);
      } else {
        report('webauthn-hint-applied',`Preserving RP hints ${(options.hints||[]).join(',')||'none'}`);
      }
      if(quietMode){
        // A saved RP+origin has been auto-selected by the REMOTE extension.
        // No page overlay is installed. Chrome/OS may still show a passkey,
        // Touch ID, security key, or phone confirmation UI.
        controller = new AbortController();
        window.addEventListener('pagehide',()=>{if(!done)controller.abort();},{once:true});
        (async()=>{
          try{
            phase='navigator.credentials.get';
            const allow=Array.isArray(parsed.allowCredentials)?parsed.allowCredentials:[];
            const transports=allow.map(c=>(c.transports||[]).join('+')||'unspecified').join(';')||'none';
            report('webauthn-silent-start',`No bridge approval/panel; RP=${parsed.rpId} origin=${location.origin}`);
            report('webauthn-request-shape',`allowCredentials=${allow.length} transports=${transports} UV=${parsed.userVerification||'preferred'} hints=${(parsed.hints||[]).join(',')||'none'} timeoutHint=${parsed.timeout??'none'}`);
            report('webauthn-get-start','Chrome native authenticator UI requested automatically');
            const credential=await navigator.credentials.get({publicKey:parsed,signal:controller.signal});
            report('webauthn-get-resolved','Chrome returned a credential');
            report('webauthn-authenticator',`attachment=${credential?.authenticatorAttachment||'unknown'} kind=${credential?.type||'unknown'} legacyAppIdUsed=${credential?.getClientExtensionResults?.()?.appid===true}`);
            phase='serialize-credential';
            if(typeof credential?.toJSON!=='function')throw Error('WebAuthn credential serialization unavailable');
            finish({ok:true,credential:credential.toJSON(),pageOrigin:location.origin});
          }catch(error){
            const name=error?.name||'Error';
            const message=String(error?.message||error).slice(0,170);
            report('webauthn-get-rejected',`${name}: ${message}`);
            finish({ok:false,phase,name,error:message});
          }
        })();
        return;
      }
      controller = new AbortController();
      // Navigating away must not leave an abandoned YubiKey request pending.
      window.addEventListener('pagehide', () => {
        if (!done) controller.abort();
      }, {once: true});
      host = document.createElement('div');
      host.setAttribute('data-ykwss-browser-bridge-v03', '');
      // Some IdPs (including Okta) disallow injected <style> elements via CSP.
      // Property-by-property DOM styling remains usable; a constructable
      // stylesheet gives richer styling when supported by the page/browser.
      function setStyles(el, props){ for(const [key,value] of Object.entries(props)) el.style[key]=value; }
      setStyles(host,{all:'initial',position:'fixed',zIndex:'2147483647',top:'18px',right:'18px',
        width:'min(390px, calc(100vw - 36px))',colorScheme:'light',fontFamily:'system-ui, sans-serif'});
      const root = host.attachShadow({mode:'open'});
      const css = `:host{all:initial}.shell{box-sizing:border-box;background:#101c31;color:#fff;font:14px/1.45 system-ui,sans-serif;border:2px solid #78a7fa;border-radius:16px;box-shadow:0 14px 44px #0008;padding:18px}h3{margin:0 0 9px;font-size:17px}p{margin:8px 0}.small{color:#bed0e9;font-size:12px;overflow-wrap:anywhere}button{border:0;border-radius:9px;padding:12px;font-size:14px;font-weight:700;cursor:pointer;margin:7px 7px 0 0;background:#b7f9cd;color:#172f22}button.secondary{background:#3a4c65;color:#fff}button:disabled{opacity:.5;cursor:default}`;
      let styleMode='direct DOM properties';
      try {
        const sheet=new CSSStyleSheet();sheet.replaceSync(css);
        root.adoptedStyleSheets=[sheet];styleMode='adopted stylesheet + DOM property fallback';
      }catch { /* Direct-property styling below is the CSP-safe fallback. */ }
      const shell = document.createElement('section');
      setStyles(shell,{boxSizing:'border-box',display:'block',backgroundColor:'#101c31',color:'#fff',
        fontFamily:'system-ui, sans-serif',fontSize:'14px',lineHeight:'1.45',
        border:'2px solid #78a7fa',borderRadius:'16px',boxShadow:'0 14px 44px #0008',padding:'18px'});
      shell.className = 'shell';
      shell.setAttribute('role', 'dialog');
      shell.setAttribute('aria-label', 'Local YubiKey bridge');
      const heading = document.createElement('h3'); heading.textContent = '🔑 Local WebAuthn bridge';
      setStyles(heading,{fontFamily:'system-ui, sans-serif',fontSize:'17px',fontWeight:'700',margin:'0 0 9px'});
      const intro = document.createElement('p'); intro.textContent = autoInvoke ?
        'Trusted-VM mode: asking remote Chrome to start the authenticator chooser. You still approve using your key, biometric, or phone.' :
        'This is the REMOTE login page. Verify the origin and choose your authenticator below.';
      setStyles(intro,{margin:'8px 0',fontFamily:'system-ui, sans-serif',fontSize:'14px'});
      const line = (label, value) => {
        const p = document.createElement('p'); p.className = 'small';
        const span = document.createElement('span');span.textContent = label + ': ';
        const strong = document.createElement('strong');strong.textContent = value;
        setStyles(p,{margin:'8px 0',color:'#bed0e9',fontFamily:'system-ui, sans-serif',fontSize:'12px',overflowWrap:'anywhere'});
        p.append(span, strong);return p;
      };
      const originEl = line('Remote origin',location.origin);
      const rpEl = line('RP ID',rpId);
      const idEl = line('Challenge fingerprint',displayId);
      const note = document.createElement('p');note.className = 'small';
      note.textContent = 'Preferred chooser: '+(preferredHint==='default'?'website/browser default':preferredHint)+
        '. Chrome may offer different authenticators depending on enrolled credentials. The signed assertion goes only to the local website.';
      setStyles(note,{margin:'8px 0',color:'#bed0e9',fontFamily:'system-ui, sans-serif',fontSize:'12px',overflowWrap:'anywhere'});
      const button = document.createElement('button');button.type='button';button.id='go';button.textContent='Choose remote authenticator';
      const cancel = document.createElement('button');cancel.type='button';cancel.id='cancel';cancel.className='secondary';cancel.textContent='Cancel';
      for(const b of [button,cancel])setStyles(b,{border:'0',borderRadius:'9px',padding:'12px',
        fontFamily:'system-ui, sans-serif',fontSize:'14px',fontWeight:'700',cursor:'pointer',
        margin:'7px 7px 0 0',backgroundColor:b===button?'#b7f9cd':'#3a4c65',
        color:b===button?'#172f22':'#fff'});
      const state=document.createElement('p');state.className='small';state.id='state';state.setAttribute('role','status');
      state.textContent=autoInvoke?'Starting Chrome chooser…':'Click to start the remote browser chooser.';
      setStyles(state,{margin:'8px 0',color:'#bed0e9',fontFamily:'system-ui, sans-serif',fontSize:'12px',overflowWrap:'anywhere'});
      shell.append(heading,intro,originEl,rpEl,idEl,note,button,cancel,state);
      root.append(shell);
      report('webauthn-ui-style',styleMode);
      cancel.addEventListener('click', () => {
        report('page-canceled', 'Canceled from remote login tab');
        controller.abort();
        finish({ok:false,name:'NotAllowedError',error:'Canceled by user on remote login page'});
      });
      async function startWebAuthn(automatic=false) {
        if(done || button.disabled) return;
        const isolated = tryIsolatedOnNextClick;
        // Each attempt must have an independent AbortSignal. Abort/release of
        // another website's passkey request is outside this extension's control.
        try { controller?.abort(); } catch {}
        controller = new AbortController();
        button.disabled=true;
        report(automatic?'webauthn-auto-start':'remote-button-clicked',
          automatic?'Auto-start enabled for the saved trusted-VM rule':'User clicked remote authenticator button');
        state.textContent='Waiting for Chrome security-key / Keychain / phone chooser…';
        try {
          phase=isolated?'navigator.credentials.get in isolated frame':'navigator.credentials.get';
          report('webauthn-get-start', isolated ?
            'Attempting same-origin blank frame after top-level pending-request rejection' :
            'Browser is evaluating RP/origin policy; key UI might not appear');
          let appidHost='none';
          if (typeof options?.extensions?.appid==='string') {
            try{appidHost=new URL(options.extensions.appid).host;}catch{appidHost='invalid URL';}
          }
          let nativeGet=false;
          try{nativeGet=/\[native code\]/.test(Function.prototype.toString.call(navigator.credentials.get));}catch{}
          report('webauthn-context',
            `origin=${location.origin} rp=${parsed.rpId||'(default)'} focused=${document.hasFocus()} nativeGet=${nativeGet} appidHost=${appidHost} extensions=${Object.keys(options.extensions||{}).join(',')||'none'}`);
          const descriptors=Array.isArray(parsed.allowCredentials)?parsed.allowCredentials:[];
          const transportGroups=descriptors.map(item=>Array.isArray(item.transports)&&item.transports.length?
            item.transports.slice(0,5).join('+'):'unspecified');
          const transports=transportGroups.slice(0,8).join(';')||'none';
          report('webauthn-request-shape',
            `allowCredentials=${parsed.allowCredentials?.length??'discoverable'} transports=${transports} UV=${parsed.userVerification||'preferred'} hints=${(parsed.hints||[]).join(',')||'none'} timeoutHint=${parsed.timeout??'none'}`);
          if(preferredHint==='security-key'&&descriptors.length>0&&descriptors.every(item=>
            Array.isArray(item.transports)&&item.transports.length>0&&item.transports.every(x=>x==='internal')))
            report('webauthn-transport-warning',
              'RP lists only internal transport for allowed credential(s). A security-key UI hint cannot make a different credential eligible.');
          let credential;
          if (isolated) {
            // Create a distinct WebAuthn request context, without leaving the
            // verified IdP origin. This is an experiment, not an origin bypass.
            const frame=document.createElement('iframe');
            frame.setAttribute('allow','publickey-credentials-get');
            frame.src='about:blank';
            setStyles(frame,{position:'fixed',left:'4px',top:'4px',width:'2px',height:'2px',
              opacity:'0.01',pointerEvents:'none'});
            document.documentElement.appendChild(frame);
            isolatedFrame=frame;
            const child=frame.contentWindow;
            const childOrigin=child?.origin;
            const childSecure=child?.isSecureContext===true;
            const policy=child?.document?.permissionsPolicy||child?.document?.featurePolicy;
            const policyAllowed=policy?.allowsFeature?.('publickey-credentials-get')??null;
            report('webauthn-isolated-frame',
              `origin=${childOrigin||'unavailable'} expected=${expectedOrigin} secure=${childSecure} allowed=${policyAllowed}`);
            if(childOrigin!==expectedOrigin||!childSecure||policyAllowed===false)
              throw Error('Isolated child frame failed origin, secure-context or WebAuthn policy preflight');
            const childParsed=child.PublicKeyCredential.parseRequestOptionsFromJSON(options);
            if(['security-key','client-device','hybrid'].includes(preferredHint)) {
              const original=Array.isArray(childParsed.hints)?childParsed.hints:[];
              childParsed.hints=[preferredHint,...original.filter(x=>x!==preferredHint)];
            }
            // AbortController in the same JS realm as the child request.
            controller=new child.AbortController();
            credential=await child.navigator.credentials.get({publicKey:childParsed,signal:controller.signal});
          } else {
            credential=await navigator.credentials.get({publicKey:parsed,signal:controller.signal});
          }
          report('webauthn-get-resolved','Chrome returned a credential');
          report('webauthn-authenticator',
            `attachment=${credential?.authenticatorAttachment||'unknown'} kind=${credential?.type||'unknown'} userHandlePresent=${credential?.response?.userHandle!=null} legacyAppIdUsed=${credential?.getClientExtensionResults?.()?.appid===true} clientOrigin=${location.origin}`);
          phase='serialize-credential';
          if(typeof credential?.toJSON!=='function')throw Error('WebAuthn credential serialization is unavailable');
          const assertion=credential.toJSON();
          phase='completed';
          finish({ok:true,credential:assertion,pageOrigin:location.origin});
        }catch(error){
          const name=error?.name||'Error';
          const message=String(error?.message||error).slice(0,170);
          report('webauthn-get-rejected',name+': '+message);
          if(name==='OperationError' && /request is already pending/i.test(message)){
            report('webauthn-native-busy','Chrome reports an unfinished WebAuthn operation in the current request context.');
            if(!isolated){
              tryIsolatedOnNextClick=true;
              state.textContent='Chrome rejected the main-page request as busy. Try a separate same-origin blank frame once; the RP and signed origin remain checked.';
              button.disabled=false;button.textContent='Try isolated signing frame';return;
            }
            report('webauthn-isolated-failed','A separate same-origin frame also received the pending-request error.');
            finish({ok:false,phase,name,error:'Pending WebAuthn request persists in separate frame; try a clean remote Chrome profile.'});
            return;
          }
          // Automatic invocation may be disallowed without a real user gesture.
          // Keep the SAME local challenge available for a manual click.
          if(automatic && ['NotAllowedError','SecurityError','TypeError'].includes(name)){
            report('webauthn-auto-fallback',`Automatic Chrome request returned ${name}; manual click available`);
            state.textContent=`Automatic request returned ${name}. Click below to try with a real user gesture.`;
            button.disabled=false;button.textContent='Choose remote authenticator';return;
          }
          report('webauthn-error-source',
            `origin=${location.origin} messageLocalhost3000=${message.includes('localhost:3000')} stackLocalhost3000=${String(error?.stack||'').includes('localhost:3000')}`);
          finish({ok:false,phase,name,error:message});
        }
      }
      button.addEventListener('click',()=>startWebAuthn(false));
      document.documentElement.appendChild(host);
      report('site-overlay-ready', 'Remote HTTPS page received the WebAuthn overlay');
      if(autoInvoke)startWebAuthn(true).catch(error=>{
        report('webauthn-auto-fallback',String(error?.message||error).slice(0,150));
        button.disabled=false;
      });
    } catch (error) {
      const name=error?.name||'Error';
      const message=String(error?.message||error).slice(0,170);
      report('site-setup-rejected', phase+'; '+name+': '+message);
      finish({ok:false,phase,name,error:message});
    }
  });
}

// Injected in the extension ISOLATED world before the MAIN-world ceremony.
// This only forwards display/diagnostic events. It does not influence acceptance.
function installPageStageRelay(requestId, diagnosticsTag, expectedOrigin) {
  window.addEventListener('message', event => {
    if (event.source !== window || event.origin !== expectedOrigin) return;
    const data = event.data;
    if (!data || data.channel !== 'ykwss-page-stage-v1' || data.tag !== diagnosticsTag) return;
    const allowed = ['site-overlay-ready','remote-button-clicked','webauthn-get-start',
      'webauthn-context','webauthn-error-source','webauthn-native-busy',
      'webauthn-request-shape','webauthn-transport-warning','webauthn-authenticator',
      'webauthn-hint-applied','webauthn-auto-start','webauthn-auto-fallback','webauthn-ui-style',
      'webauthn-get-resolved','webauthn-get-rejected','webauthn-silent-start','webauthn-isolated-frame','webauthn-isolated-failed','site-setup-rejected','page-canceled'];
    if (!allowed.includes(data.stage)) return;
    chrome.runtime.sendMessage({action:'pageStage',id:requestId,tag:diagnosticsTag,
      stage:data.stage,detail:typeof data.detail==='string'?data.detail.slice(0,180):''})
      .catch(() => {});
  });
}
