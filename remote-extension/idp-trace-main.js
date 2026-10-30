// Temporary, opt-in, metadata-only instrumentation of THIS remote IdP document.
// Installed at document_start in MAIN world. Never suppresses or fabricates WebAuthn.
(() => {
  const KEY = '__ykwssTrace047Installed';
  if (window[KEY]) return;
  Object.defineProperty(window, KEY, {value: true, configurable: false});
  const EVENT = 'ykwss-bridge-trace-047';
  let next = 0;
  const emit = (kind, detail = {}) => {
    try {
      window.dispatchEvent(new CustomEvent(EVENT, {detail: {
        kind, origin: location.origin, frame: window === window.top ? 'top' : 'subframe',
        ...detail
      }}));
    } catch (_) {}
  };
  emit('installed', {ready: document.readyState});
  setTimeout(()=>emit('installed', {ready: document.readyState}),150);
  const container = navigator.credentials;
  const original = container?.get;
  if (typeof original !== 'function') {emit('unavailable');return;}
  try {
    Object.defineProperty(container, 'get', {
      configurable: true,
      writable: true,
      value: function (...args) {
        const id = ++next;
        const raw = args[0] || {};
        const options = raw.publicKey || {};
        // A site may control the arguments. Events are untrusted diagnostics only.
        const source = options.extensions?.localDesktopClientOverride ? 'bridge' : 'site';
        const mediation = String(raw.mediation || 'unspecified').slice(0,24);
        const rp = typeof options.rpId === 'string' ? options.rpId.slice(0,100) : 'default';
        // Redacted request shape only: never collect credential IDs, challenge,
        // user handles, signatures, cookie headers or AppID URLs.
        const descriptors = Array.isArray(options.allowCredentials) ? options.allowCredentials : [];
        const transportNames = new Set(['usb','nfc','ble','internal','hybrid','smart-card']);
        const transports = [...new Set(descriptors.flatMap(c =>
          Array.isArray(c.transports) ? c.transports.filter(t => transportNames.has(t)) : []))]
          .slice(0,6).join('+') || 'unspecified';
        const hints = Array.isArray(options.hints) ? options.hints
          .filter(h => ['security-key','client-device','hybrid'].includes(h))
          .slice(0,3).join('+') : '';
        const uv = ['required','preferred','discouraged'].includes(options.userVerification) ?
          options.userVerification : 'unspecified';
        const started = performance.now();
        emit('get-start', {id,source,mediation,rp,allowCount:descriptors.length,
          transports,hints,uv,appidPresent:typeof options.extensions?.appid==='string'});
        try {
          return Promise.resolve(Reflect.apply(original, this, args)).then(
            result => {emit('get-resolved',{id,source,ms:Math.round(performance.now()-started)});return result;},
            error => {emit('get-rejected',{id,source,ms:Math.round(performance.now()-started),
              name:String(error?.name||'Error').slice(0,40),message:String(error?.message||'').slice(0,100)});throw error;}
          );
        } catch (error) {
          emit('get-rejected',{id,source,ms:Math.round(performance.now()-started),
            name:String(error?.name||'Error').slice(0,40),message:String(error?.message||'').slice(0,100)});
          throw error;
        }
      }
    });
    emit('hook-ready');
  } catch (e) {emit('hook-failed',{name:String(e?.name||'Error'),message:String(e?.message||'').slice(0,100)});}
})();
