/* global chrome */
var BridgeDiag = (() => {
  let events = [];
  const storage = chrome.storage.session;
  const boot = storage.get('ykWssV03Log').then(v => {
    if (Array.isArray(v.ykWssV03Log)) events = v.ykWssV03Log.slice(-500);
  }).catch(() => {});
  let writes = boot;
  const safe = value => String(value ?? '').slice(0, 700).replace(/[A-Za-z0-9_-]{43,}/g, '[long-token]');
  function log(level, code, detail = '', requestId = '') {
    const event = {t: new Date().toISOString(), level, code: safe(code), detail: safe(detail), id: String(requestId).slice(0, 8)};
    console[level === 'error' ? 'error' : level === 'warn' ? 'warn' : 'log']('[yk-bridge]', event.code, event.detail, event.id);
    writes = writes.then(async () => {
      events.push(event);
      events = events.slice(-500);
      await storage.set({ykWssV03Log: events});
    }).catch(() => {});
    return writes;
  }
  async function snapshot() { await writes; return events.slice(); }
  async function clear() { await writes; events = []; await storage.set({ykWssV03Log: []}); }
  return {log, snapshot, clear};
})();
