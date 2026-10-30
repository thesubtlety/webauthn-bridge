/* global crypto */
// Identical file in both extensions. All WebAuthn payloads are E2EE AES-256-GCM.
var BridgeCrypto = (() => {
  const te = new TextEncoder();
  const td = new TextDecoder();
  const alphabet = /^[A-Za-z0-9_-]{43}$/;
  function b64(bytes) {
    let s = '';
    for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64(value) {
    if (typeof value !== 'string' || !alphabet.test(value)) throw Error('Pairing key must be 43 base64url characters');
    const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '=';
    const raw = Uint8Array.from(atob(padded), c => c.charCodeAt(0));
    if (raw.length !== 32) throw Error('Pairing key must encode exactly 32 bytes');
    return raw;
  }
  function relayURL(raw, room, role) {
    const u = new URL(raw);
    if (u.protocol !== 'wss:' || u.username || u.password || u.hash || u.search || u.pathname !== '/') {
      throw Error('Relay URL must be a WSS origin such as wss://example.workers.dev/');
    }
    u.pathname = '/ws/' + room;
    u.searchParams.set('role', role);
    return u.toString();
  }
  function origin(raw) {
    const u = new URL(raw);
    if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || u.pathname !== '/' ||
        raw !== u.origin && raw !== u.origin + '/') {
      throw Error('Allowed origin must be an exact HTTPS origin like https://login.example.com');
    }
    return u.origin;
  }
  async function init(secret) {
    const raw = unb64(secret);
    const roomHash = await crypto.subtle.digest('SHA-256', new Uint8Array([...te.encode('ykwss-room-v1:'), ...raw]));
    const room = b64(roomHash);
    const ikm = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',
      salt:te.encode('ykwss-v1-salt'), info:te.encode('encryption')},
      ikm, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
    return {key, room};
  }
  async function seal(ctx, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = te.encode(JSON.stringify(obj));
    if (plaintext.length > 70_000) throw Error('Payload too large');
    const encrypted = await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:te.encode(ctx.room)},ctx.key,plaintext);
    return JSON.stringify({type:'packet', iv:b64(iv), ciphertext:b64(encrypted)});
  }
  async function open(ctx, raw) {
    const data = JSON.parse(raw);
    if (data?.type !== 'packet' || typeof data.iv !== 'string' || typeof data.ciphertext !== 'string') return null;
    const ivText = data.iv.replace(/-/g, '+').replace(/_/g, '/');
    const cipherText = data.ciphertext.replace(/-/g, '+').replace(/_/g, '/');
    const iv = Uint8Array.from(atob(ivText + '='.repeat((4-ivText.length%4)%4)), c=>c.charCodeAt(0));
    const cipher = Uint8Array.from(atob(cipherText + '='.repeat((4-cipherText.length%4)%4)), c=>c.charCodeAt(0));
    if (iv.length !== 12 || cipher.length > 80_000) throw Error('Malformed encrypted frame');
    const plaintext = await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:te.encode(ctx.room)},ctx.key,cipher);
    return JSON.parse(td.decode(plaintext));
  }
  function generate() { return b64(crypto.getRandomValues(new Uint8Array(32))); }
  return {init,seal,open,relayURL,origin,generate};
})();
