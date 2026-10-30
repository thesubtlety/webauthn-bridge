import { DurableObject } from "cloudflare:workers";
// Zero-knowledge forwarding relay. Never receives the pairing secret or plaintext.
// Each room allows one 'local' and one 'remote' WebSocket connection.
export default {
  async fetch(request, env) {
    const u = new URL(request.url);
    if (u.pathname === '/health') return new Response('ok', {status: 200});
    const match = /^\/ws\/([A-Za-z0-9_-]{43})$/.exec(u.pathname);
    if (!match) return new Response('Not found', {status: 404});
    const role = u.searchParams.get('role');
    if (role !== 'local' && role !== 'remote') {
      return new Response('Invalid role', {status: 400});
    }
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('WebSocket required', {status: 426});
    }
    return env.ROOMS.getByName(match[1]).fetch(request);
  },
};

export class BridgeRoom extends DurableObject {
  async fetch(request) {
    const role = new URL(request.url).searchParams.get('role');
    if (!['local', 'remote'].includes(role)) return new Response('role', {status: 400});
    // Only an OPEN, recently-heartbeating connection owns a role.
    // getWebSockets() can also return sockets already in CLOSING state.
    const now = Date.now();
    const openOwners = this.ctx.getWebSockets().filter(
      s => s.readyState === 1 && s.deserializeAttachment()?.role === role
    );
    const liveOwner = openOwners.some(s => {
      const last = s.deserializeAttachment()?.lastSeenAt;
      return Number.isFinite(last) && now - last < 65_000;
    });
    if (liveOwner) {
      console.log('bridge-role-busy', role);
      return new Response('Role already connected', {status: 409});
    }
    for (const stale of openOwners) {
      console.log('bridge-reclaiming-stale-role', role);
      try { stale.close(4001, 'Stale connection replaced'); } catch {}
    }
    const [client, server] = Object.values(new WebSocketPair());
    this.ctx.acceptWebSocket(server); // Enables hibernation between messages.
    server.serializeAttachment({role, lastSeenAt: Date.now()});
    const peers = this.ctx.getWebSockets().filter(s => s !== server && s.readyState === 1 && s.deserializeAttachment()?.role !== role);
    server.send(JSON.stringify({type: 'peer', online: peers.length > 0}));
    for (const peer of this.ctx.getWebSockets()) {
      if (peer !== server && peer.readyState === 1 && peer.deserializeAttachment()?.role !== role) {
        try { peer.send(JSON.stringify({type: 'peer', online: true})); } catch {}
      }
    }
    return new Response(null, {status: 101, webSocket: client});
  }

  webSocketMessage(socket, data) {
    if (socket.readyState !== 1) return; // Old closing sockets cannot forward packets.
    const att = socket.deserializeAttachment() || {};
    socket.serializeAttachment({...att, lastSeenAt: Date.now()});
    if (data === 'ping') { socket.send('pong'); return; }
    if (typeof data !== 'string' || data.length > 200_000) {
      socket.close(1009, 'Frame too large');
      return;
    }
    let parsed;
    try { parsed = JSON.parse(data); } catch { return; }
    if (parsed?.type !== 'packet' ||
        typeof parsed.iv !== 'string' || typeof parsed.ciphertext !== 'string' ||
        parsed.iv.length > 100 || parsed.ciphertext.length > 190_000) return;
    const senderRole = socket.deserializeAttachment()?.role;
    for (const peer of this.ctx.getWebSockets()) {
      if (peer !== socket && peer.readyState === 1 && peer.deserializeAttachment()?.role !== senderRole) {
        try { peer.send(data); } catch {}
      }
    }
  }

  webSocketClose(socket, code, reason) {
    const role = socket.deserializeAttachment()?.role;
    // Ignore the close event of an old, replaced socket if its replacement
    // is already connected; otherwise we could falsely mark the role offline.
    const replacementExists = this.ctx.getWebSockets().some(
      s => s !== socket && s.readyState === 1 && s.deserializeAttachment()?.role === role
    );
    if (!replacementExists) {
      for (const peer of this.ctx.getWebSockets()) {
        if (peer !== socket && peer.readyState === 1 && peer.deserializeAttachment()?.role !== role) {
          try { peer.send(JSON.stringify({type: 'peer', online: false})); } catch {}
        }
      }
    }
    try { socket.close(code, reason); } catch {}
  }

  webSocketError(socket) {
    try { socket.close(1011, 'socket error'); } catch {}
  }
}
