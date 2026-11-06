'use strict';
// SPEC sections 4, 5, 6, 9 (receiver checks, and sender checks 1-3, 7, 8).
const L = require('./lib');

const ID_RE = /^[A-Za-z0-9._~:-]{1,128}$/;
const NODE_RE = /^agt_[0-9a-f]{32}$/;
const NAME_RE = /^[a-z][a-z0-9_]{0,31}$/;
const INTENT_RE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$/;
const HASH_RE = /^[0-9a-f]{64}$/;
const SIG_RE = /^[A-Za-z0-9+/]{85}[AQgw]==$/;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
const isInt = (v) => typeof v === 'number' && Number.isInteger(v);
const inRange = (v, lo, hi) => isInt(v) && v >= lo && v <= hi;
const SAFE = L.MAX_SAFE;
const onlyKeys = (o, req, opt = []) => {
  const ks = Object.keys(o);
  return req.every((k) => ks.includes(k)) && ks.every((k) => req.includes(k) || opt.includes(k));
};

// ------------------------------------------------------------ schema (hand-written, shapes only)
const text100 = (v) => L.freeText(v, 100);
const slotOk = (v) => isObj(v) && onlyKeys(v, ['start', 'end']) && L.isMinuteTime(v.start) && L.isMinuteTime(v.end);
function valueOk(v) {
  if (isStr(v)) return text100(v);
  if (typeof v === 'boolean') return true;
  if (isInt(v)) return inRange(v, -SAFE, SAFE);
  return slotOk(v);
}
function packageOk(p) {
  if (!isObj(p)) return false;
  const ks = Object.keys(p);
  if (ks.length < 1 || ks.length > 8) return false;
  return ks.every((k) => NAME_RE.test(k) && valueOk(p[k]));
}
const offerDeltaOk = (d) => isObj(d) && onlyKeys(d, ['offer']) && Array.isArray(d.offer) &&
  d.offer.length >= 1 && d.offer.length <= 5 && d.offer.every(packageOk);
const reasonPayloadOk = (p) => isObj(p) && onlyKeys(p, ['public_reason']) &&
  ['no_common_option', 'constraint_violation', 'policy_declined'].includes(p.public_reason);
const emptyOk = (p) => isObj(p) && Object.keys(p).length === 0;

function issueOk(x) {
  if (!isObj(x) || !isStr(x.name) || !NAME_RE.test(x.name)) return false;
  switch (x.kind) {
    case 'choice':
      if (!onlyKeys(x, ['name', 'kind'], ['options'])) return false;
      if (x.options !== undefined) {
        const o = x.options;
        if (!Array.isArray(o) || o.length < 1 || o.length > 20 || !o.every(text100)) return false;
        if (new Set(o).size !== o.length) return false;
      }
      return true;
    case 'time':
      return onlyKeys(x, ['name', 'kind', 'duration_minutes', 'window']) &&
        inRange(x.duration_minutes, 1, 1440) && slotOk(x.window);
    case 'amount':
      return onlyKeys(x, ['name', 'kind', 'unit', 'scale', 'min', 'max', 'step']) &&
        L.freeText(x.unit, 16) && inRange(x.scale, 0, 6) && inRange(x.min, -SAFE, SAFE) &&
        inRange(x.max, -SAFE, SAFE) && inRange(x.step, 1, SAFE);
    case 'flag':
      return onlyKeys(x, ['name', 'kind']);
    default: return false;
  }
}
const requestPayloadOk = (p) => isObj(p) && onlyKeys(p, ['topic', 'expires_at', 'issues']) &&
  L.freeText(p.topic, 200) && L.isDateTime(p.expires_at) &&
  Array.isArray(p.issues) && p.issues.length >= 1 && p.issues.length <= 8 && p.issues.every(issueOk);

const FIELDS = ['protocol', 'message_id', 'session_id', 'sender_agent_id', 'receiver_agent_id',
  'sender_node_id', 'receiver_node_id', 'message_type', 'intent', 'sequence', 'payload', 'delta',
  'nonce', 'created_at', 'payload_hash', 'signature'];

function messageSchemaOk(m) {
  if (!isObj(m) || !onlyKeys(m, FIELDS)) return false;
  if (m.protocol !== 'aun/0.4') return false;
  for (const k of ['message_id', 'session_id', 'sender_agent_id', 'receiver_agent_id', 'nonce']) {
    if (!isStr(m[k]) || !ID_RE.test(m[k])) return false;
  }
  for (const k of ['sender_node_id', 'receiver_node_id']) if (!isStr(m[k]) || !NODE_RE.test(m[k])) return false;
  if (!['REQUEST', 'COUNTER', 'ACCEPT', 'REJECT', 'ERROR'].includes(m.message_type)) return false;
  if (!isStr(m.intent) || L.cpLen(m.intent) > 64 || !INTENT_RE.test(m.intent)) return false;
  if (!inRange(m.sequence, 1, 5)) return false;
  if (!isObj(m.payload) || !isObj(m.delta)) return false;
  if (!L.isDateTime(m.created_at)) return false;
  if (!isStr(m.payload_hash) || !HASH_RE.test(m.payload_hash)) return false;
  if (!isStr(m.signature) || !SIG_RE.test(m.signature)) return false;
  const t = m.message_type;
  if (t === 'REQUEST') {
    if (m.sequence !== 1) return false;
    return requestPayloadOk(m.payload) && offerDeltaOk(m.delta);
  }
  if (m.sequence < 2) return false;
  if (t === 'COUNTER') return reasonPayloadOk(m.payload) && offerDeltaOk(m.delta);
  if (t === 'ACCEPT') return emptyOk(m.payload) && onlyKeys(m.delta, ['agreed']) && packageOk(m.delta.agreed);
  if (t === 'REJECT') {
    return reasonPayloadOk(m.payload) && onlyKeys(m.delta, ['code']) &&
      ['NO_AGREEMENT', 'OUTSIDE_LIMIT', 'HUMAN_REJECTED', 'APPROVAL_EXPIRED'].includes(m.delta.code);
  }
  return emptyOk(m.payload) && onlyKeys(m.delta, ['code']) && m.delta.code === 'NOT_SUPPORTED'; // ERROR
}

// ------------------------------------------------------------ declaration and packages (sections 4, 6)
// returns false when the declaration is invalid (INVALID_NEGOTIATION_PAYLOAD)
function declarationOk(issues) {
  const names = new Set();
  for (const x of issues) {
    if (names.has(x.name)) return false;
    names.add(x.name);
    if (x.kind === 'time') {
      const s = L.parseInstant(x.window.start), e = L.parseInstant(x.window.end);
      if (!(s < e)) return false;
      if (e - s > 31n * 86400n * L.SEC) return false;
      if (BigInt(x.duration_minutes) * 60n * L.SEC > e - s) return false;
    } else if (x.kind === 'amount') {
      if (x.min > x.max) return false;
      if (BigInt(x.max) - BigInt(x.min) > BigInt(SAFE)) return false;
    }
  }
  return true;
}

function valueValid(x, v) {
  switch (x.kind) {
    case 'choice': return isStr(v) && (x.options === undefined || x.options.includes(v));
    case 'time': {
      if (!isObj(v)) return false;
      const s = L.parseInstant(v.start), e = L.parseInstant(v.end);
      const ws = L.parseInstant(x.window.start), we = L.parseInstant(x.window.end);
      return s >= ws && e <= we && e - s === BigInt(x.duration_minutes) * 60n * L.SEC;
    }
    case 'amount': {
      if (!isInt(v) || v < x.min || v > x.max) return false;
      return (BigInt(v) - BigInt(x.min)) % BigInt(x.step) === 0n;
    }
    default: return typeof v === 'boolean';
  }
}
function valueSame(x, a, b) {
  if (x.kind === 'time') return L.parseInstant(a.start) === L.parseInstant(b.start) && L.parseInstant(a.end) === L.parseInstant(b.end);
  return a === b;
}
function packageValid(decl, p) {
  const ks = Object.keys(p);
  if (ks.length !== decl.length) return false;
  return decl.every((x) => Object.prototype.hasOwnProperty.call(p, x.name) && valueValid(x, p[x.name]));
}
const packageSame = (decl, p, q) => decl.every((x) => valueSame(x, p[x.name], q[x.name]));
function offerValid(decl, offer) {
  if (offer.length < 1 || offer.length > 5) return false;
  if (!offer.every((p) => packageValid(decl, p))) return false;
  for (let i = 0; i < offer.length; i++) for (let j = i + 1; j < offer.length; j++) if (packageSame(decl, offer[i], offer[j])) return false;
  return true;
}

// ------------------------------------------------------------ the node
class Node {
  // opts.trusted: Map node_id -> { agent_id, key (Buffer) }; opts.self: {node_id, agent_id}
  constructor(opts) {
    this.self = opts.self;
    this.trusted = opts.trusted;
    this.sessions = new Map();   // peerNode|session_id -> session
    this.msgs = new Map();       // sender node -> Map(message_id -> jcs)
    this.nonces = new Map();     // sender node -> Set(nonce)
  }

  statusAt(s, nowStr) {
    if (s.status === 'open' && L.parseInstant(nowStr) > s.exp + 300n * L.SEC) return 'expired';
    return s.status;
  }
  sessionStatus(peerNode, sid, nowStr) {
    const s = this.sessions.get(peerNode + '|' + sid);
    return s ? this.statusAt(s, nowStr) : null;
  }

  // role 'receive' runs steps 1-8, role 'send' runs 1-3, 7, 8.
  process(bytes, nowStr, role) {
    const now = L.parseInstant(nowStr);
    // 1 size
    if (bytes.length > 16384) return 'MESSAGE_TOO_LARGE';
    // 2 strict JSON
    let m;
    try { m = L.strictParse(bytes); } catch (e) { return 'MESSAGE_SCHEMA_INVALID'; }
    // 3 schema
    if (!messageSchemaOk(m)) return 'MESSAGE_SCHEMA_INVALID';
    const recv = role === 'receive';
    if (!recv && (m.sender_node_id !== this.self.node_id || m.sender_agent_id !== this.self.agent_id)) return 'SESSION_BINDING_MISMATCH';
    if (recv) {
      // 4 peer and address
      const peer = this.trusted.get(m.sender_node_id);
      if (!peer) return 'PEER_NOT_TRUSTED';
      if (peer.agent_id !== m.sender_agent_id) return 'AGENT_IDENTITY_MISMATCH';
      if (m.receiver_node_id !== this.self.node_id || m.receiver_agent_id !== this.self.agent_id) return 'SESSION_BINDING_MISMATCH';
      // 5 signature
      const ph = L.sha256hex(Buffer.from(L.jcs({ payload: m.payload, delta: m.delta }), 'utf8'));
      if (ph !== m.payload_hash) return 'MESSAGE_SIGNATURE_INVALID';
      const body = Object.assign(Object.create(null), m);
      delete body.signature;
      const sig = L.b64Decode(m.signature, 64);
      if (!sig || !L.verifyEd25519(peer.key, Buffer.from(L.jcs(body), 'utf8'), sig)) return 'MESSAGE_SIGNATURE_INVALID';
      // 6 clock ahead
      if (L.parseInstant(m.created_at) > now + 300n * L.SEC) return 'MESSAGE_EXPIRED';
    }
    // 7 duplicates and replay
    const full = L.jcs(m);
    const known = this.msgs.get(m.sender_node_id);
    // A sender never reuses its own message ID, so a copy is a duplicate for a receiver only.
    if (known && known.has(m.message_id)) return recv && known.get(m.message_id) === full ? 'duplicate' : 'MESSAGE_REPLAYED';
    const nn = this.nonces.get(m.sender_node_id);
    if (nn && nn.has(m.nonce)) return 'MESSAGE_REPLAYED';
    // 8 state and payload
    const r = this.step8(m, recv, now);
    if (r !== 'ok') return r;
    if (!known) this.msgs.set(m.sender_node_id, new Map());
    this.msgs.get(m.sender_node_id).set(m.message_id, full);
    if (!nn) this.nonces.set(m.sender_node_id, new Set());
    this.nonces.get(m.sender_node_id).add(m.nonce);
    return 'accepted';
  }

  step8(m, recv, now) {
    const peerNode = recv ? m.sender_node_id : m.receiver_node_id;
    const key = peerNode + '|' + m.session_id;
    let s = this.sessions.get(key);
    const created = L.parseInstant(m.created_at);
    if (m.message_type === 'REQUEST') {
      if (s) return 'MESSAGE_REPLAYED';
      // Section 5.1 order: known session, deadline rule, arrival on time, declaration, offer.
      const exp = L.parseInstant(m.payload.expires_at);
      if (!(exp > created && exp <= created + 7n * 86400n * L.SEC)) return 'INVALID_NEGOTIATION_PAYLOAD';
      if (now > exp + 300n * L.SEC) return 'SESSION_EXPIRED';
      const decl = m.payload.issues;
      if (!declarationOk(decl)) return 'INVALID_NEGOTIATION_PAYLOAD';
      if (!offerValid(decl, m.delta.offer)) return 'INVALID_NEGOTIATION_PAYLOAD';
      this.sessions.set(key, {
        intent: m.intent, reqCreated: created, exp, decl,
        standing: m.delta.offer, lastSender: m.sender_node_id, lastSeq: 1, counters: 0, status: 'open',
        agents: { [m.sender_node_id]: m.sender_agent_id, [m.receiver_node_id]: m.receiver_agent_id },
      });
      return 'ok';
    }
    if (!s) return 'INVALID_STATE_TRANSITION'; // unknown session, includes non-party senders
    // Section 5.2 order. 1: intent and the parties.
    if (s.agents[m.sender_node_id] !== m.sender_agent_id || s.agents[m.receiver_node_id] !== m.receiver_agent_id ||
        m.sender_node_id === m.receiver_node_id) return 'SESSION_BINDING_MISMATCH';
    if (m.intent !== s.intent) return 'SESSION_BINDING_MISMATCH';
    // 2: a sequence already recorded.
    if (m.sequence <= s.lastSeq) return 'MESSAGE_REPLAYED';
    // 3: closed, or arrival too late.
    if (s.status !== 'open') return 'INVALID_STATE_TRANSITION';
    if (now > s.exp + 300n * L.SEC) return 'SESSION_EXPIRED';
    // 4: sequence and turn.
    if (m.sequence !== s.lastSeq + 1) return 'INVALID_STATE_TRANSITION';
    if (m.sender_node_id === s.lastSender) return 'INVALID_STATE_TRANSITION';
    // 5: created_at (section 5.3).
    if (created > s.exp) return 'SESSION_EXPIRED';
    if (created < s.reqCreated - 300n * L.SEC) return 'MESSAGE_EXPIRED';
    // 6: the rules of the message type.
    const t = m.message_type;
    if (t === 'ERROR') {
      if (s.lastSeq !== 1) return 'INVALID_STATE_TRANSITION';
      s.status = 'not_supported';
    } else if (t === 'COUNTER') {
      if (s.counters >= 3) return 'INVALID_STATE_TRANSITION';
      if (!offerValid(s.decl, m.delta.offer)) return 'INVALID_NEGOTIATION_PAYLOAD';
      s.counters++;
      s.standing = m.delta.offer;
    } else if (t === 'ACCEPT') {
      const p = m.delta.agreed;
      if (!packageValid(s.decl, p)) return 'INVALID_NEGOTIATION_PAYLOAD';
      if (!s.standing.some((q) => packageSame(s.decl, p, q))) return 'INVALID_NEGOTIATION_PAYLOAD';
      s.status = 'agreed';
    } else if (t === 'REJECT') {
      s.status = 'rejected';
    }
    s.lastSender = m.sender_node_id;
    s.lastSeq = m.sequence;
    return 'ok';
  }
}

module.exports = { Node, messageSchemaOk };
