'use strict';
// SPEC section 11.2 card checks.
const L = require('./lib');

const ID_RE = /^[A-Za-z0-9._~:-]{1,128}$/;
const NODE_RE = /^agt_[0-9a-f]{32}$/;
const KEY_RE = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
const SIG_RE = /^[A-Za-z0-9+/]{85}[AQgw]==$/;
const PV_RE = /^[!-~]{1,32}$/;
const EP_RE = /^https:\/\/[!-~]{1,248}$/;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

const CARD_FIELDS = ['version', 'node_id', 'agent_id', 'public_key', 'display_name',
  'protocol_versions', 'relay_endpoint', 'issued_at', 'signature'];

function cardSchemaOk(c) {
  if (!isObj(c)) return false;
  const keys = Object.keys(c);
  if (keys.length !== CARD_FIELDS.length || !CARD_FIELDS.every((k) => keys.includes(k))) return false;
  const s = (v) => typeof v === 'string';
  if (c.version !== 'aun-card/2') return false;
  if (!(s(c.node_id) && NODE_RE.test(c.node_id))) return false;
  if (!(s(c.agent_id) && ID_RE.test(c.agent_id))) return false;
  if (!(s(c.public_key) && KEY_RE.test(c.public_key))) return false;
  if (!L.freeText(c.display_name, 100)) return false; // schema text + refused code points
  const pv = c.protocol_versions;
  if (!Array.isArray(pv) || pv.length < 1 || pv.length > 8) return false;
  if (!pv.every((x) => s(x) && PV_RE.test(x))) return false;
  if (new Set(pv).size !== pv.length) return false;
  if (!(s(c.relay_endpoint) && EP_RE.test(c.relay_endpoint))) return false;
  if (!L.isDateTime(c.issued_at)) return false;
  if (!(s(c.signature) && SIG_RE.test(c.signature))) return false;
  return true;
}

// store: Map node_id -> { public_key, agent_id, issued_at (string), t (BigInt) | null }
// returns { result: 'trusted'|'updated'|CODE, stored }
function checkCard(bytes, nowStr, inPerson, store) {
  const now = L.parseInstant(nowStr);
  if (bytes.length > 2048) return 'CARD_TOO_LARGE';
  let c;
  try { c = L.strictParse(bytes); } catch (e) { return 'CARD_SCHEMA_INVALID'; }
  if (!cardSchemaOk(c)) return 'CARD_SCHEMA_INVALID';
  const raw = L.b64Decode(c.public_key, 32);
  if (!raw) return 'CARD_SCHEMA_INVALID'; // cannot happen after the pattern
  if (L.nodeIdOf(raw) !== c.node_id) return 'CARD_IDENTITY_MISMATCH';
  if (L.isWeakPoint(raw)) return 'CARD_KEY_WEAK';
  const sig = L.b64Decode(c.signature, 64);
  const body = Object.assign(Object.create(null), c);
  delete body.signature;
  if (!sig || !L.verifyEd25519(raw, Buffer.from(L.jcs(body), 'utf8'), sig)) return 'CARD_SIGNATURE_INVALID';
  if (!c.protocol_versions.includes('aun/0.4')) return 'CARD_VERSION_UNSUPPORTED';
  const issued = L.parseInstant(c.issued_at);
  if (issued > now + 300n * L.SEC) return 'CARD_NOT_YET_VALID';
  const st = store.get(c.node_id);
  if (!st) {
    if (!inPerson) return 'CARD_PEER_NOT_TRUSTED';
    store.set(c.node_id, { public_key: c.public_key, agent_id: c.agent_id, issued_at: c.issued_at, t: issued });
    return 'trusted';
  }
  if (c.public_key !== st.public_key || c.agent_id !== st.agent_id) return 'CARD_IDENTITY_MISMATCH';
  if (st.t !== null && !(issued > st.t)) return 'CARD_STALE';
  store.set(c.node_id, { public_key: c.public_key, agent_id: c.agent_id, issued_at: c.issued_at, t: issued });
  return 'updated';
}

module.exports = { checkCard, cardSchemaOk };
