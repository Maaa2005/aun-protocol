'use strict';
// AUN 0.4 building blocks, written from SPEC.md only.

const crypto = require('node:crypto');

// ---------------------------------------------------------------- JCS (RFC 8785)
// Numbers: RFC 8785 uses the ECMAScript Number-to-string rule, which is what
// JS String(n) does. So no extra code is needed. Strings: JSON.stringify
// escapes exactly " \ and C0 controls (\b\t\n\f\r, others as lowercase \u00xx),
// which is the RFC 8785 rule. Key order: UTF-16 code unit order = default JS sort
// (SPEC section 2 names this as the one exception to code point order).
function jcs(v) {
  if (v === null) return 'null';
  switch (typeof v) {
    case 'boolean': return v ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(v)) throw new Error('JCS: non-finite number');
      return String(v);
    case 'string': return JSON.stringify(v);
    case 'object': {
      if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
      const keys = Object.keys(v).sort();
      return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
    }
    default: throw new Error('JCS: unsupported type ' + typeof v);
  }
}

// ---------------------------------------------------------------- strict JSON (SPEC section 9 step 2)
class JsonError extends Error {}
const MAX_SAFE = 9007199254740991;

// Input: Buffer. Returns the parsed value (null-prototype objects) or throws JsonError.
function strictParse(buf) {
  // valid UTF-8, no BOM
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) throw new JsonError('BOM');
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buf);
  } catch (e) { throw new JsonError('invalid utf-8'); }
  let i = 0;
  const n = text.length;
  const ws = () => { while (i < n) { const c = text.charCodeAt(i); if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++; else break; } };
  const fail = (m) => { throw new JsonError(m + ' at ' + i); };

  function parseString() {
    // text[i] === '"'
    i++;
    let out = '';
    for (;;) {
      if (i >= n) fail('unterminated string');
      const c = text.charCodeAt(i);
      if (c === 0x22) { i++; return out; }
      if (c < 0x20) fail('control char in string');
      if (c === 0x5c) {
        i++;
        const e = text[i];
        switch (e) {
          case '"': out += '"'; i++; break;
          case '\\': out += '\\'; i++; break;
          case '/': out += '/'; i++; break;
          case 'b': out += '\b'; i++; break;
          case 'f': out += '\f'; i++; break;
          case 'n': out += '\n'; i++; break;
          case 'r': out += '\r'; i++; break;
          case 't': out += '\t'; i++; break;
          case 'u': {
            const hex4 = (p) => { const h = text.slice(p, p + 4); if (!/^[0-9a-fA-F]{4}$/.test(h)) fail('bad \\u'); return parseInt(h, 16); };
            const u = hex4(i + 1);
            i += 5;
            if (u >= 0xd800 && u <= 0xdbff) {
              // must be followed by an escaped low surrogate
              if (text[i] === '\\' && text[i + 1] === 'u') {
                const lo = hex4(i + 2);
                if (lo >= 0xdc00 && lo <= 0xdfff) { out += String.fromCharCode(u, lo); i += 6; break; }
              }
              fail('lone high surrogate');
            }
            if (u >= 0xdc00 && u <= 0xdfff) fail('lone low surrogate');
            out += String.fromCharCode(u);
            break;
          }
          default: fail('bad escape');
        }
        continue;
      }
      // raw character. A raw surrogate pair is fine (astral char); a lone one cannot
      // come out of the fatal UTF-8 decoder.
      out += text[i];
      i++;
    }
  }

  function parseNumber() {
    const m = /^-?(0|[1-9][0-9]*)/.exec(text.slice(i, i + 400));
    if (!m) fail('bad number');
    const next = text[i + m[0].length];
    if (next === '.' || next === 'e' || next === 'E') fail('fraction or exponent');
    // "-0" reads as the integer 0 (section 9 step 2); BigInt gives 0n and JCS prints 0.
    const big = BigInt(m[0]);
    if (big > BigInt(MAX_SAFE) || big < -BigInt(MAX_SAFE)) fail('integer out of range');
    i += m[0].length;
    return Number(big);
  }

  // depth: envelope = level 1. Arrays and objects both count as a level.
  function parseValue(depth) {
    ws();
    if (i >= n) fail('unexpected end');
    const c = text[i];
    if (c === '{') {
      if (depth + 1 > 8) fail('too deep');
      i++;
      const o = Object.create(null);
      ws();
      if (text[i] === '}') { i++; return o; }
      for (;;) {
        ws();
        if (text[i] !== '"') fail('key expected');
        const k = parseString();
        // duplicate check is on the unescaped key
        if (Object.prototype.hasOwnProperty.call(o, k)) fail('duplicate key');
        ws();
        if (text[i] !== ':') fail(': expected');
        i++;
        const v = parseValue(depth + 1);
        Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; return o; }
        fail(', or } expected');
      }
    }
    if (c === '[') {
      if (depth + 1 > 8) fail('too deep');
      i++;
      const a = [];
      ws();
      if (text[i] === ']') { i++; return a; }
      for (;;) {
        a.push(parseValue(depth + 1));
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return a; }
        fail(', or ] expected');
      }
    }
    if (c === '"') return parseString();
    if (c === '-' || (c >= '0' && c <= '9')) return parseNumber();
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    return fail('unexpected token');
  }

  ws();
  if (text[i] !== '{') fail('top level must be an object');
  const v = parseValue(0);
  ws();
  if (i !== n) fail('trailing content');
  return v;
}

// ---------------------------------------------------------------- dates (SPEC section 2)
const DT_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]{1,6}))?)?(Z|[+-][0-9]{2}:[0-9]{2})$/;
const MIN_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(:00)?(Z|[+-][0-9]{2}:[0-9]{2})$/;

function daysFromCivil(y, m, d) {
  y -= m <= 2 ? 1 : 0;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}
const isLeap = (y) => (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
const DIM = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const MIN_INSTANT = BigInt(daysFromCivil(1, 1, 1)) * 86400n * 1000000n;
const MAX_INSTANT = BigInt(daysFromCivil(10000, 1, 1)) * 86400n * 1000000n - 1n;

// Returns the instant as BigInt microseconds since the epoch, or null if the string is not a
// valid date-time. Both the written year and the UTC year must be 0001 to 9999 (section 2).
function parseInstant(s) {
  if (typeof s !== 'string') return null;
  const m = DT_RE.exec(s);
  if (!m) return null;
  const Y = +m[1], Mo = +m[2], D = +m[3], h = +m[4], mi = +m[5];
  const sec = m[6] === undefined ? 0 : +m[6];
  if (Y < 1 || Mo < 1 || Mo > 12) return null;
  const dim = DIM[Mo - 1] + (Mo === 2 && isLeap(Y) ? 1 : 0);
  if (D < 1 || D > dim) return null;
  if (h > 23 || mi > 59 || sec > 59) return null; // no leap second
  let off = 0;
  if (m[8] !== 'Z') {
    const oh = +m[8].slice(1, 3), om = +m[8].slice(4, 6);
    if (oh > 23 || om > 59) return null;
    off = (m[8][0] === '-' ? -1 : 1) * (oh * 3600 + om * 60);
  }
  const frac = m[7] === undefined ? 0n : BigInt(m[7].padEnd(6, '0'));
  const secs = BigInt(daysFromCivil(Y, Mo, D)) * 86400n + BigInt(h * 3600 + mi * 60 + sec - off);
  const t = secs * 1000000n + frac;
  if (t < MIN_INSTANT || t > MAX_INSTANT) return null;
  return t;
}
const isDateTime = (s) => parseInstant(s) !== null;
const isMinuteTime = (s) => typeof s === 'string' && MIN_RE.test(s) && parseInstant(s) !== null;
const SEC = 1000000n;

// ---------------------------------------------------------------- free text (SPEC section 2)
function refusedCodePoint(c) {
  return (c <= 0x1f) || (c >= 0x7f && c <= 0x9f) ||
    c === 0xad || c === 0x34f || c === 0x61c || (c >= 0x115f && c <= 0x1160) ||
    (c >= 0x17b4 && c <= 0x17b5) || c === 0x180e || c === 0x200b || (c >= 0x200e && c <= 0x200f) ||
    (c >= 0x2060 && c <= 0x206f) || c === 0x3164 || c === 0xffa0 ||
    (c >= 0x1bca0 && c <= 0x1bca3) || (c >= 0x1d173 && c <= 0x1d17a) ||
    (c >= 0x2028 && c <= 0x202e) || (c >= 0xfff0 && c <= 0xfffb) ||
    c === 0xfeff ||
    (c >= 0xfdd0 && c <= 0xfdef) || ((c & 0xffff) >= 0xfffe) ||
    (c >= 0xe0000 && c <= 0xe0fff);
}
function cpLen(s) { let n = 0; for (const _ of s) n++; return n; }
function hasRefused(s) { for (const ch of s) if (refusedCodePoint(ch.codePointAt(0))) return true; return false; }
// text of 1..max code points without refused code points
function freeText(s, max) {
  if (typeof s !== 'string') return false;
  const n = cpLen(s);
  return n >= 1 && n <= max && !hasRefused(s);
}

// ---------------------------------------------------------------- Ed25519 (SPEC section 8)
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const WEAK = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
].map((h) => BigInt('0x' + Buffer.from(h, 'hex').reverse().toString('hex')));

function leInt(buf) { return BigInt('0x' + Buffer.from(buf).reverse().toString('hex')); }
// Section 8: y is read with the top bit cleared, so either sign bit is weak.
function isWeakPoint(b32) {
  const c = Buffer.from(b32);
  c[31] &= 0x7f;
  const y = leInt(c);
  return y >= P || WEAK.includes(y);
}
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
function verifyEd25519(rawKey, data, sig) {
  if (sig.length !== 64 || rawKey.length !== 32) return false;
  if (isWeakPoint(sig.subarray(0, 32))) return false;
  if (leInt(sig.subarray(32)) >= L) return false;
  try {
    const key = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, rawKey]), format: 'der', type: 'spki' });
    return crypto.verify(null, data, key, sig);
  } catch (e) { return false; }
}
// canonical standard Base64 with padding: decode, re-encode, compare
function b64Decode(s, len) {
  if (typeof s !== 'string') return null;
  const b = Buffer.from(s, 'base64');
  if (b.toString('base64') !== s) return null;
  if (len !== undefined && b.length !== len) return null;
  return b;
}
const sha256hex = (b) => crypto.createHash('sha256').update(b).digest('hex');
const nodeIdOf = (rawKey) => 'agt_' + sha256hex(rawKey).slice(0, 32);

module.exports = {
  jcs, strictParse, JsonError, parseInstant, isDateTime, isMinuteTime, SEC,
  refusedCodePoint, cpLen, hasRefused, freeText, isWeakPoint, verifyEd25519, b64Decode,
  sha256hex, nodeIdOf, MAX_SAFE,
};
