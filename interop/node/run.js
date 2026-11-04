'use strict';
// node interop/node/run.js [path-to-test-vectors-dir]
// Runs jcs-v0.2.json, card-v2.json and receiver-v0.4.json. Prints counts and mismatches.
// Exits 1 on any mismatch, and when a file holds no cases, so an empty file cannot pass.
const fs = require('node:fs');
const path = require('node:path');
const L = require('./lib');
const { checkCard } = require('./card');
const { Node } = require('./receiver');

const dir = process.argv[2] || path.join(__dirname, '..', '..', 'test-vectors');
const load = (f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
const bad = [];

// ---- JCS
let jOk = 0;
const jv = load('jcs-v0.2.json');
if (jv.vectors.length === 0) bad.push('jcs-v0.2.json holds no vectors');
for (const v of jv.vectors) {
  const got = Buffer.from(L.jcs(v.value), 'utf8');
  const want = Buffer.from(v.canonical_utf8, 'utf8');
  if (got.equals(want)) jOk++; else bad.push(`JCS ${v.name}: got ${got.toString()} want ${want.toString()}`);
}

// ---- nodes: sanity check that node_id derives from the key (SPEC section 2)
const cv = load('card-v2.json');
if (cv.cases.length === 0) bad.push('card-v2.json holds no cases');
for (const [k, n] of Object.entries(cv.nodes)) {
  if (L.nodeIdOf(Buffer.from(n.public_key, 'base64')) !== n.node_id) bad.push(`node ${k}: node_id does not derive from key`);
}

// ---- cards
let cOk = 0;
for (const c of cv.cases) {
  const store = new Map();
  let ok = true;
  c.steps.forEach((s, i) => {
    const got = checkCard(Buffer.from(s.card, 'base64'), s.now, s.in_person, store);
    if (got !== s.expect) { ok = false; bad.push(`CARD ${c.name} step ${i}: got ${got} want ${s.expect}`); }
  });
  const st = store.get(cv.nodes.a.node_id);
  const fin = st ? st.issued_at : null;
  if (fin !== c.final) { ok = false; bad.push(`CARD ${c.name} final: got ${fin} want ${c.final}`); }
  if (ok) cOk++;
}

// ---- receiver
const rv = load('receiver-v0.4.json');
if (rv.cases.length === 0) bad.push('receiver-v0.4.json holds no cases');
const N = rv.nodes;
const trusted = new Map();
for (const k of ['a', 'c']) trusted.set(N[k].node_id, { agent_id: N[k].personal_agent_id, key: Buffer.from(N[k].public_key, 'base64') });
let rOk = 0, rSteps = 0, rStepsOk = 0;
for (const c of rv.cases) {
  const node = new Node({ trusted, self: { node_id: N.b.node_id, agent_id: N.b.personal_agent_id } });
  let ok = true, lastNow = null;
  c.steps.forEach((s, i) => {
    rSteps++;
    const got = node.process(Buffer.from(s.message, 'base64'), s.now, s.action);
    lastNow = s.now;
    if (got !== s.expect) { ok = false; bad.push(`RECV ${c.name} step ${i} (${s.action}): got ${got} want ${s.expect}`); } else rStepsOk++;
  });
  const fin = node.sessionStatus(N.a.node_id, 's1', lastNow);
  if (fin !== c.final) { ok = false; bad.push(`RECV ${c.name} final: got ${fin} want ${c.final}`); }
  if (ok) rOk++;
}

console.log(`JCS      ${jOk}/${jv.vectors.length}`);
console.log(`cards    ${cOk}/${cv.cases.length} cases`);
console.log(`receiver ${rOk}/${rv.cases.length} cases (${rStepsOk}/${rSteps} steps)`);
console.log(bad.length ? `mismatches (${bad.length}):\n  ` + bad.join('\n  ') : 'no mismatches');
process.exit(bad.length ? 1 : 0);
