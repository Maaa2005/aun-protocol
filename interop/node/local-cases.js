'use strict';
// Cases in the format of receiver-v0.4.json that are not in that file. They are built from its
// first accepted REQUEST and use `send`, which verifies no signature, so they need no key.
const MISMATCH = 'SESSION_BINDING_MISMATCH';
const PAYLOAD = 'INVALID_NEGOTIATION_PAYLOAD';
const b64 = (m) => Buffer.from(JSON.stringify(m)).toString('base64');
const decode = (s) => JSON.parse(Buffer.from(s.message, 'base64'));

function localCases(rv) {
  const N = rv.nodes;
  const opening = rv.cases.flatMap((c) => c.steps).find((s) => {
    if (s.action !== 'receive' || s.expect !== 'accepted') return false;
    const m = decode(s);
    return m.message_type === 'REQUEST' && m.sender_node_id === N.a.node_id && m.session_id === 's1';
  });
  if (!opening) return null;
  const req = decode(opening);
  const send = (m, expect) => ({ action: 'send', now: opening.now, message: b64(m), expect });
  const sendOnly = (name, m, expect, final) => ({ name, steps: [send(m, expect)], final });
  const afterOpening = (name, m, expect) => ({ name, steps: [opening, send(m, expect)], final: 'open' });

  const b = { sender_node_id: N.b.node_id, sender_agent_id: N.b.personal_agent_id };
  const toA = { receiver_node_id: N.a.node_id, receiver_agent_id: N.a.personal_agent_id };
  // B's answer to the opening. Each case below breaks one thing in it.
  const reply = (fields) => ({ ...req, ...b, ...toA, sequence: 2, message_id: 'local-m2', nonce: 'local-n2', ...fields });
  const offered = req.delta.offer[0];
  const undeclared = { ...offered, not_declared: true };
  const counter = (offer, extra) => reply({
    message_type: 'COUNTER', payload: { public_reason: 'no_common_option' }, delta: { offer }, ...extra,
  });

  return [
    // Sending as someone else. SPEC section 9 gives no code for this: a sender checks its own
    // message, and the vectors' `send` is B's own. This code is the one the Python reference gives.
    sendOnly('send: A as sender, node and agent', req, MISMATCH, null),
    sendOnly('send: sender_node_id is A, sender_agent_id is B', { ...req, sender_agent_id: b.sender_agent_id }, MISMATCH, null),
    sendOnly('send: sender_agent_id is A, sender_node_id is B', { ...req, sender_node_id: b.sender_node_id }, MISMATCH, null),
    sendOnly('send: B as sender, to A', { ...req, ...b, ...toA }, 'accepted', 'open'),
    // Drops in step 8 that no vector reaches, so a change of state there would go unseen.
    afterOpening('COUNTER with a package outside the declaration', counter([undeclared]), PAYLOAD),
    afterOpening('ACCEPT with a package outside the declaration',
      reply({ message_type: 'ACCEPT', payload: {}, delta: { agreed: undeclared } }), PAYLOAD),
    afterOpening('later message to another agent of the session\'s peer',
      counter([offered], { receiver_agent_id: 'agent-x' }), MISMATCH),
  ];
}

module.exports = { localCases };
