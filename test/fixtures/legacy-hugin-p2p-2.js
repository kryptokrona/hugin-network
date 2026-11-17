'use strict'

// Verbatim copy of `sanitizeHtml` and `sanitize_group_message` from hugin-p2p 2.1.0 `utils.js`
// (npm tarball). hugin-desktop imports this `sanitize_group_message` to normalize the room
// messages it sends (messages.cjs:50, 884-894), so its output is what desktop puts on the wire.

function sanitizeHtml(input) {
  if (input === undefined || input === null) return '';
  return String(input)
    // Drop script blocks entirely.
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    // Strip any remaining HTML tags.
    .replace(/<\/?[^>]+(>|$)/g, '')
    // Remove ASCII control chars.
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .trim();
}

const sanitize_group_message = (data) => {
  // Accept both wire format (t/g/m/k/r/s/n) and unified format (timestamp/room/message/address/...)
  const rawT = data.t !== undefined ? data.t : data.timestamp;
  const rawG = data.g !== undefined ? data.g : data.room;
  const rawM = data.m !== undefined ? data.m : data.message;
  const rawK = data.k !== undefined ? data.k : data.address;
  const rawR = data.r !== undefined ? data.r : (data.reply !== undefined ? data.reply : '');
  const rawS = data.s !== undefined ? data.s : data.signature;
  const rawN = data.n !== undefined ? data.n : data.name;
  const rawHash = data.hash;

  let timestamp = sanitizeHtml(String(rawT));
  if (parseInt(timestamp) > Date.now()) timestamp = Date.now();
  if (timestamp?.length > 20 || rawT === undefined) return false;
  let room = sanitizeHtml(rawG);
  if (room?.length > 128 || rawG === undefined) return false;
  let text = sanitizeHtml(rawM);
  if (text?.length > 777 || rawM === undefined) return false;
  let addr = sanitizeHtml(rawK);
  if (addr?.length > 128 || rawK === undefined) return false;
  let reply = sanitizeHtml(rawR);
  if (reply?.length > 64) return false;
  let sig = sanitizeHtml(rawS);
  if (sig?.length > 200) return false;
  let nick = sanitizeHtml(rawN);
  if (nick?.length > 50 || rawN === undefined) return false;
  let txHash = sanitizeHtml(rawHash);
  if (txHash?.length > 128 || rawHash === undefined) return false;

  let tip = false;
  if (data.tip && data.tip !== 'false') {
    if (typeof data.tip.amount !== 'number') return false;
    if (typeof data.tip.receiver !== 'string') return false;
    tip = {
      amount: data.tip.amount,
      receiver: sanitizeHtml(data.tip.receiver),
    };
  }

  const clean_object = {
    message: text,
    address: addr,
    signature: sig,
    room,
    timestamp,
    name: nick,
    reply,
    hash: txHash,
    sent: false,
    channel: 'channel',
    tip,
  };

  return clean_object;
};

module.exports = { sanitizeHtml, sanitize_group_message }
