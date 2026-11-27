"use strict";
// Hybrid logical clock (Kulkarni et al., 2014). State and timestamps are {l, c}: l = ms, c = counter.
function send(s, pt) {
  const l = Math.max(s.l, pt);
  return { l, c: l === s.l ? s.c + 1 : 0 };
}
function receive(s, m, pt) {
  const l = Math.max(s.l, m.l, pt);
  let c = 0;
  if (l === s.l && l === m.l) c = Math.max(s.c, m.c) + 1;
  else if (l === s.l) c = s.c + 1;
  else if (l === m.l) c = m.c + 1;
  return { l, c };
}
const compare = (a, b) => a.l - b.l || a.c - b.c;
const encode = (t) => `${t.l}:${t.c}`;
function parse(s) {
  const m = typeof s === "string" && /^(\d{1,15}):(\d{1,9})$/.exec(s);
  if (!m) return null;
  return { l: Number(m[1]), c: Number(m[2]) };
}
module.exports = { send, receive, compare, encode, parse };
