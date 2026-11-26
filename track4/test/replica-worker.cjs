"use strict";
const { Replica } = require("../replica.cjs");
let node;
process.on("message", ({ id, op, value }) => {
  try {
    let result;
    if (op === "open") {
      node = new Replica(value);
      result = { ready: true };
    } else if (op === "begin") result = node.beginSync();
    else if (op === "install") result = node.install(value);
    else if (op === "execute") result = node.execute(value);
    else if (op === "close") {
      node.close();
      process.disconnect();
      return;
    } else throw new Error("Unknown worker operation");
    process.send({ id, result });
  } catch (e) {
    process.send({ id, error: e.code || e.message });
  }
});
