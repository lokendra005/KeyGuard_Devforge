"use strict";
let token = "";
let signed = null;
const el = (id) => document.getElementById(id);
const notice = (message) => {
  el("notice").textContent = message;
};
async function api(route, body) {
  const response = await fetch(route, {
    method: body ? "POST" : "GET",
    headers: body
      ? { "Content-Type": "application/json" }
      : { Authorization: "Bearer " + token },
    body: body ? JSON.stringify(body) : undefined,
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Request failed");
  return result;
}
function table(id, rows) {
  const fragment = document.createDocumentFragment();
  for (const cells of rows) {
    const row = document.createElement("tr");
    for (const value of cells) {
      const cell = document.createElement("td");
      cell.textContent = String(value);
      row.append(cell);
    }
    fragment.append(row);
  }
  el(id).replaceChildren(fragment);
}
async function refresh() {
  try {
    const state = await api("/v1/status");
    el("connection").textContent = "Connected · " + state.node;
    el("file-count").textContent = state.files.length;
    el("actor-count").textContent = state.actors.filter(
      (a) => !a.disabled,
    ).length;
    el("event-count").textContent = state.checkpoint.seq;
    el("alert-count").textContent = state.detection
      ? state.detection.alerts.length
      : "—";
    el("authority").textContent = state.authority;
    table(
      "files",
      state.files.map((f) => [f.id, f.owner, f.version]),
    );
    table(
      "actors",
      state.actors.map((a) => [
        a.id,
        a.role,
        a.disabled ? "Revoked" : "Active",
        a.epoch,
        state.keys.filter((k) => k.actor === a.id).length,
      ]),
    );
    table(
      "events",
      state.events.map((e) => [
        e.seq,
        e.actor,
        e.action,
        e.node,
        JSON.stringify(e.detail),
      ]),
    );
    el("checkpoint").textContent =
      "Checkpoint " +
      state.checkpoint.seq +
      " · SHA-384 " +
      state.checkpoint.hash;
    const signals = document.createDocumentFragment();
    for (const alert of state.detection?.alerts || []) {
      const box = document.createElement("article");
      box.className = "signal";
      const title = document.createElement("h3");
      title.textContent = alert.rule;
      const summary = document.createElement("p");
      summary.textContent = alert.identity + " · " + alert.services.join(" → ");
      const explanation = document.createElement("p");
      explanation.textContent = alert.explanation;
      const evidence = document.createElement("code");
      evidence.textContent = alert.events.join(", ");
      box.append(title, summary, explanation, evidence);
      signals.append(box);
    }
    el("signals").replaceChildren(signals);
    if (!state.detection?.alerts.length)
      el("signals").textContent = state.detection
        ? "No rules triggered for the ingested observations."
        : "No observations ingested.";
    table(
      "timeline",
      (state.detection?.events || []).map((row) => [
        row.event.event_id,
        row.event.event_time_utc,
        new Date(row.corrected_ms).toISOString(),
        "±" +
          row.uncertainty_ms +
          " ms" +
          (row.uncertain ? " · uncertain" : ""),
        row.labels.join(", "),
      ]),
    );
    el("updated").textContent = "Fetched " + new Date().toLocaleString();
    for (const id of ["refresh", "disconnect", "export"])
      el(id).disabled = false;
  } catch (error) {
    notice(error.message);
    el("connection").textContent = "Connection failed";
  }
}
el("connect").addEventListener("submit", (event) => {
  event.preventDefault();
  token = el("token").value;
  el("token").value = "";
  refresh();
});
el("refresh").addEventListener("click", refresh);
el("disconnect").addEventListener("click", () => {
  token = "";
  location.reload();
});
el("export").addEventListener("click", async () => {
  try {
    const evidence = await api("/v1/evidence");
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(evidence, null, 2)], {
        type: "application/json",
      }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "keyguard-evidence.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    notice(error.message);
  }
});
el("signed-file").addEventListener("change", async (event) => {
  signed = null;
  el("submit").disabled = true;
  try {
    const file = event.target.files[0];
    if (!file || file.size > 16 * 1024 * 1024)
      throw new Error("Choose a signed JSON file under 16 MiB.");
    signed = JSON.parse(await file.text());
    if (!signed.signature || !signed.body)
      throw new Error("Missing signed command fields.");
    el("preview").textContent = JSON.stringify(
      { actor: signed.actor, expires: signed.expires, body: signed.body },
      null,
      2,
    );
    el("submit").disabled = false;
  } catch (error) {
    notice(error.message);
  }
});
el("submit").addEventListener("click", async () => {
  el("submit").disabled = true;
  try {
    const result = await api("/v1/command", signed);
    notice("Action completed: " + JSON.stringify(result));
    signed = null;
    if (token) await refresh();
  } catch (error) {
    notice(
      error.message + " · Inspect state before preparing another command.",
    );
  }
});
