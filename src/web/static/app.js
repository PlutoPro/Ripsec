"use strict";

const $ = (id) => document.getElementById(id);
let me = null;
let enrolment = null;

async function api(method, path, body) {
  const response = await fetch(path, {
    method,
    headers: { "x-ripsec": "1", ...(body && { "content-type": "application/json" }) },
    body: body && JSON.stringify(body),
  });
  if (response.status === 401) {
    show(false);
    throw new Error("Your session ended. Sign in again.");
  }
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { error: text }; }
  if (!response.ok) throw new Error(data?.error || response.statusText);
  return data;
}

function show(signedIn) {
  $("signin").hidden = signedIn;
  $("app").hidden = !signedIn;
  $("logout").hidden = !signedIn;
  if (!signedIn) me = null;
}

function report(error) {
  $("error").textContent = error ? error.message : "";
  $("error").hidden = !error;
}

// Text only: names come from users and must never be parsed as HTML.
function cell(row, text) {
  const td = row.insertCell();
  td.textContent = text;
  return td;
}

function action(td, label, run, confirmText) {
  const button = document.createElement("button");
  button.textContent = label;
  button.className = "quiet";
  button.addEventListener("click", async () => {
    if (confirmText && !confirm(confirmText)) return;
    try { await run(); report(); await refresh(); } catch (e) { report(e); }
  });
  td.append(button);
}

function size(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (bytes >= 1000 && i < units.length - 1) { bytes /= 1000; i++; }
  return `${bytes.toFixed(i ? 1 : 0)} ${units[i]}`;
}

function duration(seconds) {
  const h = Math.floor(seconds / 3600), m = Math.floor((seconds % 3600) / 60);
  return h ? `${h}h ${m}m` : `${m}m ${seconds % 60}s`;
}

function empty(tbody, columns, text) {
  if (tbody.rows.length) return;
  const td = tbody.insertRow().insertCell();
  td.colSpan = columns;
  td.textContent = text;
  td.className = "note";
}

async function refresh() {
  if (!me) return;
  const [devices, sessions] = await Promise.all([api("GET", "/api/devices"), api("GET", "/api/sessions")]);

  const d = $("devices");
  d.replaceChildren();
  for (const device of devices) {
    const row = d.insertRow();
    cell(row, device.name);
    cell(row, device.owner_name);
    cell(row, device.id).className = "mono";
    const site = device.remote_subnets.length > 0;
    cell(row, site ? `site ${device.remote_subnets.join(", ")}`
      : device.active ? `until ${new Date(device.expires * 1000).toLocaleString()}` : "expired");
    const td = row.insertCell();
    const url = `/api/devices/${encodeURIComponent(device.id)}`;
    if (device.mine && !site) action(td, "Renew", () => api("POST", `${url}/renew`));
    action(td, "Revoke", () => api("DELETE", url), `Revoke ${device.name}? It will be disconnected.`);
  }
  empty(d, 5, "No devices yet.");

  const s = $("sessions");
  s.replaceChildren();
  for (const session of sessions) {
    const row = s.insertRow();
    cell(row, session.device_name);
    cell(row, session.peer);
    cell(row, session.virtual_ip ?? "site");
    const kex = cell(row, session.post_quantum ? "ML-KEM hybrid" : "classical only");
    kex.className = session.post_quantum ? "good" : "bad";
    cell(row, `${size(session.bytes_in)} / ${size(session.bytes_out)}`);
    cell(row, duration(session.connected_seconds));
    action(row.insertCell(), "Disconnect", () => api("DELETE", `/api/sessions/${session.id}`));
  }
  empty(s, 7, "Nobody is connected.");
}

function download(name, text, type) {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([text], { type }));
  link.download = name;
  link.click();
  URL.revokeObjectURL(link.href);
}

$("add").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const subnets = form.subnets.value.split(",").map((s) => s.trim()).filter(Boolean);
  try {
    enrolment = await api("POST", "/api/devices", { name: form.name.value, remote_subnets: subnets });
    $("r-server").textContent = enrolment.server_address;
    $("r-serverid").textContent = enrolment.server_id;
    $("r-id").textContent = enrolment.device.id;
    $("r-secret").textContent = enrolment.secret;
    $("dl-apple").hidden = !enrolment.apple;
    $("result").hidden = false;
    form.reset();
    report();
    await refresh();
  } catch (e) { report(e); }
});

$("dl-apple").addEventListener("click", () =>
  download("ripsec.mobileconfig", enrolment.apple, "application/x-apple-aspen-config"));
$("dl-strongswan").addEventListener("click", () =>
  download("ripsec.conf", enrolment.strongswan, "text/plain"));
$("dismiss").addEventListener("click", () => {
  enrolment = null;
  $("r-secret").textContent = "";
  $("result").hidden = true;
});

$("logout").addEventListener("click", async () => {
  const { provider_logout } = await api("POST", "/auth/logout");
  if (provider_logout) location.assign(provider_logout);
  else location.reload();
});

(async () => {
  try {
    me = await api("GET", "/api/me");
  } catch {
    return show(false);
  }
  show(true);
  $("who").textContent = `${me.name}${me.admin ? " (administrator)" : ""}`;
  $("subnets").hidden = !me.admin;
  await refresh().catch(report);
  setInterval(() => refresh().catch(report), 5000);
})();
