"use strict";

const { invoke } = window.__TAURI__.core;
const $ = (id) => document.getElementById(id);

const LABELS = {
  disconnected: ["Not connected", "Connect"],
  connecting: ["Connecting…", "Cancel"],
  connected: ["Protected", "Disconnect"],
  reconnecting: ["Reconnecting…", "Disconnect"],
};

let status = null;
let importing = false;
let busy = false;
// An error from something the user just did, as opposed to one the service reports.
let ownError = "";

// Text only ever goes in through textContent: names and messages come from outside.
function text(id, value) {
  if ($(id).textContent !== value) $(id).textContent = value;
}

function view(name) {
  for (const id of ["unavailable", "welcome", "home", "import"]) $(id).hidden = id !== name;
}

function showError(message) {
  text("error", message ?? "");
  $("error").hidden = !message;
}

function duration(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return h ? `${h} h ${m} min` : m ? `${m} min ${s} s` : `${s} s`;
}

function size(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) {
    bytes /= 1024;
    i += 1;
  }
  return `${i ? bytes.toFixed(1) : bytes} ${units[i]}`;
}

const everything = (routes) => routes.includes("0.0.0.0/0");
const describe = (routes) => (everything(routes) ? "All IPv4 traffic" : routes.join(", "));

function render() {
  if (importing) return view("import");
  if (!status.profile) {
    view("welcome");
    return showError(ownError || status.error);
  }
  view("home");
  const state = status.state;
  const connected = state === "connected";
  text("state", LABELS[state][0]);
  text("action", LABELS[state][1]);
  $("power").dataset.state = state;
  $("power").disabled = busy;
  text("detail", connected ? "Post-quantum encryption" : state === "reconnecting" ? "The server stopped answering." : "");
  text("server", `${status.profile.server}:${status.profile.port}`);
  const routes = connected ? status.routes : status.profile.routes;
  text("routes", describe(routes));
  for (const element of document.querySelectorAll(".live")) element.hidden = !connected;
  if (connected) {
    text("address", status.address ?? "");
    text("duration", duration(status.connected_seconds));
    text("traffic", `↓ ${size(status.bytes_in)}   ↑ ${size(status.bytes_out)}`);
  }
  $("ipv6").hidden = !(connected && everything(routes));
  showError(ownError || status.error);
}

async function refresh() {
  try {
    status = await invoke("status");
  } catch (reason) {
    status = null;
    if (!importing) {
      view("unavailable");
      text("unavailable-reason", String(reason));
      showError("");
    }
    return;
  }
  render();
}

async function act(command, args) {
  busy = true;
  ownError = "";
  if (status) render();
  try {
    await invoke(command, args);
  } catch (reason) {
    ownError = String(reason);
  }
  busy = false;
  await refresh();
}

$("power").addEventListener("click", () => act(status.state === "disconnected" ? "connect" : "disconnect"));

for (const button of document.querySelectorAll(".choose")) {
  button.addEventListener("click", async () => {
    ownError = "";
    try {
      const preview = await invoke("choose_profile");
      if (!preview) return;
      const form = $("settings");
      form.elements.server.value = preview.server;
      form.elements.port.value = preview.port;
      form.elements.routes.value = "";
      text("file", preview.name);
      text("allowed", preview.routes === "0.0.0.0/0" ? "all IPv4 traffic" : preview.routes);
      importing = true;
      showError("");
      view("import");
    } catch (reason) {
      ownError = String(reason);
      showError(ownError);
    }
  });
}

$("settings").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target.elements;
  try {
    await invoke("import_profile", {
      server: form.server.value,
      port: Number(form.port.value),
      routes: form.routes.value,
    });
    importing = false;
    ownError = "";
    await refresh();
  } catch (reason) {
    showError(String(reason));
  }
});

$("cancel").addEventListener("click", () => {
  importing = false;
  showError("");
  refresh();
});

// A second click confirms, without a dialog box.
let armed = null;
$("remove").addEventListener("click", () => {
  if (!armed) {
    text("remove", "Click again to remove");
    armed = setTimeout(() => {
      armed = null;
      text("remove", "Remove profile");
    }, 4000);
    return;
  }
  clearTimeout(armed);
  armed = null;
  text("remove", "Remove profile");
  act("remove_profile");
});

(async function poll() {
  await refresh();
  setTimeout(poll, 1000);
})();
