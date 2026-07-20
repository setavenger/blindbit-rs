const invoke = window.__TAURI__.core.invoke;

const $ = (id) => document.getElementById(id);

function setText(id, value) {
  $(id).textContent = value;
}

// ---------------------------------------------------------------------------
// Status view
// ---------------------------------------------------------------------------

let daemonReachable = false;

function render({ reachable, status }) {
  daemonReachable = reachable;
  const pill = $("reachable");
  pill.textContent = reachable ? "connected" : "unreachable";
  pill.className = `pill ${reachable ? "pill-good" : "pill-bad"}`;
  updateSettingsAvailability();
  // Load the settings form on the first poll that finds the daemon up
  // (retried at poll cadence while loading fails).
  if (reachable && loadedConfig === null && !configLoadInFlight) loadConfig();

  if (!status) return; // nothing known yet; keep placeholders

  setText("scanning", status.scanning ? "running" : "stopped");
  setText("scanned-height", status.scanned_height.toLocaleString());
  setText("tip-height", status.tip_height != null ? status.tip_height.toLocaleString() : "?");

  const pct = Math.max(0, Math.min(1, status.scan_progress)) * 100;
  $("progress-bar").style.width = `${pct}%`;
  setText("progress-text", `${pct.toFixed(1)}%`);

  setText("network", status.network);
  setText("electrum-clients", status.electrum_clients);
  setText("oracle", status.oracle_connected ? "connected" : "disconnected");
  setText("version", status.version);
  setText("sp-address", status.sp_address ?? "–");

  $("error-block").hidden = !status.last_error;
  setText("last-error", status.last_error ?? "");

  $("start-btn").disabled = !reachable || status.scanning;
  $("stop-btn").disabled = !reachable || !status.scanning;
}

async function refresh() {
  try {
    render(await invoke("get_status"));
  } catch (e) {
    console.error("get_status failed", e);
  }
}

async function action(command) {
  $("action-error").textContent = "";
  try {
    await invoke(command);
    await refresh();
  } catch (e) {
    $("action-error").textContent = String(e);
  }
}

$("start-btn").addEventListener("click", () => action("start_scanning"));
$("stop-btn").addEventListener("click", () => action("stop_scanning"));

// ---------------------------------------------------------------------------
// Settings view
// ---------------------------------------------------------------------------

// The last config loaded from the daemon; unedited fields (log_level,
// control_socket, ...) are sent back unchanged on save.
let loadedConfig = null;

let configLoadInFlight = false;

function updateSettingsAvailability() {
  $("settings-unreachable").hidden = daemonReachable;
  $("settings-fields").disabled = !daemonReachable || loadedConfig === null;
}

function fillForm(cfg) {
  $("cfg-network").value = cfg.network;
  $("cfg-oracle-url").value = cfg.oracle_url;
  $("cfg-p2p-addr").value = cfg.p2p_node_addr ?? "";
  $("cfg-start-height").value = cfg.start_height ?? "";
  $("cfg-spend-pubkey").value = cfg.spend_pubkey ?? "";
  $("cfg-max-labels").value = cfg.max_label_num;
  $("cfg-key-file").value = cfg.key_file ?? "";
  $("cfg-http-addr").value = cfg.http_addr;
  $("cfg-electrum-addr").value = cfg.electrum_addr;
  $("cfg-state-file").value = cfg.state_file;
  $("cfg-scan-key").value = "";
}

// Build the config to send: loaded config + form edits. Empty optional
// fields become null; the daemon validates everything.
function formConfig() {
  const text = (id) => $(id).value.trim();
  const optional = (id) => text(id) || null;
  return {
    ...loadedConfig,
    network: $("cfg-network").value,
    oracle_url: text("cfg-oracle-url"),
    p2p_node_addr: optional("cfg-p2p-addr"),
    start_height: text("cfg-start-height") === "" ? null : Number(text("cfg-start-height")),
    spend_pubkey: optional("cfg-spend-pubkey"),
    max_label_num: Number(text("cfg-max-labels") || "0"),
    key_file: optional("cfg-key-file"),
    http_addr: text("cfg-http-addr"),
    electrum_addr: text("cfg-electrum-addr"),
    state_file: text("cfg-state-file"),
  };
}

function settingsMessage(text, isError) {
  const el = $("settings-msg");
  el.textContent = text;
  el.className = `small ${isError ? "error" : "ok"}`;
}

async function loadConfig() {
  configLoadInFlight = true;
  try {
    loadedConfig = await invoke("get_config");
    fillForm(loadedConfig);
    settingsMessage("", false);
  } catch (e) {
    loadedConfig = null;
    settingsMessage(String(e), true);
  } finally {
    configLoadInFlight = false;
  }
  updateSettingsAvailability();
}

async function saveConfig(event) {
  event.preventDefault();
  if (loadedConfig === null) return;
  $("save-btn").disabled = true;
  settingsMessage("Saving…", false);

  const notes = [];
  // Config first: if the user changed key_file in the same save, the scan
  // key below must land in the NEW path. A set_config failure aborts the
  // save before the key is sent anywhere, keeping the form edits intact.
  try {
    const note = await invoke("set_config", { config: formConfig() });
    if (note) notes.push(note);
  } catch (e) {
    settingsMessage(String(e), true);
    $("save-btn").disabled = false;
    return;
  }

  // The config is persisted daemon-side from here on. Write-only scan key:
  // only sent when the user typed one; a failure must not skip the reload
  // below, or the form keeps merging stale hidden fields into later saves.
  let keyError = null;
  const key = $("cfg-scan-key").value.trim();
  if (key !== "") {
    try {
      const keyNote = await invoke("set_scan_key", { key });
      if (keyNote) notes.push(keyNote);
    } catch (e) {
      keyError = String(e);
    }
  }

  // Reload so loadedConfig matches what the daemon persisted (loadConfig
  // clears the message, so report the outcome afterwards).
  await loadConfig();
  await refresh();
  if (keyError) {
    settingsMessage(`Config saved, but updating the scan key failed: ${keyError}`, true);
    // fillForm cleared the key input; restore it so the user can retry.
    $("cfg-scan-key").value = key;
  } else {
    settingsMessage(notes.length ? `Saved. ${notes.join(". ")}` : "Saved.", false);
  }
  $("save-btn").disabled = false;
}

$("settings-form").addEventListener("submit", saveConfig);
$("reload-btn").addEventListener("click", loadConfig);

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

function showTab(name) {
  $("view-status").hidden = name !== "status";
  $("view-settings").hidden = name !== "settings";
  $("tab-status").classList.toggle("active", name === "status");
  $("tab-settings").classList.toggle("active", name === "settings");
  if (name === "settings" && loadedConfig === null && !configLoadInFlight) loadConfig();
}

$("tab-status").addEventListener("click", () => showTab("status"));
$("tab-settings").addEventListener("click", () => showTab("settings"));

refresh();
setInterval(refresh, 1000);
