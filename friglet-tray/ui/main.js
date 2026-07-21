const invoke = window.__TAURI__.core.invoke;
const writeText = window.__TAURI__.clipboardManager.writeText;

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

  renderWallet(reachable ? status : null);
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
    const status = await invoke("get_status");
    // First-run setup mode only matters while the daemon is unreachable.
    if (!status.reachable) {
      await refreshSetupState();
    } else if (setupMode) {
      exitSetupMode();
    }
    render(status);
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
// Wallet view
// ---------------------------------------------------------------------------

let walletLabelsKey = null;

function truncateMiddle(value) {
  if (!value || value.length <= 38) return value || "–";
  return `${value.slice(0, 20)}…${value.slice(-14)}`;
}

async function copyAddress(address, confirmation) {
  if (!address) return;
  try {
    await writeText(address);
    confirmation.textContent = "Copied!";
    confirmation.classList.add("visible");
    setTimeout(() => confirmation.classList.remove("visible"), 1400);
  } catch (e) {
    console.error("copy failed", e);
    confirmation.textContent = "Copy failed";
    confirmation.classList.add("visible", "error");
    setTimeout(() => confirmation.classList.remove("visible", "error"), 1800);
  }
}

function renderLabelAddresses(labels) {
  const key = JSON.stringify(labels);
  if (key === walletLabelsKey) return;
  walletLabelsKey = key;

  const list = $("label-addresses");
  list.replaceChildren();
  $("no-label-addresses").hidden = labels.length > 0;
  for (const item of labels) {
    const row = document.createElement("div");
    row.className = "label-address-row";

    const meta = document.createElement("span");
    meta.className = "label-number";
    meta.textContent = `Label ${item.label}`;

    const address = document.createElement("code");
    address.className = "address-value";
    address.textContent = truncateMiddle(item.address);
    address.title = item.address;

    const copy = document.createElement("button");
    copy.type = "button";
    copy.className = "copy-btn";
    copy.textContent = "Copy";

    const confirmation = document.createElement("span");
    confirmation.className = "copied";
    confirmation.setAttribute("aria-live", "polite");
    confirmation.textContent = "Copied!";
    copy.addEventListener("click", () => copyAddress(item.address, confirmation));

    row.append(meta, address, copy, confirmation);
    list.append(row);
  }
}

function renderWallet(status) {
  const available = status != null;
  $("wallet-unavailable").hidden = available;
  $("wallet-unavailable").textContent = setupMode
    ? "Finish setup to load wallet activity."
    : "Connect to the daemon to load wallet activity.";
  $("wallet-content").classList.toggle("unavailable", !available);
  $("wallet-content").setAttribute("aria-disabled", String(!available));

  setText("wallet-tx-count", available ? status.tx_count.toLocaleString() : "–");
  setText("wallet-output-count", available ? status.outputs_found.toLocaleString() : "–");

  const base = available ? status.sp_address : null;
  setText("wallet-base-address", truncateMiddle(base));
  $("wallet-base-address").title = base ?? "";
  $("copy-base-address").disabled = !base;
  $("copy-base-address").dataset.address = base ?? "";
  renderLabelAddresses(available ? status.label_addresses : []);
}

$("copy-base-address").addEventListener("click", () =>
  copyAddress($("copy-base-address").dataset.address, $("copied-base-address"))
);

// ---------------------------------------------------------------------------
// Settings view
// ---------------------------------------------------------------------------

// The last config loaded from the daemon; unedited fields (log_level,
// control_socket, ...) are sent back unchanged on save.
let loadedConfig = null;

let configLoadInFlight = false;

// First-run setup mode: no reachable daemon AND no usable local config.
// The form is enabled in local mode and Save writes the config + key files
// via the tray itself (save_local_config) instead of the daemon socket.
let setupMode = false;
// Prefill baseline while in setup mode (partial config file over defaults).
let setupConfig = null;

function updateSettingsAvailability() {
  $("setup-banner").hidden = !setupMode;
  $("settings-unreachable").hidden = daemonReachable || setupMode;
  $("settings-fields").disabled = setupMode
    ? false
    : !daemonReachable || loadedConfig === null;
  $("cfg-scan-key").placeholder = setupMode
    ? "required (32-byte hex)"
    : "unchanged — enter to replace";
}

async function refreshSetupState() {
  try {
    const s = await invoke("get_setup_state");
    if (s.active && !setupMode) enterSetupMode(s);
    else if (!s.active && setupMode) exitSetupMode();
  } catch (e) {
    console.error("get_setup_state failed", e);
  }
}

function enterSetupMode(s) {
  setupMode = true;
  setupConfig = s.config;
  const paths = [s.config_path, s.key_file].filter(Boolean);
  $("setup-config-path").textContent = paths.length ? `Writes: ${paths.join(", ")}` : "";
  // A pre-setup loadConfig attempt may have left an "unreachable" error.
  settingsMessage("", false);
  if (loadedConfig === null) fillForm(setupConfig);
  updateSettingsAvailability();
}

function exitSetupMode() {
  setupMode = false;
  setupConfig = null;
  updateSettingsAvailability();
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
    ...(loadedConfig ?? setupConfig),
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

// Setup-mode save: the tray validates and writes the config + key files
// locally, then starts the daemon. On success the UI flips back to the
// normal daemon-backed mode.
async function saveSetupConfig() {
  $("save-btn").disabled = true;
  settingsMessage("Saving…", false);
  const key = $("cfg-scan-key").value;
  try {
    const spawnError = await invoke("save_local_config", {
      config: formConfig(),
      scanKey: key,
    });
    if (spawnError) {
      // Files were written; only starting the daemon failed. The next polls
      // leave setup mode (the config is complete now) and disable the form.
      settingsMessage(`Saved, but the daemon failed to start: ${spawnError}`, true);
    } else {
      exitSetupMode();
      await loadConfig();
      await refresh();
      settingsMessage("Saved — daemon started.", false);
    }
  } catch (e) {
    settingsMessage(String(e), true);
  }
  $("save-btn").disabled = false;
}

async function saveConfig(event) {
  event.preventDefault();
  if (setupMode) return saveSetupConfig();
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
  $("view-wallet").hidden = name !== "wallet";
  $("tab-status").classList.toggle("active", name === "status");
  $("tab-settings").classList.toggle("active", name === "settings");
  $("tab-wallet").classList.toggle("active", name === "wallet");
  if (name === "settings" && !setupMode && loadedConfig === null && !configLoadInFlight)
    loadConfig();
}

$("tab-status").addEventListener("click", () => showTab("status"));
$("tab-settings").addEventListener("click", () => showTab("settings"));
$("tab-wallet").addEventListener("click", () => showTab("wallet"));

refresh();
setInterval(refresh, 1000);
