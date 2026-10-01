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

// Crash / restart state of a tray-supervised daemon.
function renderHealth(daemon, reachable) {
  const card = $("daemon-health");
  const pending = daemon?.restart_in_secs != null;
  const show = daemon && (daemon.last_exit || daemon.last_error || pending);
  card.hidden = !show;
  if (!show) return;

  const recovered = reachable && !pending;
  card.classList.toggle("recovered", recovered);
  const pill = $("health-state");
  pill.className = `pill ${recovered ? "pill-good" : "pill-bad"}`;
  if (pending) {
    pill.textContent = daemon.restart_in_secs > 0
      ? `crashed — restarting in ${daemon.restart_in_secs}s`
      : "crashed — restarting…";
  } else if (recovered) {
    pill.textContent = "restarted";
  } else {
    pill.textContent = "restarting…";
  }

  const parts = [];
  if (daemon.last_exit) {
    const when = daemon.last_exit_at
      ? new Date(daemon.last_exit_at * 1000).toLocaleTimeString()
      : "";
    parts.push(`Last crash${when ? ` at ${when}` : ""}: ${daemon.last_exit}.`);
  }
  if (daemon.restarts > 0) {
    parts.push(`Restarted automatically ${daemon.restarts}× this session.`);
  }
  if (daemon.last_error) parts.push(`Last restart attempt failed: ${daemon.last_error}`);
  setText("health-detail", parts.join(" "));
  $("health-output").hidden = !daemon.last_output;
  setText("health-output", daemon.last_output ?? "");
}

function render({ reachable, status, daemon }) {
  daemonReachable = reachable;
  renderHealth(daemon, reachable);
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
  renderScanHealth(status.scan_health ?? {});

  $("start-btn").disabled = !reachable || status.scanning;
  $("stop-btn").disabled = !reachable || !status.scanning;
}

// Why the scan is stuck, and where it started (the daemon's `scan_health`;
// absent from older daemons).
function renderScanHealth(health) {
  const stall = health.stall;
  $("stall-block").hidden = !stall;
  setText(
    "stall",
    stall
      ? `at height ${stall.height.toLocaleString()} since ` +
          `${new Date(stall.since_unix * 1000).toLocaleString()}: ${stall.reason}`
      : "",
  );

  const notes = [];
  const start = health.start_adjusted;
  if (start) {
    notes.push(
      `Scanning began at block ${start.oracle_floor.toLocaleString()} instead of ` +
        `${start.requested_height.toLocaleString()}: the oracle has no data below it.`,
    );
  }
  const reset = health.state_reset;
  if (reset) {
    notes.push(
      `The state file could not be read (${reset.error}). It was moved to ` +
        `${reset.backup_path}, and the wallet is being scanned again from its start height.`,
    );
  }
  const rescan = health.state_rescan;
  if (rescan) {
    notes.push(
      `Rescanning blocks ${rescan.from_height.toLocaleString()}–` +
        `${rescan.until_height.toLocaleString()} once: the state file predates ` +
        `spend tracking, so spends it missed are being looked for.`,
    );
  }
  $("scan-notes-block").hidden = notes.length === 0;
  setText("scan-notes", notes.join("\n"));
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

// Hosted oracles and default P2P ports per network (from the Rust side, so
// the daemon and the form agree).
let networkDefaults = { hosted_oracles: {}, default_ports: {} };

function updateSettingsAvailability() {
  $("setup-banner").hidden = !setupMode;
  $("settings-unreachable").hidden = daemonReachable || setupMode;
  $("settings-fields").disabled = setupMode
    ? false
    : !daemonReachable || loadedConfig === null;
  $("cfg-scan-key").placeholder = setupMode
    ? "not needed when a descriptor is pasted"
    : "unchanged — enter to replace";
  $("cfg-descriptor").placeholder = setupMode
    ? "sp([…/352h/0h/0h]spscan1q…)#…"
    : "paste a descriptor only to switch to another wallet";
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
  // Default for a first-time setup: start at login (shown, can be unticked).
  $("cfg-autostart").checked = true;
  autostartMessage("Applied when you save.", false);
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
  autostartMessage("", false);
  loadAutostart();
  updateSettingsAvailability();
}

// --- network-dependent defaults --------------------------------------------

const normalizeUrl = (url) => url.trim().replace(/\/+$/, "");

function hostedOracle(network) {
  return networkDefaults.hosted_oracles[network] ?? null;
}

function isHostedOracle(url) {
  return Object.values(networkDefaults.hosted_oracles).includes(normalizeUrl(url));
}

function updateNetworkHints() {
  const network = $("cfg-network").value;
  const hosted = hostedOracle(network);
  const url = normalizeUrl($("cfg-oracle-url").value);
  const hint = $("oracle-hint");
  if (hosted && url === hosted) {
    hint.textContent = `Hosted ${network} oracle.`;
    hint.className = "hint";
  } else if (hosted) {
    hint.textContent = `Custom oracle. The hosted ${network} oracle is ${hosted}.`;
    hint.className = "hint";
  } else {
    hint.textContent = `There is no hosted oracle for ${network}: enter the URL of your own BlindBit oracle.`;
    hint.className = url ? "hint" : "hint warn";
  }
  const port = networkDefaults.default_ports[network];
  $("cfg-p2p-addr").placeholder = port ? `node.example.com:${port}` : "host:port";
}

// Switching networks swaps a hosted (or empty) oracle URL for the new
// network's hosted one; a custom URL is left alone.
function onNetworkChange({ reinspect = true } = {}) {
  const network = $("cfg-network").value;
  const oracle = $("cfg-oracle-url");
  if (oracle.value.trim() === "" || isHostedOracle(oracle.value)) {
    oracle.value = hostedOracle(network) ?? "";
  }
  updateNetworkHints();
  if (reinspect && $("cfg-descriptor").value.trim()) inspectDescriptor();
}

// --- wallet birthday ---------------------------------------------------------

function setBirthday(mode, height) {
  $("birthday-tip").checked = mode === "tip";
  $("birthday-height").checked = mode === "height";
  if (height != null) $("cfg-start-height").value = height;
  $("cfg-start-height").disabled = mode !== "height";
}

// --- descriptor paste ----------------------------------------------------------

// Summary of the currently pasted descriptor (null when empty or invalid).
let descriptorSummary = null;
let descriptorSeq = 0;
// The pasted text carried the spend private key and was replaced by the
// watch-only form; sticky until the user edits the field again.
let spendSecretDropped = false;

function descriptorStatus(text, kind) {
  const el = $("descriptor-status");
  el.textContent = text;
  el.className = `hint ${kind ?? ""}`;
}

async function inspectDescriptor() {
  const text = $("cfg-descriptor").value.trim();
  const seq = ++descriptorSeq;
  if (!text) {
    descriptorSummary = null;
    descriptorStatus("", "");
    return;
  }
  try {
    const s = await invoke("inspect_descriptor", {
      descriptor: text,
      network: $("cfg-network").value,
    });
    if (seq !== descriptorSeq) return; // superseded by a newer edit
    const firstLook = descriptorSummary === null;
    descriptorSummary = s;
    if ($("cfg-network").value !== s.network) {
      $("cfg-network").value = s.network;
      onNetworkChange({ reinspect: false });
    }
    $("cfg-spend-pubkey").value = s.spend_pubkey;
    $("cfg-scan-key").value = ""; // the descriptor supplies the scan key
    if (s.had_spend_secret) {
      spendSecretDropped = true;
      $("cfg-descriptor").value = s.watch_only;
    }
    // A different wallet gets its own birthday (Sparrow's bh=, else "new
    // wallet"); re-pasting the configured wallet keeps the current one.
    const sameWallet = loadedConfig?.spend_pubkey === s.spend_pubkey;
    if (firstLook && !sameWallet) {
      if (s.birth_height != null) setBirthday("height", s.birth_height);
      else setBirthday("tip");
    }

    const kind = s.mainnet ? "mainnet" : "test-network";
    let msg = `✓ Watch-only ${kind} wallet, address ${truncateMiddle(s.sp_address)} — it should match Sparrow's Receive tab.`;
    if (s.birth_height != null) msg += ` Birthday from the descriptor: block ${s.birth_height}.`;
    if (spendSecretDropped) {
      msg = "This descriptor contained your spend PRIVATE key. Friglet only needs the " +
        "watch-only part: it kept the public key and replaced the text above with the " +
        "watch-only descriptor. The private key is not stored. " + msg;
      descriptorStatus(msg, "warn");
    } else {
      descriptorStatus(msg, "ok");
    }
  } catch (e) {
    if (seq !== descriptorSeq) return;
    descriptorSummary = null;
    descriptorStatus(String(e), "error");
  }
}

let descriptorTimer = null;
$("cfg-descriptor").addEventListener("input", () => {
  spendSecretDropped = false;
  clearTimeout(descriptorTimer);
  descriptorTimer = setTimeout(inspectDescriptor, 200);
});
$("cfg-network").addEventListener("change", () => onNetworkChange());
$("cfg-oracle-url").addEventListener("input", updateNetworkHints);
$("birthday-tip").addEventListener("change", () => setBirthday("tip"));
$("birthday-height").addEventListener("change", () => {
  setBirthday("height");
  $("cfg-start-height").focus();
});

// --- form <-> config -------------------------------------------------------------

function fillForm(cfg) {
  $("cfg-network").value = cfg.network;
  $("cfg-oracle-url").value = cfg.oracle_url;
  // A fresh config still carries the mainnet default oracle; follow the
  // network unless a custom URL is set.
  if (isHostedOracle(cfg.oracle_url)) $("cfg-oracle-url").value = hostedOracle(cfg.network) ?? cfg.oracle_url;
  $("cfg-p2p-addr").value = cfg.p2p_node_addr ?? "";
  if (cfg.start_height != null) setBirthday("height", cfg.start_height);
  else {
    $("cfg-start-height").value = "";
    setBirthday("tip");
  }
  $("cfg-spend-pubkey").value = cfg.spend_pubkey ?? "";
  $("cfg-max-labels").value = cfg.max_label_num;
  $("cfg-key-file").value = cfg.key_file ?? "";
  $("cfg-http-addr").value = cfg.http_addr;
  $("cfg-electrum-addr").value = cfg.electrum_addr;
  $("cfg-state-file").value = cfg.state_file;
  $("cfg-scan-key").value = "";
  $("cfg-descriptor").value = "";
  descriptorSummary = null;
  spendSecretDropped = false;
  descriptorStatus("", "");
  updateNetworkHints();
}

// Build the config to send: loaded config + form edits. Empty optional
// fields become null; the daemon validates everything.
function formConfig() {
  const text = (id) => $(id).value.trim();
  const optional = (id) => text(id) || null;
  const atTip = $("birthday-tip").checked;
  return {
    ...(loadedConfig ?? setupConfig),
    network: $("cfg-network").value,
    oracle_url: text("cfg-oracle-url"),
    p2p_node_addr: optional("cfg-p2p-addr"),
    start_height: atTip || text("cfg-start-height") === "" ? null : Number(text("cfg-start-height")),
    start_at_tip: atTip,
    spend_pubkey: optional("cfg-spend-pubkey"),
    max_label_num: Number(text("cfg-max-labels") || "0"),
    key_file: optional("cfg-key-file"),
    http_addr: text("cfg-http-addr"),
    electrum_addr: text("cfg-electrum-addr"),
    state_file: text("cfg-state-file"),
  };
}

// The pasted descriptor to save with, or an error when the field holds
// something that did not parse.
function pastedDescriptor() {
  const text = $("cfg-descriptor").value.trim();
  if (!text) return { descriptor: null };
  if (!descriptorSummary) {
    return { error: "The descriptor could not be read — see the message under it." };
  }
  return { descriptor: text };
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
  const { descriptor, error } = pastedDescriptor();
  if (error) return settingsMessage(error, true);
  $("save-btn").disabled = true;
  settingsMessage("Saving…", false);
  const key = $("cfg-scan-key").value;
  try {
    const spawnError = await invoke("save_local_config", {
      config: formConfig(),
      scanKey: key,
      descriptor,
      autostart: $("cfg-autostart").checked,
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

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// After a save the daemon restarts in-process; wait until it answers again
// (a new wallet may first fetch the chain tip from the oracle).
async function waitForDaemon(timeoutMs = 60000) {
  await sleep(600); // let the old instance go away first
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      return await invoke("get_config");
    } catch (_) {
      await sleep(500);
    }
  }
  return null;
}

async function saveConfig(event) {
  event.preventDefault();
  if (setupMode) return saveSetupConfig();
  if (loadedConfig === null) return;
  const { descriptor, error } = pastedDescriptor();
  if (error) return settingsMessage(error, true);
  $("save-btn").disabled = true;
  settingsMessage("Saving…", false);

  // Config + (optional) scan key in one request: the daemon validates both,
  // persists them and restarts once. A failure leaves the form as typed.
  const key = $("cfg-scan-key").value.trim();
  let note;
  try {
    note = await invoke("apply_settings", {
      config: formConfig(),
      scanKey: key || null,
      descriptor,
    });
  } catch (e) {
    settingsMessage(String(e), true);
    $("save-btn").disabled = false;
    return;
  }
  if (!note) {
    settingsMessage("No changes to save.", false);
    $("save-btn").disabled = false;
    return;
  }

  settingsMessage("Saved — restarting the daemon with the new settings…", false);
  const cfg = await waitForDaemon();
  // Reload so loadedConfig matches what the daemon persisted (loadConfig
  // clears the message, so report the outcome afterwards).
  await loadConfig();
  await refresh();
  if (cfg) {
    settingsMessage("Saved — the daemon restarted with the new settings. Sparrow reconnects by itself.", false);
  } else {
    settingsMessage(
      "Saved, but the daemon has not come back yet — see the Status tab for the reason.",
      true
    );
  }
  $("save-btn").disabled = false;
}

// --- start at login (a tray setting, independent of the daemon) -------------

function autostartMessage(text, isError) {
  const el = $("autostart-msg");
  el.textContent = text;
  el.className = `hint ${isError ? "error" : ""}`;
}

async function loadAutostart() {
  try {
    const enabled = await invoke("get_autostart");
    // First-run setup shows its own default until Save applies it.
    if (!setupMode) $("cfg-autostart").checked = enabled;
  } catch (e) {
    autostartMessage(String(e), true);
  }
}

$("cfg-autostart").addEventListener("change", async () => {
  // In first-run setup the choice is applied together with Save.
  if (setupMode) {
    autostartMessage("Applied when you save.", false);
    return;
  }
  const enabled = $("cfg-autostart").checked;
  try {
    await invoke("set_autostart", { enabled });
    autostartMessage(enabled ? "Friglet starts at login." : "Friglet no longer starts at login.", false);
  } catch (e) {
    $("cfg-autostart").checked = !enabled;
    autostartMessage(String(e), true);
  }
});

$("settings-form").addEventListener("submit", saveConfig);
$("reload-btn").addEventListener("click", loadConfig);

loadAutostart();

invoke("network_defaults")
  .then((d) => {
    networkDefaults = d;
    // The form may have been filled before the defaults arrived.
    onNetworkChange({ reinspect: false });
  })
  .catch((e) => console.error("network_defaults failed", e));

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
