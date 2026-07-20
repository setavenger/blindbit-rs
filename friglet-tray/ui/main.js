const invoke = window.__TAURI__.core.invoke;

const $ = (id) => document.getElementById(id);

function setText(id, value) {
  $(id).textContent = value;
}

function render({ reachable, status }) {
  const pill = $("reachable");
  pill.textContent = reachable ? "connected" : "unreachable";
  pill.className = `pill ${reachable ? "pill-good" : "pill-bad"}`;

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

refresh();
setInterval(refresh, 1000);
