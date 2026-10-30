//! Top-bar popup mode for Hyprland (SNB-656).
//!
//! On Hyprland (Omarchy 4 among others) the status window opens as a
//! floating panel right-aligned under the top bar, like Omarchy's own
//! Wi-Fi / Bluetooth / Tailscale panels, instead of as a tiled window. A
//! left click on the tray icon toggles it; Esc closes it, and so does
//! focusing another window.
//!
//! The mode is on only when `HYPRLAND_INSTANCE_SIGNATURE` is set. It talks
//! to Hyprland's request socket directly and writes no config files.
//!
//! 1. Before each show it reads the monitor under the pointer
//!    (`j/cursorpos`, `j/monitors`: bar height from `reserved`) and
//!    `general:gaps_out`, and works out where the panel goes, the way
//!    Omarchy places its panels (`y = bar + gaps_out / 2`, the same margin
//!    on the right). With the Lua API (Hyprland 0.55+, Omarchy 4) it then
//!    registers a window rule for our window (float, size, monitor-relative
//!    move) with `eval`, so the window maps in place, and turns on a rule
//!    that keeps the pointer from focusing *other* windows by hovering them
//!    while the popup is open (Omarchy sets `follow_mouse = 1`, so a stray
//!    pointer would otherwise steal the focus and close the popup; a click
//!    still focuses them). Hiding turns that rule off again.
//! 2. After the show it finds our window in `j/clients` by PID, learns the
//!    class Hyprland sees (so later rules match class and title, and it is
//!    logged for a static rule), and if the window did not land where
//!    planned (no Lua API, or the rule was wiped by a config reload) it
//!    floats, resizes and moves it by address: `hl.dsp.window.*` with the
//!    Lua API, the legacy dispatchers otherwise.
//!
//! The window is also undecorated and fixed-size (min = max) in this mode:
//! Hyprland floats fixed-size toplevels by itself, so the panel still floats
//! (centred) if every socket call fails.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tauri::{LogicalSize, WebviewWindow};

/// Panel size in logical pixels (the window's configured size).
pub const POPUP_SIZE: (u32, u32) = (420, 600);
/// Hyprland's default `general:gaps_out`, used when it can't be read.
const DEFAULT_GAPS_OUT: f64 = 20.0;
/// Read/write timeout for one request on the Hyprland socket.
#[cfg(unix)]
const IO_TIMEOUT: Duration = Duration::from_millis(500);
/// A focus loss this close before a tray click means the click caused it:
/// the click then leaves the popup closed instead of reopening it.
const BLUR_CLICK_WINDOW: Duration = Duration::from_millis(400);
/// How long to wait before acting on a focus loss, so the focus can settle.
const BLUR_SETTLE: Duration = Duration::from_millis(150);
/// How long to look for our window in `j/clients` after a show.
const MAP_TIMEOUT: Duration = Duration::from_millis(1500);
const MAP_POLL: Duration = Duration::from_millis(50);
/// Lua globals (in Hyprland's config state) holding our rule handles.
const LUA_POPUP_RULE: &str = "friglet_tray_popup_rule";
const LUA_NOHOVER_RULE: &str = "friglet_tray_nohover_rule";

// ---------------------------------------------------------------------------
// Socket
// ---------------------------------------------------------------------------

/// Hyprland's request socket (`.socket.sock`, the one `hyprctl` uses).
#[derive(Clone, Debug)]
pub struct Hyprland {
    socket: PathBuf,
}

impl Hyprland {
    /// The running Hyprland instance, if this process is inside one.
    pub fn from_env() -> Option<Self> {
        let sig = std::env::var("HYPRLAND_INSTANCE_SIGNATURE").ok()?;
        let sig = sig.trim();
        if sig.is_empty() {
            return None;
        }
        let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        Some(Self::new(socket_path(runtime.as_deref(), sig)))
    }

    pub fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    /// Send one request and return the whole reply. Hyprland reads the
    /// request as sent (no terminator), answers once and closes.
    #[cfg(unix)]
    pub fn request(&self, request: &str) -> io::Result<String> {
        use std::io::{Read, Write};
        use std::net::Shutdown;
        use std::os::unix::net::UnixStream;

        let mut stream = UnixStream::connect(&self.socket)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        stream.write_all(request.as_bytes())?;
        let _ = stream.shutdown(Shutdown::Write);
        let mut reply = String::new();
        stream.read_to_string(&mut reply)?;
        Ok(reply)
    }

    #[cfg(not(unix))]
    pub fn request(&self, _request: &str) -> io::Result<String> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no Hyprland here",
        ))
    }

    fn json<T: for<'de> Deserialize<'de>>(&self, request: &str) -> io::Result<T> {
        let reply = self.request(&format!("j/{request}"))?;
        serde_json::from_str(&reply).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{request}: {e}: {}", truncate(&reply)),
            )
        })
    }

    pub fn monitors(&self) -> io::Result<Vec<Monitor>> {
        self.json("monitors")
    }

    pub fn clients(&self) -> io::Result<Vec<Client>> {
        self.json("clients")
    }

    /// The focused window; `None` when nothing has focus (`{}`).
    pub fn active_window(&self) -> io::Result<Option<Client>> {
        let reply = self.request("j/activewindow")?;
        Ok(serde_json::from_str::<Client>(&reply)
            .ok()
            .filter(|c| !c.address.is_empty()))
    }

    /// Pointer position, global layout coordinates.
    pub fn cursor_pos(&self) -> io::Result<(f64, f64)> {
        #[derive(Deserialize)]
        struct Pos {
            x: f64,
            y: f64,
        }
        let p: Pos = self.json("cursorpos")?;
        Ok((p.x, p.y))
    }

    /// `general:gaps_out` (its top value), if readable.
    pub fn gaps_out(&self) -> Option<f64> {
        parse_gaps_out(&self.request("j/getoption general:gaps_out").ok()?)
    }
}

/// `$XDG_RUNTIME_DIR/hypr/<sig>/.socket.sock` (Hyprland 0.40+), or the
/// older `/tmp/hypr/<sig>/.socket.sock` when only that one exists.
pub fn socket_path(runtime_dir: Option<&Path>, signature: &str) -> PathBuf {
    let legacy = Path::new("/tmp/hypr").join(signature).join(".socket.sock");
    match runtime_dir {
        Some(dir) => {
            let current = dir.join("hypr").join(signature).join(".socket.sock");
            if !current.exists() && legacy.exists() {
                legacy
            } else {
                current
            }
        }
        None => legacy,
    }
}

fn truncate(s: &str) -> String {
    const MAX: usize = 200;
    match s.char_indices().nth(MAX) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------

/// The parts of a `j/monitors` entry the placement needs. Numbers are read
/// as `f64` so integer and float renderings both parse.
#[derive(Clone, Debug, Deserialize)]
pub struct Monitor {
    #[serde(default)]
    pub name: String,
    /// Top-left corner, global layout coordinates.
    pub x: f64,
    pub y: f64,
    /// Physical mode pixels, before the transform.
    pub width: f64,
    pub height: f64,
    #[serde(default = "one")]
    pub scale: f64,
    #[serde(default)]
    pub transform: i64,
    #[serde(default)]
    pub focused: bool,
    /// Space taken by bars (layer-shell exclusive zones):
    /// `[left, top, right, bottom]`, logical pixels.
    #[serde(default)]
    pub reserved: Vec<f64>,
}

fn one() -> f64 {
    1.0
}

impl Monitor {
    /// Size in layout (logical) pixels, as Hyprland computes it.
    pub fn logical_size(&self) -> (f64, f64) {
        let scale = if self.scale > 0.0 { self.scale } else { 1.0 };
        // Transforms 1, 3, 5 and 7 rotate by 90° or 270°.
        let (w, h) = if self.transform % 2 == 1 {
            (self.height, self.width)
        } else {
            (self.width, self.height)
        };
        ((w / scale).round(), (h / scale).round())
    }

    fn reserved(&self, i: usize) -> f64 {
        self.reserved.get(i).copied().unwrap_or(0.0).max(0.0)
    }

    fn contains(&self, x: f64, y: f64) -> bool {
        let (w, h) = self.logical_size();
        x >= self.x && x < self.x + w && y >= self.y && y < self.y + h
    }
}

/// The parts of a `j/clients` / `j/activewindow` entry we use.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Client {
    /// `0x…`, as `address:` selectors want it.
    pub address: String,
    pub pid: i64,
    pub class: String,
    pub title: String,
    pub floating: bool,
    /// Global layout coordinates.
    pub at: Vec<f64>,
    pub size: Vec<f64>,
}

/// `general:gaps_out` from a `j/getoption` reply: the first (top) value of
/// the CSS-style gap (`"css"` with the Lua config, `"custom"` with
/// hyprlang), or a plain `"int"`. Omarchy's panels take this first value.
pub fn parse_gaps_out(reply: &str) -> Option<f64> {
    let v: serde_json::Value = serde_json::from_str(reply).ok()?;
    if let Some(n) = v.get("int").and_then(serde_json::Value::as_f64) {
        return Some(n);
    }
    v.get("css")
        .or_else(|| v.get("custom"))
        .and_then(serde_json::Value::as_str)?
        .split(|c: char| c.is_whitespace() || c == ',')
        .find(|s| !s.is_empty())?
        .parse()
        .ok()
}

// ---------------------------------------------------------------------------
// Placement
// ---------------------------------------------------------------------------

/// Where the panel goes, in Hyprland layout (logical, global) coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    /// Distance from the monitor's top edge, and from its right edge to the
    /// panel's right edge: what a monitor-relative rule needs.
    pub top: i32,
    pub right: i32,
}

impl Placement {
    /// Whether `client` already floats here (within a pixel of rounding).
    pub fn matches(&self, client: &Client) -> bool {
        let near = |a: Option<&f64>, b: i32| a.is_some_and(|a| (a - f64::from(b)).abs() <= 1.0);
        client.floating
            && near(client.at.first(), self.x)
            && near(client.at.get(1), self.y)
            && near(client.size.first(), self.width)
            && near(client.size.get(1), self.height)
    }
}

/// The monitor the user is looking at: the one under the pointer (the tray
/// icon was just clicked; Omarchy's bar sends no click position), else the
/// focused one, else the first.
pub fn pick_monitor(monitors: &[Monitor], cursor: Option<(f64, f64)>) -> Option<&Monitor> {
    cursor
        .and_then(|(x, y)| monitors.iter().find(|m| m.contains(x, y)))
        .or_else(|| monitors.iter().find(|m| m.focused))
        .or_else(|| monitors.first())
}

/// Where the panel goes on `monitor`: right-aligned under the bar with
/// `gaps_out / 2` between them and to the right edge, like Omarchy's
/// panels (`KeyboardPanel`). `size` is the wanted size; it shrinks to fit a
/// small screen.
pub fn place(monitor: &Monitor, gaps_out: f64, size: (u32, u32)) -> Placement {
    let (w, h) = monitor.logical_size();
    let gap = (gaps_out / 2.0).round().max(0.0);
    let top = monitor.reserved(1) + gap;
    let right = monitor.reserved(2) + gap;
    let usable_w = w - monitor.reserved(0) - right - gap;
    let usable_h = h - top - monitor.reserved(3) - gap;
    let width = f64::from(size.0).min(usable_w).max(1.0).round();
    let height = f64::from(size.1).min(usable_h).max(1.0).round();
    Placement {
        x: (monitor.x + w - right - width).round() as i32,
        y: (monitor.y + top).round() as i32,
        width: width as i32,
        height: height as i32,
        top: top as i32,
        right: right as i32,
    }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// Escape `s` for a regex (Hyprland matches with RE2, whole string).
pub fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `s` as a Lua double-quoted string literal.
pub fn lua_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Lua that (re)registers the popup rule: our window floats at `plan`'s
/// size, `plan.top` below the monitor's top and `plan.right` from its right
/// edge (`move` in a rule is monitor-relative). The previous rule is
/// disabled first: Hyprland has no rule removal, and re-registering a named
/// rule appends effects instead of replacing them.
pub fn popup_rule_lua(title: &str, class: Option<&str>, plan: &Placement) -> String {
    let mut matcher = format!(
        "title = {}",
        lua_string(&format!("^{}$", regex_escape(title)))
    );
    if let Some(class) = class {
        matcher.push_str(&format!(
            ", class = {}",
            lua_string(&format!("^{}$", regex_escape(class)))
        ));
    }
    format!(
        "if {r} then {r}:set_enabled(false) end; {r} = hl.window_rule({{ match = {{ {matcher} }}, \
         float = true, size = {{ {w}, {h} }}, move = {{ \"(monitor_w-window_w-{right})\", {top} }} }})",
        r = LUA_POPUP_RULE,
        w = plan.width,
        h = plan.height,
        right = plan.right,
        top = plan.top,
    )
}

/// Lua that turns on the "hover does not focus other windows" rule: every
/// window except ours gets `no_follow_mouse` while the popup is open, so
/// only a click (or a keybinding) takes the focus away. Created once per
/// config load; the handle expires when a reload wipes the rules.
pub fn nohover_on_lua(title: &str) -> String {
    format!(
        "if {r} == nil or {r}:is_enabled() == nil then {r} = hl.window_rule({{ enabled = false, \
         match = {{ title = {m} }}, no_follow_mouse = true }}) end; {r}:set_enabled(true)",
        r = LUA_NOHOVER_RULE,
        m = lua_string(&format!("negative:^{}$", regex_escape(title))),
    )
}

/// Lua that turns the hover rule off again.
pub fn nohover_off_lua() -> String {
    format!(
        "if {r} then {r}:set_enabled(false) end",
        r = LUA_NOHOVER_RULE
    )
}

/// Dispatches that float, size and place the window at `address` (global
/// coordinates), as Lua dispatchers or the legacy (hyprlang) ones.
pub fn place_dispatches(lua: bool, address: &str, plan: &Placement) -> Vec<String> {
    let (x, y, w, h) = (plan.x, plan.y, plan.width, plan.height);
    if lua {
        let win = lua_string(&format!("address:{address}"));
        vec![
            format!("dispatch hl.dsp.window.float({{ window = {win}, action = \"enable\" }})"),
            format!("dispatch hl.dsp.window.resize({{ window = {win}, x = {w}, y = {h} }})"),
            format!("dispatch hl.dsp.window.move({{ window = {win}, x = {x}, y = {y} }})"),
        ]
    } else {
        vec![
            format!("dispatch setfloating address:{address}"),
            format!("dispatch resizewindowpixel exact {w} {h},address:{address}"),
            format!("dispatch movewindowpixel exact {x} {y},address:{address}"),
        ]
    }
}

/// What an `eval` reply says.
#[derive(Debug, PartialEq, Eq)]
pub enum EvalReply {
    Ok,
    /// No Lua API: a hyprlang config (`eval is only supported with the lua
    /// config manager`) or a Hyprland without `eval` (`unknown request`).
    NoLua,
    Error(String),
}

pub fn classify_eval(reply: &str) -> EvalReply {
    let r = reply.trim();
    if r == "ok" || r.is_empty() {
        EvalReply::Ok
    } else if r.contains("only supported with the lua config manager") || r == "unknown request" {
        EvalReply::NoLua
    } else {
        EvalReply::Error(truncate(r))
    }
}

// ---------------------------------------------------------------------------
// Popup
// ---------------------------------------------------------------------------

/// Popup mode state, managed by Tauri as `Arc<Popup>`.
pub struct Popup {
    hypr: Option<Hyprland>,
    state: Mutex<PopupState>,
}

#[derive(Default)]
struct PopupState {
    /// Our window's class as Hyprland reports it, learned after a show.
    class: Option<String>,
    /// Whether this Hyprland has the Lua API; `None` until asked.
    lua: Option<bool>,
    /// The popup rule as last registered, to skip re-registering it.
    rule: Option<String>,
    /// When the popup last closed because it lost the focus.
    blurred_at: Option<Instant>,
}

impl Popup {
    /// Popup mode when running inside Hyprland, the ordinary window
    /// otherwise.
    pub fn detect() -> Self {
        let hypr = Hyprland::from_env();
        if let Some(h) = &hypr {
            tracing::info!(
                socket = %h.socket.display(),
                "Hyprland detected: the status window opens as a top-bar popup"
            );
        }
        Self::with(hypr)
    }

    pub fn with(hypr: Option<Hyprland>) -> Self {
        Self {
            hypr,
            state: Mutex::new(PopupState::default()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.hypr.is_some()
    }

    /// Once at startup: a fixed-size, undecorated window, which Hyprland
    /// floats on its own even if the socket calls fail. Also turns off a
    /// hover rule a previous run may have left on (Lua globals outlive us).
    pub fn prepare(self: &Arc<Self>, window: &WebviewWindow) {
        let Some(hypr) = self.hypr.clone() else {
            return;
        };
        let _ = window.set_decorations(false);
        fix_size(window, POPUP_SIZE.0, POPUP_SIZE.1);
        let this = Arc::clone(self);
        tauri::async_runtime::spawn_blocking(move || this.after_hide(&hypr));
    }

    /// Show the window (as the popup in popup mode) and focus it.
    pub fn show(self: &Arc<Self>, window: &WebviewWindow) {
        let Some(hypr) = self.hypr.clone() else {
            let _ = window.show();
            let _ = window.set_focus();
            return;
        };
        let this = Arc::clone(self);
        let window = window.clone();
        tauri::async_runtime::spawn(async move {
            let title = window.title().unwrap_or_default();
            let plan = {
                let (this, hypr, title) = (Arc::clone(&this), hypr.clone(), title.clone());
                tauri::async_runtime::spawn_blocking(move || this.before_show(&hypr, &title))
                    .await
                    .ok()
                    .flatten()
            };
            if let Some(p) = plan {
                fix_size(&window, p.width as u32, p.height as u32);
            }
            let _ = window.show();
            let _ = window.set_focus();
            if let Some(p) = plan {
                let pid = i64::from(std::process::id());
                let _ = tauri::async_runtime::spawn_blocking(move || {
                    this.after_show(&hypr, &p, &title, pid)
                })
                .await;
            }
        });
    }

    /// Hide the window; in popup mode also give hover focus back to the
    /// other windows.
    pub fn hide(self: &Arc<Self>, window: &WebviewWindow) {
        let _ = window.hide();
        if let Some(hypr) = self.hypr.clone() {
            let this = Arc::clone(self);
            tauri::async_runtime::spawn_blocking(move || this.after_hide(&hypr));
        }
    }

    /// Before quitting: turn the hover rule off (blocking).
    pub fn release(&self) {
        if let Some(hypr) = &self.hypr {
            self.after_hide(hypr);
        }
    }

    /// Left click on the tray icon: toggle the popup, or open the ordinary
    /// window.
    pub fn toggle(self: &Arc<Self>, window: &WebviewWindow) {
        if !self.enabled() {
            self.show(window);
            return;
        }
        if window.is_visible().unwrap_or(false) {
            tracing::debug!("tray click: closing the popup");
            self.hide(window);
            return;
        }
        let just_blurred = self
            .state
            .lock()
            .unwrap()
            .blurred_at
            .is_some_and(|t| t.elapsed() < BLUR_CLICK_WINDOW);
        if just_blurred {
            tracing::debug!("tray click right after a focus loss: leaving the popup closed");
        } else {
            self.show(window);
        }
    }

    /// Esc in the window: closes the popup; nothing for the ordinary window.
    pub fn dismiss(self: &Arc<Self>, window: &WebviewWindow) {
        if self.enabled() {
            tracing::debug!("Esc: closing the popup");
            self.hide(window);
        }
    }

    /// Window focus changed: in popup mode, close when another window took
    /// the focus.
    pub fn focus_changed(self: &Arc<Self>, window: &WebviewWindow, focused: bool) {
        let Some(hypr) = self.hypr.clone() else {
            return;
        };
        if focused {
            return;
        }
        let this = Arc::clone(self);
        let window = window.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(BLUR_SETTLE).await;
            if !window.is_visible().unwrap_or(false) || window.is_focused().unwrap_or(false) {
                return;
            }
            // GTK also reports the window unfocused while a dropdown of ours
            // is open; Hyprland still has our window active then.
            let pid = i64::from(std::process::id());
            let ours = tauri::async_runtime::spawn_blocking(move || our_window_active(&hypr, pid))
                .await
                .unwrap_or(false);
            if !ours {
                tracing::debug!("another window has the focus: closing the popup");
                this.state.lock().unwrap().blurred_at = Some(Instant::now());
                this.hide(&window);
            }
        });
    }

    /// Blocking: plan the placement and register the rules for the coming
    /// show. `None` when Hyprland could not be asked.
    fn before_show(&self, hypr: &Hyprland, title: &str) -> Option<Placement> {
        let monitors = match hypr.monitors() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "Hyprland monitors unavailable; popup not placed");
                return None;
            }
        };
        let cursor = hypr.cursor_pos().ok();
        let monitor = pick_monitor(&monitors, cursor)?;
        let gaps_out = hypr.gaps_out().unwrap_or(DEFAULT_GAPS_OUT);
        let plan = place(monitor, gaps_out, POPUP_SIZE);
        tracing::debug!(monitor = %monitor.name, ?plan, "popup placement");

        let (lua, class, last_rule) = {
            let st = self.state.lock().unwrap();
            (st.lua, st.class.clone(), st.rule.clone())
        };
        if lua == Some(false) {
            return Some(plan);
        }
        let rule = popup_rule_lua(title, class.as_deref(), &plan);
        let mut code = String::new();
        if last_rule.as_deref() != Some(rule.as_str()) {
            code.push_str(&rule);
            code.push_str("; ");
        }
        code.push_str(&nohover_on_lua(title));
        let reply = hypr.request(&format!("eval {code}"));
        let mut st = self.state.lock().unwrap();
        match reply.as_deref().map(classify_eval) {
            Ok(EvalReply::Ok) => {
                st.lua = Some(true);
                st.rule = Some(rule);
            }
            Ok(EvalReply::NoLua) => {
                tracing::info!("Hyprland without the Lua API: the popup is placed after it maps");
                st.lua = Some(false);
            }
            Ok(EvalReply::Error(msg)) => {
                tracing::warn!(reply = %msg, "Hyprland refused the popup rule");
                st.lua = Some(true);
                st.rule = None;
            }
            Err(e) => tracing::warn!(error = %e, "Hyprland eval failed"),
        }
        Some(plan)
    }

    /// Blocking, after the show: find our window, learn its class, and put
    /// it where `plan` says if the rule did not.
    fn after_show(&self, hypr: &Hyprland, plan: &Placement, title: &str, pid: i64) {
        let deadline = Instant::now() + MAP_TIMEOUT;
        let client = loop {
            match hypr.clients() {
                Ok(clients) => {
                    if let Some(c) = clients
                        .into_iter()
                        .find(|c| c.pid == pid && (title.is_empty() || c.title == title))
                    {
                        break c;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Hyprland clients unavailable");
                    return;
                }
            }
            if Instant::now() >= deadline {
                tracing::debug!("popup window not listed by Hyprland");
                return;
            }
            std::thread::sleep(MAP_POLL);
        };

        let lua = {
            let mut st = self.state.lock().unwrap();
            if !client.class.is_empty() && st.class.as_deref() != Some(client.class.as_str()) {
                tracing::info!(class = %client.class, title = %client.title, "Hyprland window class of the status window");
                st.class = Some(client.class.clone());
            }
            if !plan.matches(&client) {
                // The rule did not apply (no Lua API, or a config reload
                // wiped it): register it again next time.
                st.rule = None;
            }
            st.lua
        };
        if plan.matches(&client) {
            return;
        }
        tracing::debug!(at = ?client.at, size = ?client.size, floating = client.floating, "placing the popup by dispatch");
        // Unknown API: Lua first, the legacy dispatchers if that is refused.
        let tries: &[bool] = match lua {
            Some(true) => &[true],
            Some(false) => &[false],
            None => &[true, false],
        };
        for &lua in tries {
            let mut all_ok = true;
            for request in place_dispatches(lua, &client.address, plan) {
                match hypr.request(&request) {
                    Ok(r) if r.trim() == "ok" => {}
                    Ok(r) => {
                        all_ok = false;
                        tracing::debug!(%request, reply = %truncate(r.trim()), "dispatch refused");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Hyprland dispatch failed");
                        return;
                    }
                }
            }
            if all_ok {
                return;
            }
        }
    }

    /// Blocking: turn the hover rule off.
    fn after_hide(&self, hypr: &Hyprland) {
        if self.state.lock().unwrap().lua == Some(false) {
            return;
        }
        match hypr.request(&format!("eval {}", nohover_off_lua())) {
            Ok(reply) => {
                let lua = match classify_eval(&reply) {
                    EvalReply::Ok => true,
                    EvalReply::NoLua => false,
                    EvalReply::Error(msg) => {
                        tracing::warn!(reply = %msg, "Hyprland refused to drop the hover rule");
                        true
                    }
                };
                self.state.lock().unwrap().lua.get_or_insert(lua);
            }
            Err(e) => tracing::debug!(error = %e, "Hyprland eval failed"),
        }
    }
}

/// Pin the window to `width` x `height` with equal min and max sizes, which
/// Hyprland reads as a fixed-size window and floats. (GTK's own
/// non-resizable mode would size the window to its content instead.)
fn fix_size(window: &WebviewWindow, width: u32, height: u32) {
    let size = LogicalSize::new(width, height);
    let _ = window.set_min_size(Some(size));
    let _ = window.set_max_size(Some(size));
    let _ = window.set_size(size);
}

/// Whether Hyprland's active window belongs to process `pid`. A failed
/// query counts as "no": the focus event is trusted then.
fn our_window_active(hypr: &Hyprland, pid: i64) -> bool {
    match hypr.active_window() {
        Ok(Some(active)) => active.pid == pid,
        Ok(None) => false,
        Err(e) => {
            tracing::debug!(error = %e, "activewindow failed; trusting the focus event");
            false
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn monitor(json: &str) -> Monitor {
        serde_json::from_str(json).unwrap()
    }

    /// Omarchy-like laptop: 2880x1800 panel at scale 2, 26 px bar on top.
    const LAPTOP: &str = r#"{"id":0,"name":"eDP-1","width":2880,"height":1800,"refreshRate":60.0,
        "x":0,"y":0,"activeWorkspace":{"id":1,"name":"1"},"reserved":[0,26,0,0],
        "scale":2.00,"transform":0,"focused":true,"dpmsStatus":true}"#;

    fn laptop() -> Monitor {
        monitor(LAPTOP)
    }

    #[test]
    fn gaps_out_reply_forms() {
        // Lua config (Hyprland 0.55+): "css"; hyprlang: "custom"; first value.
        assert_eq!(
            parse_gaps_out(r#"{"option": "general:gaps_out", "css": "10 10 10 10", "set": true }"#),
            Some(10.0)
        );
        assert_eq!(
            parse_gaps_out(r#"{"option":"general:gaps_out","custom":"8 20 8 20","set":true}"#),
            Some(8.0)
        );
        assert_eq!(
            parse_gaps_out(r#"{"option":"x","int":7,"set":false}"#),
            Some(7.0)
        );
        assert_eq!(parse_gaps_out("no such option"), None);
        assert_eq!(parse_gaps_out(r#"{"css":"a b"}"#), None);
    }

    #[test]
    fn placement_is_right_aligned_under_the_bar() {
        // Logical 1440x900; gaps_out 10 -> 5 px under the bar and on the
        // right, as Omarchy's own panels sit.
        let p = place(&laptop(), 10.0, POPUP_SIZE);
        assert_eq!(
            p,
            Placement {
                x: 1440 - 5 - 420,
                y: 26 + 5,
                width: 420,
                height: 600,
                top: 31,
                right: 5
            }
        );
    }

    #[test]
    fn placement_respects_offsets_reserved_space_and_small_screens() {
        let m = monitor(
            r#"{"name":"HDMI-A-1","x":1440,"y":-200,"width":1366,"height":768,
                "scale":1,"transform":0,"reserved":[0,30,40,0]}"#,
        );
        let p = place(&m, 20.0, POPUP_SIZE);
        assert_eq!((p.x, p.y), (1440 + 1366 - 40 - 10 - 420, -200 + 30 + 10));
        assert_eq!((p.width, p.height, p.top, p.right), (420, 600, 40, 50));
        // A short screen shrinks the panel to fit between bar and bottom.
        let tiny = monitor(r#"{"x":0,"y":0,"width":800,"height":500,"reserved":[0,30,0,0]}"#);
        let p = place(&tiny, 20.0, POPUP_SIZE);
        assert_eq!((p.y, p.height), (40, 500 - 30 - 10 - 10));
        assert_eq!(p.x, 800 - 10 - 420);
    }

    #[test]
    fn rotated_and_scaled_monitors_use_logical_size() {
        let m = monitor(
            r#"{"x":0,"y":0,"width":1920,"height":1080,"scale":1,"transform":1,"reserved":[0,26,0,0]}"#,
        );
        assert_eq!(m.logical_size(), (1080.0, 1920.0));
        assert_eq!(place(&m, 10.0, POPUP_SIZE).x, 1080 - 5 - 420);
        let frac = monitor(r#"{"x":0,"y":0,"width":2560,"height":1600,"scale":1.6}"#);
        assert_eq!(frac.logical_size(), (1600.0, 1000.0));
    }

    #[test]
    fn monitor_under_the_pointer_wins_then_focused() {
        let a = monitor(r#"{"name":"A","x":0,"y":0,"width":1920,"height":1080,"focused":true}"#);
        let b = monitor(r#"{"name":"B","x":1920,"y":0,"width":2560,"height":1440}"#);
        let all = [a, b];
        assert_eq!(pick_monitor(&all, Some((2000.0, 10.0))).unwrap().name, "B");
        assert_eq!(pick_monitor(&all, Some((-5.0, 10.0))).unwrap().name, "A");
        assert_eq!(pick_monitor(&all, None).unwrap().name, "A");
        assert!(pick_monitor(&[], None).is_none());
    }

    #[test]
    fn placement_match_tolerates_rounding_and_needs_floating() {
        let p = place(&laptop(), 10.0, POPUP_SIZE);
        let client = |floating: bool, at: [f64; 2], size: [f64; 2]| Client {
            floating,
            at: at.to_vec(),
            size: size.to_vec(),
            ..Client::default()
        };
        assert!(p.matches(&client(true, [1015.0, 31.0], [420.0, 600.0])));
        assert!(p.matches(&client(true, [1016.0, 30.0], [420.0, 600.0])));
        assert!(!p.matches(&client(false, [1015.0, 31.0], [420.0, 600.0])));
        assert!(!p.matches(&client(true, [510.0, 100.0], [420.0, 600.0])));
        assert!(!p.matches(&Client::default()));
    }

    #[test]
    fn escaping() {
        assert_eq!(regex_escape("Friglet Status"), "Friglet Status");
        assert_eq!(regex_escape("a.b(c)"), r"a\.b\(c\)");
        assert_eq!(lua_string(r#"say "hi" \ bye"#), r#""say \"hi\" \\ bye""#);
    }

    #[test]
    fn rule_and_dispatch_text() {
        let p = place(&laptop(), 10.0, POPUP_SIZE);
        assert_eq!(
            popup_rule_lua("Friglet Status", None, &p),
            "if friglet_tray_popup_rule then friglet_tray_popup_rule:set_enabled(false) end; \
             friglet_tray_popup_rule = hl.window_rule({ match = { title = \"^Friglet Status$\" }, \
             float = true, size = { 420, 600 }, move = { \"(monitor_w-window_w-5)\", 31 } })"
        );
        assert!(
            popup_rule_lua("Friglet Status", Some("friglet-tray"), &p)
                .contains(r#"match = { title = "^Friglet Status$", class = "^friglet-tray$" }"#)
        );
        assert_eq!(
            nohover_on_lua("Friglet Status"),
            "if friglet_tray_nohover_rule == nil or friglet_tray_nohover_rule:is_enabled() == nil \
             then friglet_tray_nohover_rule = hl.window_rule({ enabled = false, match = { title = \
             \"negative:^Friglet Status$\" }, no_follow_mouse = true }) end; \
             friglet_tray_nohover_rule:set_enabled(true)"
        );
        assert_eq!(
            nohover_off_lua(),
            "if friglet_tray_nohover_rule then friglet_tray_nohover_rule:set_enabled(false) end"
        );
        assert_eq!(
            place_dispatches(true, "0x55aa", &p),
            [
                r#"dispatch hl.dsp.window.float({ window = "address:0x55aa", action = "enable" })"#,
                r#"dispatch hl.dsp.window.resize({ window = "address:0x55aa", x = 420, y = 600 })"#,
                r#"dispatch hl.dsp.window.move({ window = "address:0x55aa", x = 1015, y = 31 })"#,
            ]
        );
        assert_eq!(
            place_dispatches(false, "0x55aa", &p),
            [
                "dispatch setfloating address:0x55aa",
                "dispatch resizewindowpixel exact 420 600,address:0x55aa",
                "dispatch movewindowpixel exact 1015 31,address:0x55aa",
            ]
        );
    }

    #[test]
    fn eval_replies() {
        assert_eq!(classify_eval("ok"), EvalReply::Ok);
        assert_eq!(
            classify_eval("eval is only supported with the lua config manager"),
            EvalReply::NoLua
        );
        assert_eq!(classify_eval("unknown request"), EvalReply::NoLua);
        assert!(matches!(
            classify_eval("error: [string]:1: attempt to index a nil value"),
            EvalReply::Error(_)
        ));
    }

    #[test]
    fn socket_path_prefers_the_runtime_dir() {
        let dir = std::env::temp_dir().join(format!("friglet-hypr-path-{}", std::process::id()));
        assert_eq!(
            socket_path(Some(&dir), "sig"),
            dir.join("hypr/sig/.socket.sock")
        );
        assert_eq!(
            socket_path(None, "sig"),
            Path::new("/tmp/hypr/sig/.socket.sock")
        );
    }

    // -- fake Hyprland socket ---------------------------------------------

    type Reply = Box<dyn Fn(&str) -> String + Send + Sync>;

    /// A fake `.socket.sock`: one request per connection, read to EOF as
    /// Hyprland does, answered by `reply`; every request is recorded.
    struct FakeHyprland {
        hypr: Hyprland,
        log: Arc<Mutex<Vec<String>>>,
        _dir: PathBuf,
    }

    impl FakeHyprland {
        fn start(tag: &str, reply: Reply) -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "fh-{}-{}-{tag}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join(".socket.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let log = Arc::new(Mutex::new(Vec::new()));
            let seen = Arc::clone(&log);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { break };
                    let mut req = String::new();
                    if stream.read_to_string(&mut req).is_err() {
                        continue;
                    }
                    let answer = reply(&req);
                    seen.lock().unwrap().push(req);
                    let _ = stream.write_all(answer.as_bytes());
                }
            });
            Self {
                hypr: Hyprland::new(path),
                log,
                _dir: dir,
            }
        }

        fn requests(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }

    const PID: i64 = 4242;

    fn client_json(at: [i32; 2], size: [i32; 2], floating: bool) -> String {
        format!(
            r#"[{{"address":"0x5612a0","mapped":true,"hidden":false,"at":[{},{}],"size":[{},{}],
                "workspace":{{"id":1,"name":"1"}},"floating":{floating},"monitor":0,
                "class":"friglet-tray","title":"Friglet Status","initialClass":"friglet-tray",
                "initialTitle":"Friglet Status","pid":{PID}}},
               {{"address":"0x77","floating":false,"class":"kitty","title":"zsh","pid":1,
                "at":[5,36],"size":[1000,800]}}]"#,
            at[0], at[1], size[0], size[1]
        )
    }

    /// A Hyprland 0.55+ with the Lua API that applies our rule on map.
    fn lua_hyprland(clients: String) -> Reply {
        Box::new(move |req| match req {
            "j/monitors" => format!("[{LAPTOP}]"),
            "j/cursorpos" => "{\n    \"x\": 1300,\n    \"y\": 12\n}\n".into(),
            "j/getoption general:gaps_out" => {
                r#"{"option": "general:gaps_out", "css": "10 10 10 10", "set": true }"#.into()
            }
            "j/clients" => clients.clone(),
            r if r.starts_with("eval ") || r.starts_with("dispatch hl.") => "ok".into(),
            _ => "unknown request".into(),
        })
    }

    #[test]
    fn lua_hyprland_gets_rules_before_the_show_and_nothing_after() {
        let fake = FakeHyprland::start(
            "lua",
            lua_hyprland(client_json([1015, 31], [420, 600], true)),
        );
        let popup = Popup::with(Some(fake.hypr.clone()));

        let plan = popup.before_show(&fake.hypr, "Friglet Status").unwrap();
        assert_eq!(
            (plan.x, plan.y, plan.width, plan.height),
            (1015, 31, 420, 600)
        );
        popup.after_show(&fake.hypr, &plan, "Friglet Status", PID);
        popup.after_hide(&fake.hypr);

        let reqs = fake.requests();
        assert_eq!(
            &reqs[..3],
            ["j/monitors", "j/cursorpos", "j/getoption general:gaps_out"]
        );
        assert_eq!(
            reqs[3],
            format!(
                "eval {}; {}",
                popup_rule_lua("Friglet Status", None, &plan),
                nohover_on_lua("Friglet Status")
            )
        );
        // Already in place: no dispatch; then the hover rule goes off.
        assert_eq!(
            reqs[4..],
            [
                "j/clients".to_string(),
                format!("eval {}", nohover_off_lua())
            ]
        );
        let st = popup.state.lock().unwrap();
        assert_eq!(st.lua, Some(true));
        assert_eq!(st.class.as_deref(), Some("friglet-tray"));
    }

    #[test]
    fn learned_class_joins_the_rule_and_an_unchanged_rule_is_not_resent() {
        let fake = FakeHyprland::start(
            "relearn",
            lua_hyprland(client_json([1015, 31], [420, 600], true)),
        );
        let popup = Popup::with(Some(fake.hypr.clone()));
        let title = "Friglet Status";
        for _ in 0..3 {
            let plan = popup.before_show(&fake.hypr, title).unwrap();
            popup.after_show(&fake.hypr, &plan, title, PID);
        }
        let evals: Vec<String> = fake
            .requests()
            .into_iter()
            .filter(|r| r.starts_with("eval "))
            .collect();
        let plan = place(&laptop(), 10.0, POPUP_SIZE);
        assert_eq!(evals.len(), 3);
        // 1st: title only; 2nd: class learned -> rule re-registered with it;
        // 3rd: unchanged rule, only the hover rule.
        assert!(evals[0].starts_with(&format!("eval {}", popup_rule_lua(title, None, &plan))));
        assert!(evals[1].starts_with(&format!(
            "eval {}",
            popup_rule_lua(title, Some("friglet-tray"), &plan)
        )));
        assert_eq!(evals[2], format!("eval {}", nohover_on_lua(title)));
    }

    #[test]
    fn a_misplaced_window_is_moved_with_lua_dispatchers() {
        // The rule did not apply (say a config reload wiped it): the window
        // tiled at the left.
        let fake = FakeHyprland::start(
            "misplaced",
            lua_hyprland(client_json([5, 36], [710, 858], false)),
        );
        let popup = Popup::with(Some(fake.hypr.clone()));
        let plan = popup.before_show(&fake.hypr, "Friglet Status").unwrap();
        popup.after_show(&fake.hypr, &plan, "Friglet Status", PID);
        let reqs = fake.requests();
        let tail = &reqs[reqs.len() - 3..];
        assert_eq!(tail, place_dispatches(true, "0x5612a0", &plan));
        // ...and the rule is sent again on the next show.
        assert!(popup.state.lock().unwrap().rule.is_none());
    }

    #[test]
    fn hyprland_without_lua_gets_legacy_dispatchers_only() {
        let clients = client_json([510, 150], [420, 600], true);
        let fake = FakeHyprland::start(
            "legacy",
            Box::new(move |req| match req {
                "j/monitors" => format!("[{LAPTOP}]"),
                "j/cursorpos" => r#"{"x": 1300, "y": 12}"#.into(),
                "j/getoption general:gaps_out" => {
                    r#"{"option":"general:gaps_out","custom":"10 10 10 10","set":true}"#.into()
                }
                "j/clients" => clients.clone(),
                r if r.starts_with("eval ") => {
                    "eval is only supported with the lua config manager".into()
                }
                r if r.starts_with("dispatch hl.") => "error: 3 [string]:1: syntax error".into(),
                r if r.starts_with("dispatch ") => "ok".into(),
                _ => "unknown request".into(),
            }),
        );
        let popup = Popup::with(Some(fake.hypr.clone()));
        let plan = popup.before_show(&fake.hypr, "Friglet Status").unwrap();
        popup.after_show(&fake.hypr, &plan, "Friglet Status", PID);
        // A second show skips eval entirely.
        let plan = popup.before_show(&fake.hypr, "Friglet Status").unwrap();
        popup.after_hide(&fake.hypr);

        let reqs = fake.requests();
        assert_eq!(reqs.iter().filter(|r| r.starts_with("eval ")).count(), 1);
        assert!(!reqs.iter().any(|r| r.starts_with("dispatch hl.")));
        let legacy: Vec<&String> = reqs.iter().filter(|r| r.starts_with("dispatch ")).collect();
        assert_eq!(
            legacy,
            place_dispatches(false, "0x5612a0", &plan)
                .iter()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn active_window_check_tells_ours_from_others_and_nothing() {
        let answer = Arc::new(Mutex::new(String::new()));
        let a = Arc::clone(&answer);
        let fake = FakeHyprland::start("active", Box::new(move |_| a.lock().unwrap().clone()));
        *answer.lock().unwrap() =
            format!(r#"{{"address":"0x1","pid":{PID},"class":"friglet-tray"}}"#);
        assert!(our_window_active(&fake.hypr, PID));
        *answer.lock().unwrap() = r#"{"address":"0x2","pid":1,"class":"kitty"}"#.into();
        assert!(!our_window_active(&fake.hypr, PID));
        *answer.lock().unwrap() = "{}".into();
        assert!(!our_window_active(&fake.hypr, PID));
        assert_eq!(fake.requests(), ["j/activewindow"; 3]);
    }

    #[test]
    fn no_socket_means_no_plan_and_no_panic() {
        let hypr = Hyprland::new(std::env::temp_dir().join("friglet-no-such-hypr.sock"));
        let popup = Popup::with(Some(hypr.clone()));
        assert!(popup.before_show(&hypr, "Friglet Status").is_none());
        popup.after_hide(&hypr);
        assert!(!our_window_active(&hypr, PID));
    }
}
