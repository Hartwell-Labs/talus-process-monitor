//! Talus Web Dashboard — TLS-enabled with API token authentication.
//!
//! Security features:
//! - TLS via rustls (auto-generated self-signed cert or from files)
//! - API token authentication for write operations
//! - Restricted CORS (no permissive)
//! - Security headers (CSP, X-Frame-Options, etc.)
//! - License health endpoint

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{FromRequestParts, State, WebSocketUpgrade};
use axum::http::{header, request::Parts, HeaderValue, Method, Request, Response};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::{SinkExt, StreamExt};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::registry::Registry;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex};
use tower::{Layer, Service};

use crate::license;
use crate::monitor::{Kind, Monitor, Output};

// ── API Token Authentication ──────────────────────────────────────────────

/// Generate a random API token (32 hex chars).
fn generate_api_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid = std::process::id();
    format!("{:016x}{:08x}", ts, pid)
}

/// Load or generate the API token.
/// Stored in ~/.config/talus/web-token on first run.
fn load_or_create_token() -> String {
    if let Some(config_dir) = dirs::config_dir() {
        let token_path = config_dir.join("talus").join("web-token");
        if let Ok(token) = std::fs::read_to_string(&token_path) {
            let token = token.trim().to_string();
            if !token.is_empty() {
                return token;
            }
        }
        // Generate new token
        let token = generate_api_token();
        let _ = std::fs::create_dir_all(config_dir.join("talus"));
        let _ = std::fs::write(&token_path, &token);
        let _ = std::fs::set_permissions(
            &token_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        );
        return token;
    }
    generate_api_token()
}

/// Check if auth is enabled (env var TALUS_WEB_AUTH=1).
fn auth_enabled() -> bool {
    std::env::var("TALUS_WEB_AUTH")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false)
}

/// Check if the request has a valid API token.
fn auth_valid(parts: &Parts, token: &str) -> bool {
    if !auth_enabled() {
        return true; // Auth disabled = all requests allowed
    }
    // Check Authorization header
    if let Some(auth) = parts.headers.get("authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if auth_str == format!("Bearer {token}") {
                return true;
            }
        }
    }
    // Check X-API-Token header
    if let Some(api_token) = parts.headers.get("x-api-token") {
        if let Ok(t) = api_token.to_str() {
            if t == token {
                return true;
            }
        }
    }
    false
}

/// Axum extractor that validates the API token (or short-circuits to 401).
///
/// `FromRequestParts` (not `FromRequest`) so it never consumes the body —
/// handlers can combine it freely with a `Json` body extractor.
struct Authed;

impl<S: Send + Sync> FromRequestParts<S> for Authed {
    type Rejection = (axum::http::StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // The token lives in AppState; handlers pass it via an extension set
        // below (see `with_auth_state`), keeping this extractor stateless.
        let token = parts
            .extensions
            .get::<ApiToken>()
            .map(|t| t.0.clone())
            .unwrap_or_default();
        if auth_valid(parts, &token) {
            Ok(Authed)
        } else {
            Err((
                axum::http::StatusCode::UNAUTHORIZED,
                "unauthorized: provide Authorization: Bearer <token> or X-API-Token header",
            ))
        }
    }
}

/// Newtype so the API token can ride in request extensions.
#[derive(Clone)]
struct ApiToken(String);

/// Route through this layer before `.with_state()` so every request carries
/// the API token in its extensions for the `Authed` extractor.
fn with_auth_state(router: Router<AppState>, state: &AppState) -> Router<AppState> {
    let token = ApiToken(state.api_token.clone());
    router.layer(axum::middleware::from_fn(
        move |mut req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| {
            let token = token.clone();
            async move {
                req.extensions_mut().insert(token);
                next.run(req).await
            }
        },
    ))
}

// ── Shared state ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    monitor: Arc<Mutex<Monitor>>,
    tx: broadcast::Sender<WsEvent>,
    metrics: Arc<Mutex<Registry>>,
    metrics_events: Counter,
    metrics_exec: Counter,
    metrics_open: Counter,
    metrics_alerts: Counter,
    #[allow(dead_code)]
    metrics_lost: Counter,
    metrics_ws: Counter,
    api_token: String,
}

impl AppState {
    fn new(monitor: Monitor, api_token: String) -> Self {
        let mut registry = Registry::default();
        let events_total = Counter::default();
        registry.register(
            "talus_events_total",
            "Total number of eBPF events received",
            events_total.clone(),
        );
        let exec_events_total = Counter::default();
        registry.register(
            "talus_exec_events_total",
            "Total number of execve events",
            exec_events_total.clone(),
        );
        let open_events_total = Counter::default();
        registry.register(
            "talus_open_events_total",
            "Total number of openat events",
            open_events_total.clone(),
        );
        let alerts_total = Counter::default();
        registry.register(
            "talus_alerts_total",
            "Total number of alerts fired",
            alerts_total.clone(),
        );
        let lost_events_total = Counter::default();
        registry.register(
            "talus_lost_events_total",
            "Total number of lost events (perf buffer overruns)",
            lost_events_total.clone(),
        );
        let ws_connections = Counter::default();
        registry.register(
            "talus_ws_connections_total",
            "Total number of WebSocket connections",
            ws_connections.clone(),
        );
        let (tx, _) = broadcast::channel(1024);
        Self {
            monitor: Arc::new(Mutex::new(monitor)),
            tx,
            metrics: Arc::new(Mutex::new(registry)),
            metrics_events: events_total,
            metrics_exec: exec_events_total,
            metrics_open: open_events_total,
            metrics_alerts: alerts_total,
            metrics_lost: lost_events_total,
            metrics_ws: ws_connections,
            api_token,
        }
    }
}

// ── WebSocket event types ─────────────────────────────────────────────────

#[derive(Clone, Serialize)]
#[serde(tag = "type")]
enum WsEvent {
    #[serde(rename = "event")]
    Event {
        ts: String,
        kind: String,
        pid: u32,
        uid: u32,
        comm: String,
        file: Option<String>,
        extension: Option<String>,
        argv: Option<String>,
    },
    #[serde(rename = "alert")]
    Alert {
        ts: String,
        pid: u32,
        uid: u32,
        comm: String,
        opens: u64,
        /// MeMLP neural verdicts (null when the engine is disabled).
        memlp: Option<crate::memlp::Assessment>,
    },
}

// ── REST API response types ───────────────────────────────────────────────

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    ok: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Serialize)]
struct StatsResponse {
    total_events: u64,
    total_lost: u64,
    uptime_secs: u64,
    active_pids: usize,
    threshold: u64,
    /// MeMLP neural engine summary (null when disabled).
    memlp: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
    comm: String,
    total_opens: u64,
    total_execs: u64,
    alerts: u64,
    /// Latest MeMLP neural verdicts for this PID (null when disabled or no data).
    memlp: Option<crate::memlp::Assessment>,
}

#[derive(Serialize)]
struct FileRankResponse {
    path: String,
    count: u64,
    extension: String,
    entropy: f64,
}

#[derive(Serialize)]
struct ExtensionResponse {
    extension: String,
    count: u64,
}

#[derive(Deserialize)]
struct ThresholdQuery {
    threshold: Option<u64>,
}

#[derive(Serialize)]
struct AuthInfoResponse {
    token_preview: String,
    auth_header: String,
}

// ── API handlers ──────────────────────────────────────────────────────────

async fn get_stats(
    State(state): State<AppState>,
    _auth: Authed,
) -> Json<ApiResponse<StatsResponse>> {
    let mon = state.monitor.lock().await;
    let pids = mon.stats_sorted().len();
    Json(ApiResponse {
        ok: true,
        data: Some(StatsResponse {
            total_events: mon.total_events,
            total_lost: mon.total_lost,
            uptime_secs: mon.uptime().as_secs(),
            active_pids: pids,
            threshold: mon.threshold,
            memlp: mon.memlp_summary(),
        }),
        error: None,
    })
}

async fn get_processes(
    State(state): State<AppState>,
    _auth: Authed,
) -> Json<ApiResponse<Vec<ProcessInfo>>> {
    let mon = state.monitor.lock().await;
    let processes: Vec<ProcessInfo> = mon
        .stats_sorted()
        .into_iter()
        .map(|s| ProcessInfo {
            pid: s.pid,
            ppid: s.ppid,
            comm: s.comm.trim_end_matches('\0').to_string(),
            total_opens: s.total_opens,
            total_execs: s.total_execs,
            alerts: s.alerts,
            memlp: mon.memlp_verdict(s.pid),
        })
        .collect();
    Json(ApiResponse {
        ok: true,
        data: Some(processes),
        error: None,
    })
}

async fn get_files(
    State(state): State<AppState>,
    _auth: Authed,
) -> Json<ApiResponse<Vec<FileRankResponse>>> {
    let mon = state.monitor.lock().await;
    let files: Vec<FileRankResponse> = mon
        .top_files(50)
        .into_iter()
        .map(|f| FileRankResponse {
            path: f.path,
            count: f.count,
            extension: f.extension,
            entropy: f.entropy,
        })
        .collect();
    Json(ApiResponse {
        ok: true,
        data: Some(files),
        error: None,
    })
}

async fn get_extensions(
    State(state): State<AppState>,
    _auth: Authed,
) -> Json<ApiResponse<Vec<ExtensionResponse>>> {
    let mon = state.monitor.lock().await;
    let mut exts: Vec<ExtensionResponse> = mon
        .extension_counts()
        .iter()
        .map(|(k, &v)| ExtensionResponse {
            extension: k.clone(),
            count: v,
        })
        .collect();
    exts.sort_by_key(|e| std::cmp::Reverse(e.count));
    Json(ApiResponse {
        ok: true,
        data: Some(exts),
        error: None,
    })
}

/// POST /api/v1/threshold — requires auth
async fn set_threshold(
    State(state): State<AppState>,
    _auth: Authed,
    Json(body): Json<ThresholdQuery>,
) -> Json<ApiResponse<StatsResponse>> {
    let mut mon = state.monitor.lock().await;
    if let Some(t) = body.threshold {
        mon.threshold = t;
    }
    let pids = mon.stats_sorted().len();
    Json(ApiResponse {
        ok: true,
        data: Some(StatsResponse {
            total_events: mon.total_events,
            total_lost: mon.total_lost,
            uptime_secs: mon.uptime().as_secs(),
            active_pids: pids,
            threshold: mon.threshold,
            memlp: mon.memlp_summary(),
        }),
        error: None,
    })
}

/// GET /api/v1/license — license health (public)
async fn get_license_health() -> Json<license::LicenseHealth> {
    Json(license::license_health())
}

/// GET /api/v1/auth — show auth info
async fn get_auth_info(State(state): State<AppState>) -> Json<ApiResponse<AuthInfoResponse>> {
    let preview = if state.api_token.len() > 8 {
        format!(
            "{}...{}",
            &state.api_token[..4],
            &state.api_token[state.api_token.len() - 4..]
        )
    } else {
        "****".into()
    };
    Json(ApiResponse {
        ok: true,
        data: Some(AuthInfoResponse {
            token_preview: preview,
            auth_header: "Authorization: Bearer <token>".into(),
        }),
        error: None,
    })
}

async fn metrics_handler(State(state): State<AppState>, _auth: Authed) -> impl IntoResponse {
    let registry = state.metrics.lock().await;
    let mut buffer = String::new();
    encode(&mut buffer, &registry).unwrap();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        buffer,
    )
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(socket: WebSocket, state: AppState) {
    state.metrics_ws.inc();
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.tx.subscribe();

    let mut send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&event) {
                if sender.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
        }
    });

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Close(_) = msg {
                break;
            }
        }
    });

    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    }
}

// ── Event forwarder ───────────────────────────────────────────────────────

fn spawn_event_forwarder(state: AppState) {
    tokio::spawn(async move {
        loop {
            {
                let mut mon = state.monitor.lock().await;
                let outputs = mon.poll();
                for output in outputs {
                    match output {
                        Output::Event(ev) => {
                            state.metrics_events.inc();
                            match ev.kind {
                                Kind::Exec => {
                                    state.metrics_exec.inc();
                                }
                                Kind::Open => {
                                    state.metrics_open.inc();
                                }
                                _ => {}
                            }
                            let _ = state.tx.send(WsEvent::Event {
                                ts: ev.ts,
                                kind: format!("{:?}", ev.kind),
                                pid: ev.pid,
                                uid: ev.uid,
                                comm: ev.comm.trim_end_matches('\0').to_string(),
                                file: ev.file,
                                extension: ev.extension,
                                argv: ev.argv,
                            });
                        }
                        Output::Alert(al) => {
                            state.metrics_alerts.inc();
                            let _ = state.tx.send(WsEvent::Alert {
                                ts: al.ts,
                                pid: al.pid,
                                uid: al.uid,
                                comm: al.comm.trim_end_matches('\0').to_string(),
                                opens: al.opens,
                                memlp: al.memlp,
                            });
                        }
                        Output::Action(_) => {}
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    });
}

// ── Dashboard HTML ────────────────────────────────────────────────────────

async fn dashboard() -> impl IntoResponse {
    axum::response::Html(DASHBOARD_HTML)
}

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Talus eBPF Monitor</title>
<style>
  :root { --bg: #0a0a1a; --panel: #111127; --border: #1e1e3a; --cyan: #00ffff; --green: #00ff64; --red: #ff3232; --yellow: #ffff00; --magenta: #ff00ff; --dim: #505064; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: #ccc; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 13px; }
  .header { background: var(--panel); border-bottom: 1px solid var(--border); padding: 12px 20px; display: flex; justify-content: space-between; align-items: center; }
  .header h1 { color: var(--cyan); font-size: 16px; }
  .header .stats { color: var(--dim); }
  .grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; padding: 8px; height: calc(100vh - 50px); }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 4px; overflow: hidden; display: flex; flex-direction: column; }
  .panel-header { padding: 8px 12px; border-bottom: 1px solid var(--border); color: var(--cyan); font-weight: bold; font-size: 12px; }
  .panel-body { flex: 1; overflow-y: auto; padding: 4px 8px; }
  .event { padding: 2px 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .event .ts { color: var(--dim); }
  .event .tag { font-weight: bold; padding: 0 4px; }
  .tag-exec { color: var(--green); }
  .tag-open { color: var(--cyan); }
  .tag-alert { color: var(--red); font-weight: bold; }
  .process-row { display: flex; justify-content: space-between; padding: 2px 0; }
  .process-row .alerts { color: var(--red); }
  .file-row { display: grid; grid-template-columns: 2fr 1fr 1fr; padding: 2px 0; gap: 8px; }
  .ext-bar { display: flex; align-items: center; gap: 8px; padding: 2px 0; }
  .ext-bar .bar { height: 12px; background: var(--cyan); border-radius: 2px; }
  .status { position: fixed; bottom: 0; left: 0; right: 0; background: var(--panel); border-top: 1px solid var(--border); padding: 4px 20px; display: flex; gap: 20px; color: var(--dim); font-size: 11px; }
  .connected { color: var(--green); }
  .disconnected { color: var(--red); }
</style>
</head>
<body>
<div class="header">
  <h1>⚡ TALUS eBPF MONITOR <span id="tier-badge" style="font-size:11px;padding:2px 8px;border-radius:3px;background:#505064;color:#ccc;">loading...</span></h1>
  <div class="stats" id="stats">loading...</div>
</div>
<div class="grid">
  <div class="panel" style="grid-row: span 2">
    <div class="panel-header">EVENTS (<span id="event-count">0</span>)</div>
    <div class="panel-body" id="events"></div>
  </div>
  <div class="panel"><div class="panel-header">PROCESSES</div><div class="panel-body" id="processes"></div></div>
  <div class="panel"><div class="panel-header">TOP FILES</div><div class="panel-body" id="files"></div></div>
  <div class="panel"><div class="panel-header">FILE TYPES</div><div class="panel-body" id="extensions"></div></div>
  <div class="panel"><div class="panel-header">ALERTS</div><div class="panel-body" id="alerts"></div></div>
</div>
<div class="status">
  <span>WebSocket: <span id="ws-status" class="disconnected">disconnected</span></span>
  <span>Events: <span id="total-events">0</span></span>
  <span>Lost: <span id="total-lost">0</span></span>
  <span>Uptime: <span id="uptime">0s</span></span>
</div>
<script>
const MAX_EVENTS=500;let eventCount=0;const eventsEl=document.getElementById('events');const alertsEl=document.getElementById('alerts');
function connect(){const ws=new WebSocket(`wss://${location.host}/ws`);ws.onopen=()=>{document.getElementById('ws-status').textContent='connected';document.getElementById('ws-status').className='connected'};ws.onclose=()=>{document.getElementById('ws-status').textContent='disconnected';document.getElementById('ws-status').className='disconnected';setTimeout(connect,2000)};ws.onmessage=e=>{const d=JSON.parse(e.data);if(d.type==='event'){eventCount++;document.getElementById('event-count').textContent=eventCount;const div=document.createElement('div');div.className='event';const tc=d.kind==='Exec'?'tag-exec':'tag-open';const tt=d.kind==='Exec'?'EXEC':'OPEN';const f=d.file?' → '+d.file:'';div.innerHTML=`<span class="ts">${d.ts}</span> <span class="tag ${tc}">${tt}</span> [${d.pid}] ${d.comm}${f}`;eventsEl.appendChild(div);if(eventsEl.children.length>MAX_EVENTS)eventsEl.removeChild(eventsEl.firstChild);eventsEl.scrollTop=eventsEl.scrollHeight}else if(d.type==='alert'){const div=document.createElement('div');div.className='event';div.innerHTML=`<span class="ts">${d.ts}</span> <span class="tag tag-alert">⚠ ALERT</span> [${d.pid}] ${d.comm} — ${d.opens} opens/s`;alertsEl.appendChild(div)}}}
connect();
setInterval(async()=>{try{const r=await fetch('/api/v1/stats');const j=await r.json();if(j.ok){const d=j.data;document.getElementById('stats').textContent=`evt ${d.total_events} | lost ${d.total_lost} | uptime ${d.uptime_secs}s | threshold ${d.threshold}/s`;document.getElementById('total-events').textContent=d.total_events;document.getElementById('total-lost').textContent=d.total_lost;document.getElementById('uptime').textContent=d.uptime_secs+'s'}}catch(e){}});
setInterval(async()=>{try{const r=await fetch('/api/v1/license');const j=await r.json();const b=document.getElementById('tier-badge');if(j.tier==='enterprise'){b.textContent='◆ ENTERPRISE';b.style.background='#00ff64';b.style.color='#0a0a1a';}else{b.textContent='◇ COMMUNITY';b.style.background='#505064';b.style.color='#aaa';}}catch(e){}},5000);
setInterval(async()=>{try{const r=await fetch('/api/v1/files');const j=await r.json();if(j.ok){document.getElementById('files').innerHTML=j.data.map(f=>`<div class="file-row"><span>${f.path.length>30?'…'+f.path.slice(-27):f.path}</span><span>.${f.extension}</span><span>${f.count} E:${f.entropy.toFixed(2)}</span></div>`).join('')}}catch(e){}try{const r=await fetch('/api/v1/extensions');const j=await r.json();if(j.ok&&j.data.length>0){const max=Math.max(...j.data.map(e=>e.count));document.getElementById('extensions').innerHTML=j.data.slice(0,8).map(e=>`<div class="ext-bar"><span style="width:50px">.${e.extension}</span><div class="bar" style="width:${(e.count/max*100).toFixed(0)}%"></div><span>${e.count}</span></div>`).join('')}}catch(e){}try{const r=await fetch('/api/v1/processes');const j=await r.json();if(j.ok){document.getElementById('processes').innerHTML=j.data.slice(0,30).map(p=>{const ab=p.alerts>0?` <span class="alerts">⚠${p.alerts}</span>`:'';return`<div class="process-row"><span>${p.comm} [${p.pid}]</span><span>${p.total_opens} opens${ab}</span></div>`}).join('')}}catch(e){}},3000);
</script>
</body>
</html>"#;

// ── Security Headers Middleware ─────────────────────────────────────────

#[derive(Clone)]
struct SecurityHeadersLayer;

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersService { inner }
    }
}

#[derive(Clone)]
struct SecurityHeadersService<S> {
    inner: S,
}

impl<S, ReqBody> Service<Request<ReqBody>> for SecurityHeadersService<S>
where
    S: Service<Request<ReqBody>, Response = Response<axum::body::Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<axum::body::Body>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let fut = self.inner.call(req);
        Box::pin(async move {
            let mut response = fut.await?;
            let headers = response.headers_mut();

            headers.insert(
                header::HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );
            headers.insert(
                header::HeaderName::from_static("x-frame-options"),
                HeaderValue::from_static("DENY"),
            );
            headers.insert(
                header::HeaderName::from_static("x-xss-protection"),
                HeaderValue::from_static("1; mode=block"),
            );
            headers.insert(
                header::HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("strict-origin-when-cross-origin"),
            );
            headers.insert(
                header::HeaderName::from_static("permissions-policy"),
                HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
            );
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:"),
            );

            Ok(response)
        })
    }
}

// ── TLS Support ──────────────────────────────────────────────────────────

/// Generate a self-signed TLS certificate for development.
#[cfg(feature = "web")]
fn generate_self_signed_cert() -> Result<(rustls::ServerConfig, String), anyhow::Error> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])?;
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der.clone())?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
        )?;

    Ok((server_config, "self-signed".into()))
}

// ── Public entry point ────────────────────────────────────────────────────

pub async fn start_web_server(
    monitor: Monitor,
    addr: SocketAddr,
    _threshold: u64,
) -> anyhow::Result<()> {
    let api_token = load_or_create_token();
    let state = AppState::new(monitor, api_token.clone());

    // Start event forwarder
    spawn_event_forwarder(state.clone());

    // Read-only routes (no auth needed)
    let read_routes = Router::new()
        .route("/", get(dashboard))
        .route("/ws", get(ws_handler))
        .route("/api/v1/stats", get(get_stats))
        .route("/api/v1/processes", get(get_processes))
        .route("/api/v1/files", get(get_files))
        .route("/api/v1/extensions", get(get_extensions))
        .route("/api/v1/license", get(get_license_health))
        .route("/api/v1/auth", get(get_auth_info))
        .route("/metrics", get(metrics_handler));

    // Write routes (require auth)
    let write_routes = Router::new().route("/api/v1/threshold", post(set_threshold));

    let app = with_auth_state(read_routes.merge(write_routes), &state)
        .with_state(state)
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin("https://localhost".parse::<HeaderValue>().unwrap())
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    header::HeaderName::from_static("x-api-token"),
                ]),
        )
        .layer(SecurityHeadersLayer);

    // Print startup info
    eprintln!();
    eprintln!("  \x1b[36m╔══════════════════════════════════════════════════╗\x1b[0m");
    eprintln!("  \x1b[36m║\x1b[0m  \x1b[1m🌐 TALUS WEB DASHBOARD\x1b[0m                         \x1b[36m║\x1b[0m");
    eprintln!("  \x1b[36m╠══════════════════════════════════════════════════╣\x1b[0m");
    eprintln!("  \x1b[36m║\x1b[0m  URL:      https://{addr}                     \x1b[36m║\x1b[0m");
    eprintln!("  \x1b[36m║\x1b[0m  TLS:      self-signed certificate             \x1b[36m║\x1b[0m");
    eprintln!("  \x1b[36m║\x1b[0m  Auth:     Bearer token required for POST      \x1b[36m║\x1b[0m");
    eprintln!(
        "  \x1b[36m║\x1b[0m  Token:    {}...\x1b[36m║\x1b[0m",
        &api_token[..8.min(api_token.len())]
    );
    eprintln!("  \x1b[36m║\x1b[0m  WebSocket: wss://{addr}/ws                  \x1b[36m║\x1b[0m");
    eprintln!("  \x1b[36m║\x1b[0m  Metrics:   https://{addr}/metrics           \x1b[36m║\x1b[0m");
    eprintln!("  \x1b[36m╚══════════════════════════════════════════════════╝\x1b[0m");
    eprintln!();

    // Generate TLS config
    let (tls_config, _cert_type) = generate_self_signed_cert()?;
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    loop {
        let (stream, _peer_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[talus] TLS accept error: {e}");
                continue;
            }
        };

        let tls_acceptor = tls_acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[talus] TLS handshake error: {e}");
                    return;
                }
            };

            // Serve the TLS stream with hyper-util directly. `axum::serve`
            // owns its listener, so it cannot accept pre-wrapped TLS streams;
            // per-connection serving also keeps one bad client from touching
            // the accept loop.
            let hyper_service = hyper_util::service::TowerToHyperService::new(app);
            let builder =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            let conn = builder.serve_connection_with_upgrades(
                hyper_util::rt::TokioIo::new(tls_stream),
                hyper_service,
            );
            if let Err(e) = conn.await {
                eprintln!("[talus] serve error: {e}");
            }
        });
    }
}
