// talus-web — Go web dashboard for Talus eBPF Process Monitor
//
// Replaces the Rust axum web server. Connects to the C monitor library
// via CGO FFI, serves REST API + WebSocket + Prometheus metrics + dashboard.

package main

/*
#cgo CFLAGS: -I../c-monitor/include
#cgo LDFLAGS: -L../c-monitor -ltalus_monitor -lpthread -lelf -lz -lbpf
#include "talus.h"
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ── Configuration ────────────────────────────────────────────────────────

var (
	bpfPath    string
	listenAddr string
	threshold  uint64
)

func init() {
	flag.StringVar(&bpfPath, "bpf", "", "Path to compiled eBPF object")
	flag.StringVar(&listenAddr, "addr", "127.0.0.1:8080", "Listen address")
	flag.Uint64Var(&threshold, "threshold", 50, "Alert threshold")
}

// ── API types ────────────────────────────────────────────────────────────

type ApiResponse struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

type StatsResponse struct {
	TotalEvents uint64 `json:"total_events"`
	TotalLost   uint64 `json:"total_lost"`
	UptimeSecs  uint64 `json:"uptime_secs"`
	ActivePIDs  uint64 `json:"active_pids"`
	Threshold   uint64 `json:"threshold"`
}

type ProcessInfo struct {
	PID        uint32 `json:"pid"`
	PPID       uint32 `json:"ppid"`
	Comm       string `json:"comm"`
	TotalOpens uint64 `json:"total_opens"`
	TotalExecs uint64 `json:"total_execs"`
	Alerts     uint64 `json:"alerts"`
}

type FileRankResponse struct {
	Path      string  `json:"path"`
	Count     uint64  `json:"count"`
	Extension string  `json:"extension"`
	Entropy   float64 `json:"entropy"`
}

type ExtensionResponse struct {
	Extension string `json:"extension"`
	Count     uint64 `json:"count"`
}

type ThresholdRequest struct {
	Threshold uint64 `json:"threshold"`
}

// ── WebSocket event ──────────────────────────────────────────────────────

type WsEvent struct {
	Type      string `json:"type"`
	Ts        string `json:"ts,omitempty"`
	Kind      string `json:"kind,omitempty"`
	PID       uint32 `json:"pid,omitempty"`
	UID       uint32 `json:"uid,omitempty"`
	Comm      string `json:"comm,omitempty"`
	File      string `json:"file,omitempty"`
	Opens     uint64 `json:"opens_in_1s,omitempty"`
}

// ── Global monitor ───────────────────────────────────────────────────────

var (
	monitor *C.talus_monitor_t
	mu      sync.Mutex

	// WebSocket subscribers
	wsClients   = make(map[*wsConn]bool)
	wsClientsMu sync.RWMutex
	wsBroadcast = make(chan WsEvent, 1024)

	// Prometheus-like counters
	metricsEvents uint64
	metricsExec   uint64
	metricsOpen   uint64
	metricsAlerts uint64
	metricsLost   uint64
	metricsWS     uint64
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// ── Monitor FFI helpers ──────────────────────────────────────────────────

func createMonitor(path string, thresh uint64) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var mon *C.talus_monitor_t
	rc := C.talus_monitor_create(cPath, C.uint64_t(thresh), &mon)
	if rc != C.TALUS_OK {
		errMsg := C.talus_last_error()
		if errMsg != nil {
			return fmt.Errorf("failed to create monitor: %s", C.GoString(errMsg))
		}
		return fmt.Errorf("failed to create monitor: %s", C.talus_strerror(rc))
	}
	monitor = mon
	return nil
}

func destroyMonitor() {
	if monitor != nil {
		C.talus_monitor_destroy(monitor)
		monitor = nil
	}
}

func pollEvents() []WsEvent {
	if monitor == nil {
		return nil
	}

	events := make([]C.talus_event_t, 64)
	var count C.uint32_t

	mu.Lock()
	rc := C.talus_monitor_poll(monitor, &events[0], 64, &count)
	mu.Unlock()

	if rc != C.TALUS_OK {
		return nil
	}

	var wsEvents []WsEvent
	for i := 0; i < int(count); i++ {
		ev := &events[i]
		kind := eventKindStr(int32(ev.kind))

		if ev.kind == -1 {
			// Alert
			wsEvents = append(wsEvents, WsEvent{
				Type: "alert",
				Ts:   cStrToString(ev.timestamp),
				PID:  uint32(ev.pid),
				UID:  uint32(ev.uid),
				Comm: cStrToString(ev.comm),
			})
			metricsAlerts++
		} else {
			wsEvents = append(wsEvents, WsEvent{
				Type: "event",
				Ts:   cStrToString(ev.timestamp),
				Kind: kind,
				PID:  uint32(ev.pid),
				UID:  uint32(ev.uid),
				Comm: cStrToString(ev.comm),
				File: cStrToString(ev.file),
			})
			switch int32(ev.kind) {
			case C.TALUS_EVENT_EXECVE:
				metricsExec++
			case C.TALUS_EVENT_OPENAT:
				metricsOpen++
			}
			metricsEvents++
		}
	}

	if int(count) > 0 {
		C.talus_free_events(&events[0], count)
	}

	return wsEvents
}

func cStrToString(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}

func eventKindStr(kind int32) string {
	switch kind {
	case C.TALUS_EVENT_EXECVE:
		return "Exec"
	case C.TALUS_EVENT_OPENAT:
		return "Open"
	case C.TALUS_EVENT_CONNECT:
		return "Connect"
	case C.TALUS_EVENT_ACCEPT:
		return "Accept"
	case C.TALUS_EVENT_SENDTO:
		return "SendTo"
	case C.TALUS_EVENT_RECVFROM:
		return "RecvFrom"
	case C.TALUS_EVENT_MKDIR:
		return "Mkdir"
	case C.TALUS_EVENT_UNLINK:
		return "Unlink"
	case C.TALUS_EVENT_KILL:
		return "Kill"
	case C.TALUS_EVENT_CHMOD:
		return "Chmod"
	default:
		return "Unknown"
	}
}

// ── REST API handlers ────────────────────────────────────────────────────

func handleStats(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	var stats C.talus_stats_t
	C.talus_monitor_stats(monitor, &stats)
	mu.Unlock()

	data, _ := json.Marshal(StatsResponse{
		TotalEvents: uint64(stats.total_events),
		TotalLost:   uint64(stats.total_lost),
		UptimeSecs:  uint64(stats.uptime_secs),
		ActivePIDs:  uint64(stats.active_pids),
		Threshold:   uint64(stats.threshold),
	})
	writeJSON(w, ApiResponse{OK: true, Data: data})
}

func handleProcesses(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	stats := make([]C.talus_process_stats_t, 512)
	var count C.uint32_t
	C.talus_monitor_processes(monitor, &stats[0], 512, &count)
	mu.Unlock()

	var procs []ProcessInfo
	for i := 0; i < int(count); i++ {
		procs = append(procs, ProcessInfo{
			PID:        uint32(stats[i].pid),
			PPID:       uint32(stats[i].ppid),
			Comm:       cStrToString(stats[i].comm),
			TotalOpens: uint64(stats[i].total_opens),
			TotalExecs: uint64(stats[i].total_execs),
			Alerts:     uint64(stats[i].alerts),
		})
	}
	if int(count) > 0 {
		C.talus_free_processes(&stats[0], count)
	}

	data, _ := json.Marshal(procs)
	writeJSON(w, ApiResponse{OK: true, Data: data})
}

func handleFiles(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	files := make([]C.talus_file_rank_t, 128)
	var count C.uint32_t
	C.talus_monitor_top_files(monitor, &files[0], 128, &count)
	mu.Unlock()

	var ranks []FileRankResponse
	for i := 0; i < int(count); i++ {
		ranks = append(ranks, FileRankResponse{
			Path:      cStrToString(files[i].path),
			Count:     uint64(files[i].count),
			Extension: cStrToString(files[i].extension),
			Entropy:   float64(files[i].entropy),
		})
	}
	if int(count) > 0 {
		C.talus_free_files(&files[0], count)
	}

	data, _ := json.Marshal(ranks)
	writeJSON(w, ApiResponse{OK: true, Data: data})
}

func handleExtensions(w http.ResponseWriter, r *http.Request) {
	// Extensions are tracked in the monitor — we expose them via process stats
	// For now, return empty — full impl would aggregate from processes
	data, _ := json.Marshal([]ExtensionResponse{})
	writeJSON(w, ApiResponse{OK: true, Data: data})
}

// originAllowed rejects cross-site browser requests against the local API.
//
// The dashboard runs without authentication by design (it is a localhost
// operator view), so a page on the internet must not be able to drive it.
// Requests with no Origin (curl, the Tauri shell before it sets one) are
// allowed; browser origins must be same-host or the Tauri webview schemes.
func originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme == "tauri" {
		return true
	}
	if u.Host == "tauri.localhost" {
		return true
	}
	return u.Host == r.Host && (u.Scheme == "http" || u.Scheme == "https")
}

func handleSetThreshold(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		writeJSON(w, ApiResponse{OK: false, Error: "method not allowed"})
		return
	}
	if !originAllowed(r) {
		w.WriteHeader(http.StatusForbidden)
		writeJSON(w, ApiResponse{OK: false, Error: "cross-origin request rejected"})
		return
	}
	var req ThresholdRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, ApiResponse{OK: false, Error: err.Error()})
		return
	}

	mu.Lock()
	C.talus_monitor_set_threshold(monitor, C.uint64_t(req.Threshold))
	var stats C.talus_stats_t
	C.talus_monitor_stats(monitor, &stats)
	mu.Unlock()

	data, _ := json.Marshal(StatsResponse{
		TotalEvents: uint64(stats.total_events),
		TotalLost:   uint64(stats.total_lost),
		UptimeSecs:  uint64(stats.uptime_secs),
		ActivePIDs:  uint64(stats.active_pids),
		Threshold:   uint64(stats.threshold),
	})
	writeJSON(w, ApiResponse{OK: true, Data: data})
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := fmt.Sprintf(
		"# HELP talus_events_total Total eBPF events received\n"+
			"# TYPE talus_events_total counter\n"+
			"talus_events_total %d\n"+
			"# HELP talus_exec_events_total Total execve events\n"+
			"# TYPE talus_exec_events_total counter\n"+
			"talus_exec_events_total %d\n"+
			"# HELP talus_open_events_total Total openat events\n"+
			"# TYPE talus_open_events_total counter\n"+
			"talus_open_events_total %d\n"+
			"# HELP talus_alerts_total Total alerts fired\n"+
			"# TYPE talus_alerts_total counter\n"+
			"talus_alerts_total %d\n"+
			"# HELP talus_lost_events_total Lost events (perf buffer overruns)\n"+
			"# TYPE talus_lost_events_total counter\n"+
			"talus_lost_events_total %d\n"+
			"# HELP talus_ws_connections_total WebSocket connections\n"+
			"# TYPE talus_ws_connections_total counter\n"+
			"talus_ws_connections_total %d\n",
		metricsEvents, metricsExec, metricsOpen,
		metricsAlerts, metricsLost, metricsWS,
	)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte(metrics))
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}

// ── WebSocket ────────────────────────────────────────────────────────────

type wsConn struct {
	conn *websocket.Conn
	send chan WsEvent
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	if !originAllowed(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	wsClientsMu.Lock()
	client := &wsConn{conn: conn, send: make(chan WsEvent, 64)}
	wsClients[client] = true
	metricsWS++
	wsClientsMu.Unlock()

	// Reader
	go func() {
		defer func() {
			wsClientsMu.Lock()
			delete(wsClients, client)
			wsClientsMu.Unlock()
			conn.Close()
		}()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if len(msg) == 0 {
				continue
			}
			// Handle close messages
			if msg[0] == websocket.CloseMessage {
				return
			}
		}
	}()

	// Writer
	go func() {
		defer conn.Close()
		for event := range client.send {
			data, _ := json.Marshal(event)
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}
		}
	}()
}

// ── Event forwarder ──────────────────────────────────────────────────────

func startEventForwarder() {
	go func() {
		for {
			events := pollEvents()
			for _, ev := range events {
				wsClientsMu.RLock()
				for client := range wsClients {
					select {
					case client.send <- ev:
					default:
						// Client too slow, drop
					}
				}
				wsClientsMu.RUnlock()
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
}

// ── JSON response helper ─────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// ── Dashboard HTML ───────────────────────────────────────────────────────

const dashboardHTML = `<!DOCTYPE html>
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
  .tag-net { color: var(--magenta); }
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
  <h1>⚡ TALUS eBPF MONITOR</h1>
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
const MAX_EVENTS=500;const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));let eventCount=0;const eventsEl=document.getElementById('events');const alertsEl=document.getElementById('alerts');
function connect(){const ws=new WebSocket(` + "`ws://${location.host}/ws`" + `);ws.onopen=()=>{document.getElementById('ws-status').textContent='connected';document.getElementById('ws-status').className='connected'};ws.onclose=()=>{document.getElementById('ws-status').textContent='disconnected';document.getElementById('ws-status').className='disconnected';setTimeout(connect,2000)};ws.onmessage=e=>{const d=JSON.parse(e.data);if(d.type==='event'){eventCount++;document.getElementById('event-count').textContent=eventCount;const div=document.createElement('div');div.className='event';const tc=d.kind==='Exec'?'tag-exec':d.kind==='Open'?'tag-open':'tag-net';const tt=d.kind==='Exec'?'EXEC':d.kind==='Open'?'OPEN':d.kind||'NET';const f=d.file?' → '+esc(d.file):'';div.innerHTML=` + "`<span class=\"ts\">${esc(d.ts)}</span> <span class=\"tag ${tc}\">${tt}</span> [${esc(d.pid)}] ${esc(d.comm)}${f}`" + `;eventsEl.appendChild(div);if(eventsEl.children.length>MAX_EVENTS)eventsEl.removeChild(eventsEl.firstChild);eventsEl.scrollTop=eventsEl.scrollHeight}else if(d.type==='alert'){const div=document.createElement('div');div.className='event';div.innerHTML=` + "`<span class=\"ts\">${esc(d.ts)}</span> <span class=\"tag tag-alert\">⚠ ALERT</span> [${esc(d.pid)}] ${esc(d.comm)}`" + `;alertsEl.appendChild(div)}}}connect();
setInterval(async()=>{try{const r=await fetch('/api/v1/stats');const j=await r.json();if(j.ok){const d=j.data;document.getElementById('stats').textContent=` + "`evt ${d.total_events} | lost ${d.total_lost} | uptime ${d.uptime_secs}s | threshold ${d.threshold}/s`" + `;document.getElementById('total-events').textContent=d.total_events;document.getElementById('total-lost').textContent=d.total_lost;document.getElementById('uptime').textContent=d.uptime_secs+'s'}}catch(e){}},2000);
setInterval(async()=>{try{const r=await fetch('/api/v1/files');const j=await r.json();if(j.ok){document.getElementById('files').innerHTML=j.data.map(f=>` + "`<div class=\"file-row\"><span>${esc(f.path.length>30?'…'+f.path.slice(-27):f.path)}</span><span>.${esc(f.extension)}</span><span>${f.count} E:${f.entropy.toFixed(2)}</span></div>`" + `).join('')}}catch(e){}try{const r=await fetch('/api/v1/extensions');const j=await r.json();if(j.ok&&j.data.length>0){const max=Math.max(...j.data.map(e=>e.count));document.getElementById('extensions').innerHTML=j.data.slice(0,8).map(e=>` + "`<div class=\"ext-bar\"><span style=\"width:50px\">.${esc(e.extension)}</span><div class=\"bar\" style=\"width:${(e.count/max*100).toFixed(0)}%\"></div><span>${e.count}</span></div>`" + `).join('')}}catch(e){}try{const r=await fetch('/api/v1/processes');const j=await r.json();if(j.ok){document.getElementById('processes').innerHTML=j.data.slice(0,30).map(p=>{const ab=p.alerts>0?` + "` <span class=\"alerts\">⚠${p.alerts}</span>`" + `:'';return ` + "`<div class=\"process-row\"><span>${esc(p.comm)} [${esc(p.pid)}]</span><span>${p.total_opens} opens${ab}</span></div>`" + `}).join('')}}catch(e){}},3000);
</script>
</body>
</html>`

// ── Main ─────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()

	if bpfPath == "" {
		// Try to auto-detect
		candidates := []string{
			"process-monitor-ebpf.bpf.o",
			"c-ebpf/process_monitor.bpf.o",
			"/usr/local/lib/talus/process-monitor-ebpf",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				bpfPath = c
				break
			}
		}
		if bpfPath == "" {
			fmt.Fprintf(os.Stderr, "Usage: talus-web [--bpf PATH] [--addr :8080] [--threshold N]\n")
			os.Exit(1)
		}
	}

	log.Printf("[talus-web] Loading eBPF object: %s", bpfPath)
	if err := createMonitor(bpfPath, threshold); err != nil {
		log.Fatalf("[talus-web] Failed to create monitor: %v", err)
	}
	defer destroyMonitor()

	log.Printf("[talus-web] Alert threshold: %d/s", threshold)

	// Start event forwarder
	startEventForwarder()

	// Routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleDashboard)
	mux.HandleFunc("/ws", handleWS)
	mux.HandleFunc("/api/v1/stats", handleStats)
	mux.HandleFunc("/api/v1/processes", handleProcesses)
	mux.HandleFunc("/api/v1/files", handleFiles)
	mux.HandleFunc("/api/v1/extensions", handleExtensions)
	mux.HandleFunc("/api/v1/threshold", handleSetThreshold)
	mux.HandleFunc("/metrics", handleMetrics)

	log.Printf("[talus-web] Dashboard: http://%s/", strings.TrimPrefix(listenAddr, ":"))
	log.Printf("[talus-web] WebSocket: ws://%s/ws", strings.TrimPrefix(listenAddr, ":"))
	log.Printf("[talus-web] Prometheus: http://%s/metrics", strings.TrimPrefix(listenAddr, ":"))

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[talus-web] Shutting down...")
		destroyMonitor()
		os.Exit(0)
	}()

	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatalf("[talus-web] Server error: %v", err)
	}
}
