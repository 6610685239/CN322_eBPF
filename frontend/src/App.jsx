import { useState, useEffect, useRef, useCallback } from "react";

const API = import.meta.env.VITE_API_URL || "http://localhost:3001";

/* ════════════════════════════════════════════════════════════════════
   GLOBAL CSS — injected once
════════════════════════════════════════════════════════════════════ */
const CSS = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:       #080c10;
    --surface:  #0d1320;
    --border:   #1c2c40;
    --border2:  #243648;
    --text:     #c8d8e8;
    --muted:    #4a6278;
    --green:    #00e676;
    --amber:    #ffab00;
    --red:      #ff3d71;
    --blue:     #29b6f6;
    --font-mono: 'Share Tech Mono', monospace;
    --font-ui:   'Rajdhani', sans-serif;
  }

  html, body, #root { height: 100%; background: var(--bg); color: var(--text); }
  body { font-family: var(--font-ui); font-size: 15px; }

  ::selection { background: #00e67640; }
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }

  /* ── Layout ── */
  .layout { display: flex; height: 100vh; overflow: hidden; }

  .sidebar {
    width: 220px; flex-shrink: 0;
    background: var(--surface);
    border-right: 1px solid var(--border);
    display: flex; flex-direction: column;
    padding: 0;
  }

  .sidebar-logo {
    padding: 24px 20px 20px;
    border-bottom: 1px solid var(--border);
  }
  .logo-title {
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--green);
    letter-spacing: 2px;
    text-transform: uppercase;
  }
  .logo-sub {
    font-size: 11px; color: var(--muted);
    margin-top: 4px; font-family: var(--font-mono);
  }

  .sidebar-indicator {
    display: flex; align-items: center; gap: 8px;
    padding: 10px 20px;
    border-bottom: 1px solid var(--border);
    font-size: 12px;
    font-family: var(--font-mono);
    color: var(--muted);
  }
  .dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
  .dot.green  { background: var(--green); box-shadow: 0 0 6px var(--green); animation: pulse 2s infinite; }
  .dot.red    { background: var(--red); }
  .dot.amber  { background: var(--amber); }

  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

  .nav { flex: 1; padding: 12px 0; }
  .nav-item {
    display: flex; align-items: center; gap: 12px;
    padding: 11px 20px;
    cursor: pointer;
    font-size: 14px; font-weight: 600; letter-spacing: .5px;
    color: var(--muted);
    border-left: 3px solid transparent;
    transition: all .15s;
    user-select: none;
  }
  .nav-item:hover { color: var(--text); background: rgba(255,255,255,.03); }
  .nav-item.active { color: var(--green); border-left-color: var(--green); background: rgba(0,230,118,.06); }
  .nav-icon { font-size: 16px; width: 20px; text-align: center; }

  .sidebar-footer {
    padding: 16px 20px;
    border-top: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
  }
  .user-name { font-size: 13px; font-family: var(--font-mono); color: var(--muted); }
  .btn-logout {
    background: none; border: 1px solid var(--border2);
    color: var(--muted); padding: 4px 10px;
    font-family: var(--font-mono); font-size: 11px;
    cursor: pointer; letter-spacing: 1px;
    transition: all .15s;
  }
  .btn-logout:hover { color: var(--red); border-color: var(--red); }

  /* ── Main content ── */
  .main { flex: 1; overflow-y: auto; display: flex; flex-direction: column; }

  .topbar {
    padding: 18px 28px;
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    background: var(--surface); flex-shrink: 0;
  }
  .page-title {
    font-size: 20px; font-weight: 700; letter-spacing: 1.5px;
    text-transform: uppercase; color: var(--text);
  }
  .page-sub { font-size: 12px; color: var(--muted); margin-top: 2px; font-family: var(--font-mono); }

  .content { padding: 28px; flex: 1; }

  /* ── Cards ── */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    margin-bottom: 20px;
  }
  .card-header {
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
  }
  .card-title { font-size: 13px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; color: var(--blue); }
  .card-body { padding: 20px; }

  /* ── Toggle Switch ── */
  .feature-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
  .feature-card {
    background: var(--bg);
    border: 1px solid var(--border);
    padding: 20px;
    display: flex; flex-direction: column; gap: 14px;
    transition: border-color .2s;
    position: relative; overflow: hidden;
  }
  .feature-card.enabled { border-color: var(--green); }
  .feature-card.enabled::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: var(--green);
  }
  .feature-label { font-size: 13px; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; }
  .feature-desc { font-size: 12px; color: var(--muted); line-height: 1.5; }
  .feature-status { font-family: var(--font-mono); font-size: 11px; }
  .feature-status.on { color: var(--green); }
  .feature-status.off { color: var(--red); }

  .toggle {
    display: flex; align-items: center; gap: 10px; cursor: pointer; user-select: none;
  }
  .toggle-track {
    width: 44px; height: 24px;
    background: var(--border2); border-radius: 12px;
    position: relative; transition: background .2s;
    border: 1px solid var(--border2);
    flex-shrink: 0;
  }
  .toggle-track.on { background: var(--green); border-color: var(--green); }
  .toggle-thumb {
    position: absolute; top: 2px; left: 2px;
    width: 18px; height: 18px; border-radius: 50%;
    background: #fff; transition: transform .2s;
  }
  .toggle-track.on .toggle-thumb { transform: translateX(20px); }

  /* ── Stats row ── */
  .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
  .stat-card {
    background: var(--bg); border: 1px solid var(--border);
    padding: 16px 20px;
  }
  .stat-num { font-family: var(--font-mono); font-size: 28px; font-weight: 400; line-height: 1; }
  .stat-num.green { color: var(--green); }
  .stat-num.amber { color: var(--amber); }
  .stat-num.red   { color: var(--red); }
  .stat-num.blue  { color: var(--blue); }
  .stat-label { font-size: 11px; letter-spacing: 1.5px; text-transform: uppercase; color: var(--muted); margin-top: 6px; }

  /* ── Table ── */
  .tbl { width: 100%; border-collapse: collapse; font-size: 13px; }
  .tbl th {
    text-align: left; padding: 10px 14px;
    font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
    color: var(--muted); border-bottom: 1px solid var(--border);
    font-family: var(--font-mono);
  }
  .tbl td { padding: 10px 14px; border-bottom: 1px solid var(--border); }
  .tbl tr:last-child td { border-bottom: none; }
  .tbl tr:hover td { background: rgba(255,255,255,.02); }
  .mono { font-family: var(--font-mono); }
  .tag {
    display: inline-block; padding: 2px 8px;
    font-size: 10px; letter-spacing: 1px; text-transform: uppercase;
    font-family: var(--font-mono);
  }
  .tag.bl { color: var(--red); border: 1px solid var(--red); background: rgba(255,61,113,.08); }
  .tag.ping { color: var(--amber); border: 1px solid var(--amber); background: rgba(255,171,0,.08); }
  .tag.web { color: var(--blue); border: 1px solid var(--blue); background: rgba(41,182,246,.08); }

  /* ── Inputs / Buttons ── */
  .input-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .inp {
    background: var(--bg); border: 1px solid var(--border2);
    color: var(--text); padding: 8px 12px;
    font-family: var(--font-mono); font-size: 13px;
    outline: none; transition: border-color .15s;
  }
  .inp:focus { border-color: var(--blue); }
  .inp::placeholder { color: var(--muted); }
  .inp-note { flex: 1; min-width: 140px; }
  .inp-ip { width: 170px; }
  .inp-port { width: 100px; }

  .btn {
    padding: 8px 18px; font-family: var(--font-ui);
    font-weight: 700; font-size: 13px; letter-spacing: 1px;
    text-transform: uppercase; cursor: pointer;
    border: 1px solid; transition: all .15s;
  }
  .btn-primary { background: var(--green); color: #000; border-color: var(--green); }
  .btn-primary:hover { background: #00ff88; }
  .btn-primary:disabled { opacity: .4; cursor: not-allowed; }
  .btn-danger { background: none; color: var(--red); border-color: var(--red); }
  .btn-danger:hover { background: rgba(255,61,113,.12); }

  /* ── Logs ── */
  .log-wrap { height: 420px; overflow-y: auto; background: var(--bg); border: 1px solid var(--border); padding: 0; }
  .log-line {
    display: flex; align-items: baseline; gap: 12px;
    padding: 6px 14px; border-bottom: 1px solid rgba(255,255,255,.03);
    font-family: var(--font-mono); font-size: 12px;
    animation: fadeIn .3s ease;
  }
  @keyframes fadeIn { from{opacity:0;transform:translateY(-4px)} to{opacity:1;transform:none} }
  .log-ts { color: var(--muted); flex-shrink: 0; width: 80px; }
  .log-badge {
    flex-shrink: 0; padding: 1px 7px; font-size: 10px;
    letter-spacing: 1px; text-transform: uppercase;
  }
  .log-badge.blacklist { background: rgba(255,61,113,.15); color: var(--red); }
  .log-badge.ping      { background: rgba(255,171,0,.15); color: var(--amber); }
  .log-badge.web       { background: rgba(41,182,246,.15); color: var(--blue); }
  .log-body { color: var(--text); flex: 1; }
  .log-empty { padding: 40px; text-align: center; color: var(--muted); font-family: var(--font-mono); font-size: 12px; }
  .log-controls { display: flex; gap: 10px; align-items: center; }
  .badge-count {
    background: var(--border); color: var(--text);
    font-size: 11px; font-family: var(--font-mono);
    padding: 2px 8px; min-width: 28px; text-align: center;
  }

  /* ── Login ── */
  .login-wrap {
    height: 100vh; display: flex; align-items: center; justify-content: center;
    background: var(--bg);
    background-image:
      linear-gradient(rgba(0,230,118,.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,230,118,.03) 1px, transparent 1px);
    background-size: 40px 40px;
  }
  .login-box {
    background: var(--surface); border: 1px solid var(--border);
    width: 380px; padding: 40px;
  }
  .login-title {
    font-family: var(--font-mono); font-size: 12px;
    letter-spacing: 3px; text-transform: uppercase;
    color: var(--green); margin-bottom: 8px;
  }
  .login-sub { font-size: 22px; font-weight: 700; margin-bottom: 32px; letter-spacing: 1px; }
  .form-group { margin-bottom: 18px; }
  .form-label { display: block; font-size: 11px; letter-spacing: 1.5px; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }
  .form-inp {
    width: 100%; background: var(--bg);
    border: 1px solid var(--border2); color: var(--text);
    padding: 10px 14px; font-family: var(--font-mono); font-size: 14px;
    outline: none; transition: border-color .15s;
  }
  .form-inp:focus { border-color: var(--green); }
  .btn-login {
    width: 100%; padding: 12px; background: var(--green); color: #000;
    border: none; font-family: var(--font-ui); font-weight: 700;
    font-size: 14px; letter-spacing: 2px; text-transform: uppercase;
    cursor: pointer; margin-top: 8px; transition: background .15s;
  }
  .btn-login:hover { background: #00ff88; }
  .btn-login:disabled { opacity: .5; cursor: not-allowed; }
  .err-msg { color: var(--red); font-size: 12px; font-family: var(--font-mono); margin-top: 12px; }

  .empty-row td { text-align: center; color: var(--muted); padding: 28px; font-family: var(--font-mono); font-size: 12px; }
  .note-text { color: var(--muted); font-size: 12px; }

  /* ── Scrollbar auto-follow checkbox ── */
  .checkbox-label {
    display: flex; align-items: center; gap: 8px;
    font-size: 12px; color: var(--muted); cursor: pointer;
    user-select: none; font-family: var(--font-mono);
  }
  .checkbox-label input { accent-color: var(--green); cursor: pointer; }
`;

function injectCSS(css) {
  if (document.getElementById("fw-styles")) return;
  const el = document.createElement("style");
  el.id = "fw-styles";
  el.textContent = css;
  document.head.appendChild(el);
}

/* ════════════════════════════════════════════════════════════════════
   API helpers
════════════════════════════════════════════════════════════════════ */
function getToken() { return localStorage.getItem("fw_token"); }

async function apiFetch(path, opts = {}) {
  const token = getToken();
  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(opts.headers || {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

/* ════════════════════════════════════════════════════════════════════
   Timestamp helper
════════════════════════════════════════════════════════════════════ */
function fmtTime(ts) {
  const d = new Date(ts);
  const h = String(d.getHours()).padStart(2, "0");
  const m = String(d.getMinutes()).padStart(2, "0");
  const s = String(d.getSeconds()).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

/* ════════════════════════════════════════════════════════════════════
   LOGIN PAGE
════════════════════════════════════════════════════════════════════ */
function LoginPage({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error,    setError]    = useState("");
  const [loading,  setLoading]  = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError(""); setLoading(true);
    try {
      const data = await apiFetch("/api/login", {
        method: "POST",
        body: { username, password },
      });
      localStorage.setItem("fw_token", data.token);
      localStorage.setItem("fw_user", data.username);
      onLogin(data.username);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-box" onSubmit={submit}>
        <div className="login-title">// XDP Firewall</div>
        <div className="login-sub">Dashboard Access</div>
        <div className="form-group">
          <label className="form-label">Username</label>
          <input className="form-inp" value={username} onChange={e => setUsername(e.target.value)} autoFocus />
        </div>
        <div className="form-group">
          <label className="form-label">Password</label>
          <input className="form-inp" type="password" value={password} onChange={e => setPassword(e.target.value)} />
        </div>
        {error && <div className="err-msg">⚠ {error}</div>}
        <button className="btn-login" type="submit" disabled={loading}>
          {loading ? "Authenticating..." : "Login →"}
        </button>
      </form>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   FEATURE TOGGLES PANEL
════════════════════════════════════════════════════════════════════ */
const FEATURES = [
  { id: "blacklist", label: "IP Blacklist", icon: "🚫", desc: "บล็อก IP ที่อยู่ในรายการ blacklist ทั้งหมด" },
  { id: "ping",      label: "ICMP Block",   icon: "🏓", desc: "บล็อก Ping (ICMP) จากทุก IP ที่เข้ามา" },
  { id: "port",      label: "Port Block",   icon: "🔒", desc: "บล็อก TCP Port ตามรายการที่กำหนดไว้" },
];

function FeaturesPanel({ features, onToggle }) {
  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">⚙ Feature Control</span>
      </div>
      <div className="card-body">
        <div className="feature-grid">
          {FEATURES.map(f => {
            const on = !!features[f.id];
            return (
              <div key={f.id} className={`feature-card ${on ? "enabled" : ""}`}>
                <div style={{ fontSize: 24 }}>{f.icon}</div>
                <div>
                  <div className="feature-label">{f.label}</div>
                  <div className="feature-desc">{f.desc}</div>
                </div>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span className={`feature-status ${on ? "on" : "off"}`}>
                    {on ? "● ACTIVE" : "○ INACTIVE"}
                  </span>
                  <label className="toggle">
                    <div
                      className={`toggle-track ${on ? "on" : ""}`}
                      onClick={() => onToggle(f.id, !on)}
                    >
                      <div className="toggle-thumb" />
                    </div>
                  </label>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   STATS PANEL
════════════════════════════════════════════════════════════════════ */
function StatsPanel({ stats }) {
  const byType = Object.fromEntries((stats?.byType || []).map(r => [r.event_type, r.c]));
  return (
    <div className="stats-grid" style={{ marginBottom: 20 }}>
      <div className="stat-card">
        <div className="stat-num green">{stats?.total ?? "—"}</div>
        <div className="stat-label">Total Blocked</div>
      </div>
      <div className="stat-card">
        <div className="stat-num red">{byType.blacklist ?? 0}</div>
        <div className="stat-label">By Blacklist</div>
      </div>
      <div className="stat-card">
        <div className="stat-num amber">{byType.ping ?? 0}</div>
        <div className="stat-label">By Ping Block</div>
      </div>
      <div className="stat-card">
        <div className="stat-num blue">{byType.web ?? 0}</div>
        <div className="stat-label">By Port Block</div>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   BLACKLIST PANEL
════════════════════════════════════════════════════════════════════ */
function BlacklistPanel() {
  const [rows,    setRows]    = useState([]);
  const [ip,      setIp]      = useState("");
  const [note,    setNote]    = useState("");
  const [error,   setError]   = useState("");
  const [loading, setLoading] = useState(false);

  async function load() {
    try { setRows(await apiFetch("/api/blacklist")); } catch {}
  }

  useEffect(() => { load(); }, []);

  async function add() {
    setError(""); setLoading(true);
    try {
      await apiFetch("/api/blacklist", { method: "POST", body: { ip, note } });
      setIp(""); setNote("");
      await load();
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }

  async function remove(id) {
    try { await apiFetch(`/api/blacklist/${id}`, { method: "DELETE" }); await load(); } catch {}
  }

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">🚫 IP Blacklist</span>
        <span className="badge-count">{rows.length}</span>
      </div>
      <div className="card-body">
        <div className="input-row" style={{ marginBottom: 16 }}>
          <input
            className="inp inp-ip"
            placeholder="192.168.1.100"
            value={ip}
            onChange={e => setIp(e.target.value)}
            onKeyDown={e => e.key === "Enter" && add()}
          />
          <input
            className="inp inp-note"
            placeholder="Note (optional)"
            value={note}
            onChange={e => setNote(e.target.value)}
          />
          <button className="btn btn-primary" onClick={add} disabled={!ip || loading}>
            + Add IP
          </button>
        </div>
        {error && <div className="err-msg" style={{ marginBottom: 12 }}>⚠ {error}</div>}
        <table className="tbl">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Note</th>
              <th>Added</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr className="empty-row"><td colSpan={4}>No IPs in blacklist</td></tr>
            )}
            {rows.map(r => (
              <tr key={r.id}>
                <td className="mono" style={{ color: "var(--red)" }}>{r.ip}</td>
                <td className="note-text">{r.note || "—"}</td>
                <td className="mono" style={{ fontSize: 11, color: "var(--muted)" }}>
                  {r.created_at?.slice(0, 16).replace("T", " ")}
                </td>
                <td style={{ textAlign: "right" }}>
                  <button className="btn btn-danger" style={{ padding: "4px 12px", fontSize: 11 }} onClick={() => remove(r.id)}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   PORT BLOCK PANEL
════════════════════════════════════════════════════════════════════ */
function PortsPanel() {
  const [rows,    setRows]    = useState([]);
  const [port,    setPort]    = useState("");
  const [note,    setNote]    = useState("");
  const [error,   setError]   = useState("");
  const [loading, setLoading] = useState(false);

  async function load() {
    try { setRows(await apiFetch("/api/ports")); } catch {}
  }

  useEffect(() => { load(); }, []);

  async function add() {
    setError(""); setLoading(true);
    try {
      await apiFetch("/api/ports", { method: "POST", body: { port: Number(port), note } });
      setPort(""); setNote("");
      await load();
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }

  async function remove(id) {
    try { await apiFetch(`/api/ports/${id}`, { method: "DELETE" }); await load(); } catch {}
  }

  const WELL_KNOWN = [
    { port: 80,   label: "HTTP" },
    { port: 443,  label: "HTTPS" },
    { port: 8000, label: "Dev" },
    { port: 22,   label: "SSH" },
    { port: 3306, label: "MySQL" },
  ];

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">🔒 Port Blocklist</span>
        <span className="badge-count">{rows.length}</span>
      </div>
      <div className="card-body">
        <div style={{ marginBottom: 14, display: "flex", gap: 8, flexWrap: "wrap" }}>
          {WELL_KNOWN.map(w => (
            <button
              key={w.port}
              className="btn"
              style={{ padding: "3px 10px", fontSize: 11, color: "var(--muted)", borderColor: "var(--border2)" }}
              onClick={() => setPort(String(w.port))}
            >
              {w.label} :{w.port}
            </button>
          ))}
        </div>
        <div className="input-row" style={{ marginBottom: 16 }}>
          <input
            className="inp inp-port"
            placeholder="8080"
            type="number"
            min="1" max="65535"
            value={port}
            onChange={e => setPort(e.target.value)}
            onKeyDown={e => e.key === "Enter" && add()}
          />
          <input
            className="inp inp-note"
            placeholder="Note (optional)"
            value={note}
            onChange={e => setNote(e.target.value)}
          />
          <button className="btn btn-primary" onClick={add} disabled={!port || loading}>
            + Add Port
          </button>
        </div>
        {error && <div className="err-msg" style={{ marginBottom: 12 }}>⚠ {error}</div>}
        <table className="tbl">
          <thead>
            <tr>
              <th>Port</th>
              <th>Note</th>
              <th>Added</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr className="empty-row"><td colSpan={4}>No ports blocked</td></tr>
            )}
            {rows.map(r => (
              <tr key={r.id}>
                <td className="mono" style={{ color: "var(--blue)", fontSize: 15 }}>:{r.port}</td>
                <td className="note-text">{r.note || "—"}</td>
                <td className="mono" style={{ fontSize: 11, color: "var(--muted)" }}>
                  {r.created_at?.slice(0, 16).replace("T", " ")}
                </td>
                <td style={{ textAlign: "right" }}>
                  <button className="btn btn-danger" style={{ padding: "4px 12px", fontSize: 11 }} onClick={() => remove(r.id)}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   LIVE LOGS PANEL
════════════════════════════════════════════════════════════════════ */
function LogsPanel({ liveLog }) {
  const [history,    setHistory]    = useState([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const [filter,     setFilter]     = useState("all");
  const bottomRef = useRef(null);

  useEffect(() => {
    apiFetch("/api/logs?limit=200").then(rows => {
      setHistory(rows.map(r => ({
        eventType: r.event_type,
        ip: r.ip,
        port: r.port,
        timestamp: r.created_at,
      })));
    }).catch(() => {});
  }, []);

  // Merge history + live
  const allLogs = [...history, ...liveLog];

  const filtered = filter === "all" ? allLogs : allLogs.filter(l => l.eventType === filter);

  useEffect(() => {
    if (autoScroll && bottomRef.current)
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
  }, [filtered.length, autoScroll]);

  function logLine(l, i) {
    const ts = l.timestamp ? fmtTime(l.timestamp) : "??:??:??";
    const body = l.eventType === "blacklist"
      ? `Blocked IP ${l.ip}`
      : l.eventType === "ping"
      ? `Blocked Ping from ${l.ip}`
      : `Blocked ${l.ip} → Port ${l.port}`;
    return (
      <div key={i} className="log-line">
        <span className="log-ts">{ts}</span>
        <span className={`log-badge ${l.eventType}`}>{l.eventType}</span>
        <span className="log-body">{body}</span>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">📡 Live Event Log</span>
        <div className="log-controls">
          {["all", "blacklist", "ping", "web"].map(f => (
            <button
              key={f}
              className="btn"
              style={{
                padding: "3px 10px", fontSize: 11,
                color: filter === f ? "#000" : "var(--muted)",
                background: filter === f ? "var(--green)" : "none",
                borderColor: filter === f ? "var(--green)" : "var(--border2)",
              }}
              onClick={() => setFilter(f)}
            >
              {f.toUpperCase()}
            </button>
          ))}
          <label className="checkbox-label">
            <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} />
            Auto-scroll
          </label>
          <span className="badge-count">{filtered.length}</span>
        </div>
      </div>
      <div className="log-wrap">
        {filtered.length === 0
          ? <div className="log-empty">// No events yet — waiting for traffic...</div>
          : filtered.map((l, i) => logLine(l, i))
        }
        <div ref={bottomRef} />
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   MAIN APP
════════════════════════════════════════════════════════════════════ */
const TABS = [
  { id: "overview",  label: "Overview",    icon: "◈" },
  { id: "blacklist", label: "IP Blacklist", icon: "🚫" },
  { id: "ports",     label: "Port Block",  icon: "🔒" },
  { id: "logs",      label: "Live Logs",   icon: "📡" },
];

export default function App() {
  injectCSS(CSS);

  const [user,     setUser]     = useState(localStorage.getItem("fw_user") || null);
  const [tab,      setTab]      = useState("overview");
  const [features, setFeatures] = useState({});
  const [stats,    setStats]    = useState(null);
  const [liveLog,  setLiveLog]  = useState([]);
  const [fwOnline, setFwOnline] = useState(false);
  const wsRef = useRef(null);

  /* ── Load features + stats ── */
  async function loadData() {
    try {
      const [f, s] = await Promise.all([
        apiFetch("/api/features"),
        apiFetch("/api/stats"),
      ]);
      setFeatures(f);
      setStats(s);
    } catch {}
  }

  /* ── WebSocket ── */
  function connectWS() {
    const token = getToken();
    if (!token) return;
    const ws = new WebSocket(`${API.replace("http", "ws")}/ws?token=${token}`);
    wsRef.current = ws;

    ws.onmessage = e => {
      const msg = JSON.parse(e.data);
      if (msg.type === "state") {
        const obj = {};
        msg.features.forEach(f => (obj[f.id] = f.enabled === 1));
        setFeatures(obj);
      } else if (msg.type === "log") {
        setLiveLog(prev => [...prev.slice(-500), msg]);
        setStats(s => s ? { ...s, total: (s.total || 0) + 1 } : s);
      } else if (msg.type === "firewall_status") {
        setFwOnline(msg.connected);
      }
    };

    ws.onclose  = () => { setTimeout(connectWS, 3000); };
    ws.onerror  = () => {};
  }

  useEffect(() => {
    if (!user) return;
    loadData();
    connectWS();
    return () => wsRef.current?.close();
  }, [user]);

  /* ── Toggle feature ── */
  async function onToggle(feature, enabled) {
    setFeatures(f => ({ ...f, [feature]: enabled }));
    try {
      await apiFetch(`/api/features/${feature}`, { method: "PATCH", body: { enabled } });
    } catch {
      setFeatures(f => ({ ...f, [feature]: !enabled })); // rollback
    }
  }

  /* ── Auth ── */
  function handleLogin(username) { setUser(username); }
  function handleLogout() {
    localStorage.removeItem("fw_token");
    localStorage.removeItem("fw_user");
    setUser(null);
    wsRef.current?.close();
  }

  if (!user) return <LoginPage onLogin={handleLogin} />;

  const PAGE_TITLES = {
    overview:  { title: "System Overview",    sub: "Feature control & statistics" },
    blacklist: { title: "IP Blacklist",        sub: "Manage blocked IP addresses" },
    ports:     { title: "Port Blocklist",      sub: "Manage blocked TCP ports" },
    logs:      { title: "Live Event Log",      sub: "Real-time traffic events" },
  };

  return (
    <div className="layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-title">XDP Firewall</div>
          <div className="logo-sub">Dashboard v1.0</div>
        </div>
        <div className="sidebar-indicator">
          <div className={`dot ${fwOnline ? "green" : "red"}`} />
          {fwOnline ? "Firewall Online" : "Firewall Offline"}
        </div>
        <nav className="nav">
          {TABS.map(t => (
            <div
              key={t.id}
              className={`nav-item ${tab === t.id ? "active" : ""}`}
              onClick={() => setTab(t.id)}
            >
              <span className="nav-icon">{t.icon}</span>
              {t.label}
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className="user-name">// {user}</span>
          <button className="btn-logout" onClick={handleLogout}>LOGOUT</button>
        </div>
      </aside>

      {/* Main */}
      <div className="main">
        <div className="topbar">
          <div>
            <div className="page-title">{PAGE_TITLES[tab].title}</div>
            <div className="page-sub">{PAGE_TITLES[tab].sub}</div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {Object.entries(features).map(([k, v]) => (
              <span key={k} style={{
                fontFamily: "var(--font-mono)", fontSize: 10,
                padding: "2px 8px",
                color: v ? "var(--green)" : "var(--muted)",
                border: `1px solid ${v ? "var(--green)" : "var(--border2)"}`,
                background: v ? "rgba(0,230,118,.07)" : "none",
                letterSpacing: 1,
              }}>
                {k.toUpperCase()}
              </span>
            ))}
          </div>
        </div>

        <div className="content">
          {tab === "overview" && (
            <>
              <StatsPanel stats={stats} />
              <FeaturesPanel features={features} onToggle={onToggle} />
            </>
          )}
          {tab === "blacklist" && <BlacklistPanel />}
          {tab === "ports"     && <PortsPanel />}
          {tab === "logs"      && <LogsPanel liveLog={liveLog} />}
        </div>
      </div>
    </div>
  );
}
