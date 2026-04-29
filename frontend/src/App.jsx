import { useState, useEffect, useRef, useMemo } from "react";

const API = import.meta.env.VITE_API_URL || "http://localhost:3001";

/* ════════════════════════════════════════════════════════════════════
   DESIGN TOKENS + GLOBAL CSS
════════════════════════════════════════════════════════════════════ */
const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg-base:      #07090d;
    --bg-elev-1:    #0d1117;
    --bg-elev-2:    #131a23;
    --bg-elev-3:    #1a2230;

    --border-subtle: rgba(255,255,255,0.04);
    --border:        rgba(255,255,255,0.08);
    --border-strong: rgba(255,255,255,0.16);

    --text:        #e6edf3;
    --text-muted:  #8b96a5;
    --text-faint:  #586069;

    --cyan:        #22d3ee;
    --cyan-deep:   #0891b2;
    --cyan-glow:   rgba(34,211,238,0.35);
    --emerald:     #10b981;
    --emerald-glow:rgba(16,185,129,0.30);
    --amber:       #f59e0b;
    --rose:        #f43f5e;
    --rose-glow:   rgba(244,63,94,0.30);
    --violet:      #a78bfa;

    --shadow-sm: 0 1px 2px rgba(0,0,0,0.4);
    --shadow-md: 0 4px 12px rgba(0,0,0,0.35), 0 0 0 1px var(--border);
    --shadow-lg: 0 16px 40px rgba(0,0,0,0.5), 0 0 0 1px var(--border);
    --glow-cyan: 0 0 24px rgba(34,211,238,0.18);

    --font-ui:    'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    --font-mono:  'JetBrains Mono', 'SF Mono', Menlo, monospace;

    --r-sm: 6px;
    --r-md: 10px;
    --r-lg: 14px;
  }

  html, body, #root {
    height: 100%; width: 100%;
    background: var(--bg-base);
    color: var(--text);
    overflow: hidden;
  }
  body {
    font-family: var(--font-ui);
    font-size: 14px;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }

  body::before {
    content: ''; position: fixed; inset: 0;
    z-index: 0; pointer-events: none;
    background:
      radial-gradient(ellipse 70% 50% at 30% 0%, rgba(34,211,238,0.06), transparent 60%),
      radial-gradient(ellipse 60% 50% at 90% 100%, rgba(167,139,250,0.05), transparent 60%);
  }

  ::selection { background: rgba(34,211,238,0.30); color: #fff; }

  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.06); border-radius: 4px; }
  ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.14); }

  button { font-family: inherit; }

  /* ── Layout ─────────────────────────────────────── */
  .layout {
    display: flex; height: 100vh; width: 100vw;
    overflow: hidden;
    position: relative; z-index: 1;
  }

  /* ── Sidebar ────────────────────────────────────── */
  .sidebar {
    width: 260px; flex-shrink: 0;
    background: linear-gradient(180deg, var(--bg-elev-1) 0%, var(--bg-base) 100%);
    border-right: 1px solid var(--border);
    display: flex; flex-direction: column;
    position: relative;
  }
  .sidebar::after {
    content: ''; position: absolute;
    right: 0; top: 0; bottom: 0; width: 1px;
    background: linear-gradient(180deg, transparent, var(--cyan-glow) 30%, transparent 70%);
    opacity: .25;
  }

  .brand {
    padding: 24px 22px 22px;
    border-bottom: 1px solid var(--border-subtle);
    display: flex; align-items: center; gap: 12px;
  }
  .brand-logo {
    width: 38px; height: 38px;
    background: linear-gradient(135deg, var(--cyan), var(--cyan-deep));
    border-radius: var(--r-sm);
    display: flex; align-items: center; justify-content: center;
    box-shadow: var(--glow-cyan);
    flex-shrink: 0;
  }
  .brand-logo svg { width: 20px; height: 20px; color: #07090d; }
  .brand-text { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .brand-name { font-size: 14px; font-weight: 700; letter-spacing: .3px; color: var(--text); }
  .brand-tag { font-family: var(--font-mono); font-size: 10px; color: var(--text-faint); letter-spacing: .5px; }

  .status-banner {
    margin: 16px 16px 8px;
    padding: 12px 14px;
    background: var(--bg-elev-2);
    border: 1px solid var(--border-subtle);
    border-radius: var(--r-sm);
    display: flex; align-items: center; gap: 12px;
  }
  .status-banner.online  { border-color: rgba(16,185,129,0.30); }
  .status-banner.offline { border-color: rgba(244,63,94,0.30); }

  .pulse-wrap { position: relative; width: 9px; height: 9px; flex-shrink: 0; }
  .pulse-dot { position: absolute; inset: 0; border-radius: 50%; }
  .pulse-dot.green { background: var(--emerald); box-shadow: 0 0 10px var(--emerald-glow); }
  .pulse-dot.red   { background: var(--rose); box-shadow: 0 0 10px var(--rose-glow); }
  .pulse-ring {
    position: absolute; inset: -3px;
    border-radius: 50%;
    border: 2px solid var(--emerald);
    opacity: 0;
    animation: pulse-ring 2s ease-out infinite;
  }
  @keyframes pulse-ring {
    0%   { transform: scale(.6); opacity: .6; }
    100% { transform: scale(1.8); opacity: 0; }
  }

  .status-text { font-family: var(--font-mono); font-size: 12px; color: var(--text); }
  .status-label { font-size: 10px; color: var(--text-faint); margin-top: 2px; }

  .nav { flex: 1; padding: 14px 14px; overflow-y: auto; }
  .nav-group-label {
    font-size: 10px; letter-spacing: 1.5px; color: var(--text-faint);
    text-transform: uppercase; padding: 12px 10px 10px; font-weight: 600;
  }
  .nav-item {
    display: flex; align-items: center; gap: 12px;
    padding: 10px 12px; cursor: pointer;
    border-radius: var(--r-sm);
    color: var(--text-muted);
    font-size: 13.5px; font-weight: 500;
    transition: all .15s ease; user-select: none;
    position: relative; margin-bottom: 2px;
  }
  .nav-item:hover { color: var(--text); background: rgba(255,255,255,0.03); }
  .nav-item.active {
    color: var(--cyan); background: linear-gradient(90deg, rgba(34,211,238,0.10), transparent);
  }
  .nav-item.active::before {
    content: '';
    position: absolute; left: -14px; top: 50%; transform: translateY(-50%);
    width: 3px; height: 18px;
    background: var(--cyan); border-radius: 0 2px 2px 0;
    box-shadow: var(--glow-cyan);
  }
  .nav-icon { width: 18px; height: 18px; flex-shrink: 0; }

  .stop-fw-wrap { padding: 14px 16px; border-top: 1px solid var(--border-subtle); }
  .btn-stop-fw {
    width: 100%; padding: 11px 14px;
    background: rgba(244,63,94,0.06);
    border: 1px solid rgba(244,63,94,0.30);
    color: var(--rose);
    border-radius: var(--r-sm);
    font-size: 12px; font-weight: 600;
    letter-spacing: .8px; text-transform: uppercase;
    cursor: pointer; transition: all .15s ease;
    display: flex; align-items: center; justify-content: center; gap: 8px;
  }
  .btn-stop-fw:hover:not(:disabled) {
    background: rgba(244,63,94,0.14);
    border-color: var(--rose);
    box-shadow: 0 0 16px rgba(244,63,94,0.20);
  }
  .btn-stop-fw:disabled { opacity: .35; cursor: not-allowed; }
  .btn-stop-fw svg { width: 14px; height: 14px; }

  .user-card {
    padding: 14px 16px;
    border-top: 1px solid var(--border-subtle);
    display: flex; align-items: center; gap: 10px;
  }
  .user-avatar {
    width: 34px; height: 34px;
    border-radius: 50%;
    background: linear-gradient(135deg, var(--violet), var(--cyan));
    display: flex; align-items: center; justify-content: center;
    font-weight: 700; font-size: 13px; color: #07090d;
    flex-shrink: 0;
  }
  .user-info { flex: 1; min-width: 0; }
  .user-name { font-size: 13px; font-weight: 600; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .user-role { font-size: 10px; color: var(--text-faint); font-family: var(--font-mono); }
  .icon-btn {
    background: none; border: 1px solid var(--border);
    width: 30px; height: 30px; border-radius: var(--r-sm);
    display: flex; align-items: center; justify-content: center;
    cursor: pointer; color: var(--text-muted);
    transition: all .15s ease;
  }
  .icon-btn:hover { color: var(--rose); border-color: rgba(244,63,94,0.40); }
  .icon-btn svg { width: 14px; height: 14px; }

  /* ── Main ───────────────────────────────────────── */
  .main { flex: 1; min-width: 0; overflow-y: auto; display: flex; flex-direction: column; }

  .topbar {
    padding: 20px 36px;
    border-bottom: 1px solid var(--border-subtle);
    display: flex; align-items: center; justify-content: space-between;
    background: rgba(13,17,23,0.65);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    flex-shrink: 0; gap: 24px;
    position: sticky; top: 0; z-index: 10;
  }
  .page-title { font-size: 20px; font-weight: 700; letter-spacing: -.2px; color: var(--text); }
  .page-sub { font-size: 12.5px; color: var(--text-muted); margin-top: 3px; }

  .feature-pills { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
  .pill {
    font-family: var(--font-mono); font-size: 10.5px;
    padding: 4px 11px; letter-spacing: .8px;
    border-radius: 999px;
    border: 1px solid var(--border);
    transition: all .2s ease;
    display: flex; align-items: center; gap: 6px;
  }
  .pill::before {
    content: ''; width: 5px; height: 5px; border-radius: 50%;
    background: var(--text-faint);
  }
  .pill.on  {
    color: var(--emerald);
    border-color: rgba(16,185,129,0.30);
    background: rgba(16,185,129,0.06);
  }
  .pill.on::before { background: var(--emerald); box-shadow: 0 0 6px var(--emerald-glow); }
  .pill.off { color: var(--text-faint); }

  .content { padding: 32px 36px 48px; flex: 1; }

  /* ── Dashboard grid ─────────────────────────────── */
  .dash-row { display: grid; gap: 22px; margin-bottom: 22px; }
  .dash-row.cols-2 { grid-template-columns: 1fr 1fr; }
  .dash-row.cols-2-asym { grid-template-columns: 1.4fr 1fr; }
  .dash-row > .card { margin-bottom: 0; }

  @media (max-width: 1280px) {
    .dash-row.cols-2,
    .dash-row.cols-2-asym { grid-template-columns: 1fr; }
  }

  /* ── Card ──────────────────────────────────────── */
  .card {
    background: linear-gradient(180deg, var(--bg-elev-1), var(--bg-elev-2));
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    margin-bottom: 22px;
    box-shadow: var(--shadow-md);
    overflow: hidden;
    display: flex; flex-direction: column;
  }
  .card-header {
    padding: 16px 24px;
    border-bottom: 1px solid var(--border-subtle);
    display: flex; align-items: center; justify-content: space-between;
    background: var(--bg-elev-2);
    flex-shrink: 0;
    gap: 12px;
  }
  .card-title {
    font-size: 12px; font-weight: 600; letter-spacing: 1.2px;
    text-transform: uppercase; color: var(--text-muted);
    display: flex; align-items: center; gap: 9px;
  }
  .card-title svg { width: 14px; height: 14px; color: var(--cyan); }
  .card-body { padding: 24px; flex: 1; }
  .card-body.flush { padding: 0; }

  /* ── Stats ──────────────────────────────────────── */
  .stats-grid {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 18px;
    margin-bottom: 22px;
  }
  @media (max-width: 1100px) {
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
  }
  .stat-card {
    background: linear-gradient(180deg, var(--bg-elev-1), var(--bg-elev-2));
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    padding: 22px 24px;
    position: relative; overflow: hidden;
    transition: transform .2s ease, border-color .2s ease;
  }
  .stat-card:hover { transform: translateY(-2px); border-color: var(--border-strong); }
  .stat-card::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0; height: 3px;
    border-radius: var(--r-md) var(--r-md) 0 0;
  }
  .stat-card.cyan::before    { background: linear-gradient(90deg, var(--cyan), transparent); }
  .stat-card.rose::before    { background: linear-gradient(90deg, var(--rose), transparent); }
  .stat-card.amber::before   { background: linear-gradient(90deg, var(--amber), transparent); }
  .stat-card.violet::before  { background: linear-gradient(90deg, var(--violet), transparent); }
  .stat-card.emerald::before { background: linear-gradient(90deg, var(--emerald), transparent); }
  .stat-card-top {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 14px;
  }
  .stat-icon {
    width: 34px; height: 34px;
    border-radius: var(--r-sm);
    display: flex; align-items: center; justify-content: center;
  }
  .stat-icon svg { width: 16px; height: 16px; }
  .stat-icon.cyan    { background: rgba(34,211,238,0.10); color: var(--cyan); }
  .stat-icon.rose    { background: rgba(244,63,94,0.10); color: var(--rose); }
  .stat-icon.amber   { background: rgba(245,158,11,0.10); color: var(--amber); }
  .stat-icon.violet  { background: rgba(167,139,250,0.10); color: var(--violet); }
  .stat-icon.emerald { background: rgba(16,185,129,0.10); color: var(--emerald); }
  .stat-label { font-size: 11px; color: var(--text-faint); letter-spacing: .8px; text-transform: uppercase; }
  .stat-num {
    font-family: var(--font-mono); font-size: 34px; font-weight: 600;
    line-height: 1; color: var(--text);
  }
  .stat-sub {
    font-size: 11.5px; color: var(--text-muted); margin-top: 10px;
    font-family: var(--font-mono);
    display: flex; align-items: center; gap: 6px;
  }
  .stat-sub svg { width: 12px; height: 12px; }

  /* ── Feature grid ───────────────────────────────── */
  .feature-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
  .feature-card {
    background: var(--bg-elev-1);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    padding: 22px;
    display: flex; flex-direction: column; gap: 14px;
    transition: all .2s ease;
    position: relative; overflow: hidden;
  }
  .feature-card::before {
    content: ''; position: absolute;
    top: 0; left: 0; right: 0; height: 2px;
    background: var(--border-strong);
    opacity: 0;
    transition: opacity .2s ease;
  }
  .feature-card.enabled {
    border-color: rgba(16,185,129,0.30);
    background: linear-gradient(180deg, rgba(16,185,129,0.04), var(--bg-elev-1));
  }
  .feature-card.enabled::before { background: var(--emerald); opacity: 1; }
  .feature-icon-wrap {
    width: 42px; height: 42px;
    border-radius: var(--r-md);
    background: var(--bg-elev-3);
    display: flex; align-items: center; justify-content: center;
    color: var(--text-muted);
    transition: all .2s ease;
  }
  .feature-icon-wrap svg { width: 20px; height: 20px; }
  .feature-card.enabled .feature-icon-wrap {
    background: rgba(16,185,129,0.10);
    color: var(--emerald);
  }
  .feature-label { font-size: 14px; font-weight: 600; color: var(--text); }
  .feature-desc { font-size: 12.5px; color: var(--text-muted); line-height: 1.55; }
  .feature-footer { display: flex; align-items: center; justify-content: space-between; margin-top: 4px; }
  .feature-status {
    font-family: var(--font-mono); font-size: 11px;
    display: flex; align-items: center; gap: 6px;
  }
  .feature-status::before {
    content: ''; width: 6px; height: 6px; border-radius: 50%;
  }
  .feature-status.on  { color: var(--emerald); }
  .feature-status.on::before  { background: var(--emerald); box-shadow: 0 0 6px var(--emerald-glow); }
  .feature-status.off { color: var(--text-faint); }
  .feature-status.off::before { background: var(--text-faint); }

  /* ── Toggle ─────────────────────────────────────── */
  .toggle-track {
    width: 40px; height: 22px;
    background: var(--bg-elev-3); border: 1px solid var(--border);
    border-radius: 99px;
    position: relative; cursor: pointer;
    transition: all .2s ease;
    flex-shrink: 0;
  }
  .toggle-track:hover { border-color: var(--border-strong); }
  .toggle-track.on {
    background: var(--emerald); border-color: var(--emerald);
    box-shadow: 0 0 12px rgba(16,185,129,0.30);
  }
  .toggle-thumb {
    position: absolute; top: 2px; left: 2px;
    width: 16px; height: 16px; border-radius: 50%;
    background: #fff; transition: transform .25s cubic-bezier(.4,.0,.2,1);
    box-shadow: 0 1px 3px rgba(0,0,0,0.3);
  }
  .toggle-track.on .toggle-thumb { transform: translateX(18px); }

  /* ── Flood ──────────────────────────────────────── */
  .flood-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
  .flood-card {
    background: var(--bg-elev-1);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    padding: 22px;
    display: flex; flex-direction: column; gap: 14px;
    transition: all .2s ease;
    position: relative; overflow: hidden;
  }
  .flood-card.enabled {
    border-color: rgba(16,185,129,0.30);
    background: linear-gradient(180deg, rgba(16,185,129,0.04), var(--bg-elev-1));
  }
  .flood-card.enabled::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: var(--emerald);
  }
  .flood-icon-wrap {
    width: 42px; height: 42px;
    border-radius: var(--r-md);
    display: flex; align-items: center; justify-content: center;
  }
  .flood-icon-wrap svg { width: 20px; height: 20px; }
  .flood-icon-wrap.cyan  { background: rgba(34,211,238,0.10); color: var(--cyan); }
  .flood-icon-wrap.amber { background: rgba(245,158,11,0.10); color: var(--amber); }
  .flood-icon-wrap.rose  { background: rgba(244,63,94,0.10); color: var(--rose); }
  .flood-title { font-size: 14px; font-weight: 600; color: var(--text); }
  .flood-limits { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .flood-limit-item {
    background: var(--bg-elev-2);
    border: 1px solid var(--border-subtle);
    border-radius: var(--r-sm);
    padding: 9px 12px;
  }
  .flood-limit-label {
    font-size: 9.5px; color: var(--text-faint);
    text-transform: uppercase; letter-spacing: 1px;
  }
  .flood-limit-val {
    font-family: var(--font-mono); font-size: 16px; font-weight: 600;
    color: var(--text); margin-top: 2px;
  }
  .flood-limit-val small { font-size: 10px; color: var(--text-faint); font-weight: 400; }
  .flood-edit {
    display: flex; flex-direction: column; gap: 8px;
    padding: 12px; background: var(--bg-elev-2);
    border: 1px solid var(--border); border-radius: var(--r-sm);
  }

  /* ── Flood summary (mini) ─────────────────────── */
  .flood-mini-list { display: flex; flex-direction: column; gap: 12px; }
  .flood-mini-row {
    display: flex; align-items: center; gap: 14px;
    padding: 14px 16px;
    background: var(--bg-elev-2);
    border: 1px solid var(--border-subtle);
    border-radius: var(--r-sm);
    transition: border-color .2s ease;
  }
  .flood-mini-row.on {
    border-color: rgba(16,185,129,0.25);
    background: rgba(16,185,129,0.04);
  }
  .flood-mini-icon {
    width: 36px; height: 36px;
    border-radius: var(--r-sm);
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
  }
  .flood-mini-icon svg { width: 18px; height: 18px; }
  .flood-mini-info { flex: 1; min-width: 0; }
  .flood-mini-label { font-size: 13.5px; font-weight: 600; color: var(--text); }
  .flood-mini-rates {
    font-family: var(--font-mono); font-size: 11px;
    color: var(--text-muted); margin-top: 3px;
  }
  .flood-mini-rates b { color: var(--text); font-weight: 500; }

  /* ── Top IPs rank ───────────────────────────────── */
  .ip-rank-list { display: flex; flex-direction: column; gap: 14px; }
  .ip-rank {
    display: flex; align-items: center; gap: 14px;
  }
  .ip-rank-num {
    width: 26px; height: 26px; flex-shrink: 0;
    background: var(--bg-elev-3); border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);
    font-weight: 700;
  }
  .ip-rank:nth-child(1) .ip-rank-num { background: rgba(244,63,94,0.12); color: var(--rose); }
  .ip-rank:nth-child(2) .ip-rank-num { background: rgba(245,158,11,0.12); color: var(--amber); }
  .ip-rank:nth-child(3) .ip-rank-num { background: rgba(34,211,238,0.12); color: var(--cyan); }
  .ip-rank-info { flex: 1; min-width: 0; }
  .ip-rank-ip {
    font-family: var(--font-mono); font-size: 13.5px;
    color: var(--text); margin-bottom: 6px;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .ip-rank-bar {
    height: 4px; background: var(--bg-elev-3);
    border-radius: 2px; overflow: hidden;
  }
  .ip-rank-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--cyan), var(--violet));
    border-radius: 2px;
    transition: width .4s ease;
  }
  .ip-rank-count {
    font-family: var(--font-mono); font-size: 13px;
    color: var(--text); font-weight: 600;
    min-width: 36px; text-align: right;
  }
  .empty-pad {
    padding: 48px 24px; text-align: center;
    color: var(--text-faint); font-family: var(--font-mono); font-size: 12px;
    display: flex; flex-direction: column; align-items: center; gap: 12px;
  }
  .empty-pad svg { width: 28px; height: 28px; opacity: .5; }

  /* ── Table ─────────────────────────────────────── */
  .tbl { width: 100%; border-collapse: collapse; font-size: 13px; }
  .tbl th {
    text-align: left; padding: 12px 18px;
    font-size: 10px; letter-spacing: 1.2px; text-transform: uppercase;
    color: var(--text-faint); border-bottom: 1px solid var(--border-subtle);
    font-weight: 600;
  }
  .tbl td {
    padding: 13px 18px; border-bottom: 1px solid var(--border-subtle);
    transition: background .15s ease;
  }
  .tbl tr:last-child td { border-bottom: none; }
  .tbl tr:hover td { background: rgba(255,255,255,0.02); }
  .mono { font-family: var(--font-mono); }
  .note-text { color: var(--text-muted); font-size: 12.5px; }
  .ts-text { font-family: var(--font-mono); font-size: 11px; color: var(--text-faint); }
  .empty-row td {
    text-align: center; color: var(--text-faint);
    padding: 56px; font-family: var(--font-mono); font-size: 12px;
  }

  /* ── Inputs ────────────────────────────────────── */
  .input-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .inp {
    background: var(--bg-elev-2);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 10px 14px;
    font-family: var(--font-mono); font-size: 13px;
    outline: none; border-radius: var(--r-sm);
    transition: all .15s ease;
  }
  .inp:focus {
    border-color: var(--cyan);
    box-shadow: 0 0 0 3px rgba(34,211,238,0.12);
  }
  .inp::placeholder { color: var(--text-faint); }
  .inp-ip   { width: 200px; }
  .inp-port { width: 120px; }
  .inp-note { flex: 1; min-width: 180px; }

  /* ── Buttons ───────────────────────────────────── */
  .btn {
    padding: 10px 16px;
    font-weight: 600; font-size: 12.5px;
    cursor: pointer;
    border: 1px solid; transition: all .15s ease;
    border-radius: var(--r-sm);
    display: inline-flex; align-items: center; gap: 6px;
    white-space: nowrap;
  }
  .btn:disabled { opacity: .4; cursor: not-allowed; }
  .btn:active:not(:disabled) { transform: translateY(1px); }
  .btn svg { width: 14px; height: 14px; }
  .btn-primary {
    background: linear-gradient(180deg, var(--cyan), var(--cyan-deep));
    color: #07090d; border-color: var(--cyan);
    box-shadow: 0 0 12px rgba(34,211,238,0.20);
  }
  .btn-primary:hover:not(:disabled) {
    box-shadow: 0 0 22px rgba(34,211,238,0.40);
    transform: translateY(-1px);
  }
  .btn-danger {
    background: rgba(244,63,94,0.06);
    color: var(--rose); border-color: rgba(244,63,94,0.30);
  }
  .btn-danger:hover:not(:disabled) {
    background: rgba(244,63,94,0.14); border-color: var(--rose);
  }
  .btn-ghost {
    background: var(--bg-elev-2);
    color: var(--text-muted); border-color: var(--border);
  }
  .btn-ghost:hover:not(:disabled) {
    color: var(--text); border-color: var(--border-strong);
  }
  .btn-edit {
    background: rgba(34,211,238,0.06);
    color: var(--cyan); border-color: rgba(34,211,238,0.30);
  }
  .btn-edit:hover:not(:disabled) {
    background: rgba(34,211,238,0.12); border-color: var(--cyan);
  }
  .btn-sm { padding: 6px 11px; font-size: 11px; }

  .badge-count {
    background: var(--bg-elev-3);
    color: var(--text-muted);
    font-size: 11px; font-family: var(--font-mono);
    padding: 3px 11px; min-width: 30px; text-align: center;
    border-radius: 999px; border: 1px solid var(--border);
  }

  .well-known-btns { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 14px; }
  .chip {
    padding: 5px 12px;
    background: var(--bg-elev-2);
    color: var(--text-muted);
    border: 1px solid var(--border);
    border-radius: 999px;
    font-family: var(--font-mono); font-size: 11px;
    cursor: pointer; transition: all .15s ease;
  }
  .chip:hover { color: var(--cyan); border-color: rgba(34,211,238,0.40); }

  /* ── Logs ──────────────────────────────────────── */
  .log-wrap {
    height: 540px; overflow-y: auto;
    background: var(--bg-base);
    border-top: 1px solid var(--border-subtle);
  }
  .log-wrap.compact { height: 380px; }

  .log-line {
    display: flex; align-items: baseline; gap: 14px;
    padding: 9px 20px;
    border-bottom: 1px solid rgba(255,255,255,0.02);
    font-family: var(--font-mono); font-size: 12px;
    animation: slideIn .25s ease;
  }
  .log-line:hover { background: rgba(255,255,255,0.02); }
  @keyframes slideIn {
    from { opacity: 0; transform: translateY(-4px); }
    to   { opacity: 1; transform: none; }
  }
  .log-ts { color: var(--text-faint); flex-shrink: 0; width: 78px; }
  .log-badge {
    flex-shrink: 0; padding: 2px 9px;
    font-size: 10px; letter-spacing: .8px;
    text-transform: uppercase; min-width: 80px; text-align: center;
    border-radius: var(--r-sm);
    font-weight: 600;
  }
  .log-badge.blacklist { background: rgba(244,63,94,0.12);  color: var(--rose); }
  .log-badge.ping      { background: rgba(245,158,11,0.12); color: var(--amber); }
  .log-badge.port       { background: rgba(34,211,238,0.12); color: var(--cyan); }
  .log-body { color: var(--text); flex: 1; min-width: 0; }
  .log-empty {
    padding: 80px 24px; text-align: center;
    color: var(--text-faint);
    font-family: var(--font-mono); font-size: 12px;
    display: flex; flex-direction: column; align-items: center; gap: 14px;
  }
  .log-empty svg { width: 32px; height: 32px; opacity: .4; }

  .log-controls { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .filter-btn {
    padding: 5px 12px;
    font-family: var(--font-mono); font-size: 10.5px;
    letter-spacing: .8px; text-transform: uppercase;
    cursor: pointer;
    border: 1px solid var(--border);
    background: var(--bg-elev-2);
    color: var(--text-muted);
    transition: all .15s ease;
    border-radius: var(--r-sm);
  }
  .filter-btn:hover { color: var(--text); }
  .filter-btn.active {
    color: #07090d;
    background: linear-gradient(180deg, var(--cyan), var(--cyan-deep));
    border-color: var(--cyan);
    box-shadow: var(--glow-cyan);
  }
  .checkbox-label {
    display: flex; align-items: center; gap: 6px;
    font-size: 11px; color: var(--text-muted); cursor: pointer;
    user-select: none; font-family: var(--font-mono);
  }
  .checkbox-label input { accent-color: var(--cyan); cursor: pointer; }

  /* ── Login ─────────────────────────────────────── */
  .login-wrap {
    min-height: 100vh; height: 100vh;
    display: flex; align-items: center; justify-content: center;
    background: var(--bg-base);
    padding: 40px 20px;
    position: relative; overflow: hidden;
  }
  .login-wrap::before {
    content: ''; position: absolute; inset: 0;
    background:
      radial-gradient(circle at 20% 30%, rgba(34,211,238,0.10), transparent 40%),
      radial-gradient(circle at 80% 70%, rgba(167,139,250,0.08), transparent 40%);
    pointer-events: none;
  }
  .login-wrap::after {
    content: ''; position: absolute; inset: 0;
    background-image:
      linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px);
    background-size: 48px 48px;
    pointer-events: none;
  }
  .login-box {
    background: linear-gradient(180deg, var(--bg-elev-1), var(--bg-elev-2));
    border: 1px solid var(--border);
    width: 420px; padding: 44px;
    border-radius: var(--r-lg);
    box-shadow: var(--shadow-lg), var(--glow-cyan);
    position: relative; z-index: 1;
  }
  .login-brand {
    display: flex; align-items: center; gap: 14px; margin-bottom: 32px;
  }
  .login-brand .brand-logo { width: 46px; height: 46px; }
  .login-brand .brand-logo svg { width: 24px; height: 24px; }
  .login-title {
    font-family: var(--font-mono); font-size: 11px;
    letter-spacing: 2px; text-transform: uppercase; color: var(--cyan);
    margin-bottom: 4px;
  }
  .login-h { font-size: 22px; font-weight: 700; color: var(--text); }
  .form-group { margin-bottom: 18px; }
  .form-label {
    display: block; font-size: 11px; letter-spacing: .8px;
    color: var(--text-muted); margin-bottom: 8px; font-weight: 500;
  }
  .form-inp {
    width: 100%; background: var(--bg-elev-2);
    border: 1px solid var(--border); color: var(--text);
    padding: 12px 14px;
    font-family: var(--font-mono); font-size: 14px;
    outline: none; border-radius: var(--r-sm);
    transition: all .15s ease;
  }
  .form-inp:focus {
    border-color: var(--cyan);
    box-shadow: 0 0 0 3px rgba(34,211,238,0.12);
  }
  .btn-login {
    width: 100%; padding: 13px;
    background: linear-gradient(180deg, var(--cyan), var(--cyan-deep));
    color: #07090d; border: none;
    font-weight: 700; font-size: 13.5px; letter-spacing: 1px;
    cursor: pointer; margin-top: 8px;
    border-radius: var(--r-sm);
    box-shadow: 0 0 20px rgba(34,211,238,0.25);
    transition: all .15s ease;
    display: flex; align-items: center; justify-content: center; gap: 8px;
  }
  .btn-login:hover:not(:disabled) {
    box-shadow: 0 0 32px rgba(34,211,238,0.50);
    transform: translateY(-1px);
  }
  .btn-login:disabled { opacity: .5; cursor: not-allowed; }
  .err-msg {
    color: var(--rose);
    background: rgba(244,63,94,0.08);
    border: 1px solid rgba(244,63,94,0.25);
    padding: 10px 13px; border-radius: var(--r-sm);
    font-size: 12px; font-family: var(--font-mono);
    margin-top: 14px;
    display: flex; align-items: center; gap: 8px;
  }
  .err-msg svg { width: 14px; height: 14px; flex-shrink: 0; }

  /* ── Modal ─────────────────────────────────────── */
  .modal-overlay {
    position: fixed; inset: 0; z-index: 100;
    background: rgba(7,9,13,0.78); backdrop-filter: blur(6px);
    display: flex; align-items: center; justify-content: center;
    animation: fadeIn .15s ease;
    padding: 20px;
  }
  @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
  .modal {
    background: linear-gradient(180deg, var(--bg-elev-1), var(--bg-elev-2));
    border: 1px solid rgba(244,63,94,0.30);
    border-radius: var(--r-lg);
    width: 460px; padding: 36px;
    box-shadow: var(--shadow-lg), 0 0 32px rgba(244,63,94,0.15);
    animation: scaleIn .2s cubic-bezier(.4,.0,.2,1);
  }
  @keyframes scaleIn {
    from { opacity: 0; transform: scale(.95); }
    to   { opacity: 1; transform: scale(1); }
  }
  .modal-icon {
    width: 50px; height: 50px;
    border-radius: var(--r-md);
    background: rgba(244,63,94,0.10);
    display: flex; align-items: center; justify-content: center;
    margin-bottom: 18px;
    color: var(--rose);
  }
  .modal-icon svg { width: 24px; height: 24px; }
  .modal-title {
    font-size: 18px; font-weight: 700;
    color: var(--text); margin-bottom: 10px;
  }
  .modal-body {
    font-size: 13.5px; color: var(--text-muted);
    line-height: 1.6; margin-bottom: 26px;
  }
  .modal-actions { display: flex; gap: 10px; }
  .modal-actions .btn { flex: 1; justify-content: center; padding: 12px; font-size: 13px; }
`;

function injectCSS(css) {
  if (document.getElementById("fw-styles")) return;
  const el = document.createElement("style");
  el.id = "fw-styles";
  el.textContent = css;
  document.head.appendChild(el);
}

/* ════════════════════════════════════════════════════════════════════
   ICONS — inline SVG
════════════════════════════════════════════════════════════════════ */
const Icon = {
  shield: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  layout: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>,
  zap: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>,
  ban: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>,
  lock: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
  activity: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
  power: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>,
  logout: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>,
  plus: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>,
  trash: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>,
  edit: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>,
  check: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>,
  x: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>,
  alert: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  arrowRight: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>,
  droplet: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2.69l5.66 5.66a8 8 0 1 1-11.31 0z"/></svg>,
  target: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>,
  link: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>,
  inbox: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>,
  globe: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>,
  clock: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>,
  trending: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>,
};

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

function fmtTime(ts) {
  const d = new Date(ts);
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map(n => String(n).padStart(2, "0")).join(":");
}

function fmtDate(ts) {
  return ts?.slice(0, 16).replace("T", " ") || "—";
}

/* ════════════════════════════════════════════════════════════════════
   LOGIN PAGE
════════════════════════════════════════════════════════════════════ */
function LoginPage({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError(""); setLoading(true);
    try {
      const data = await apiFetch("/api/login", { method: "POST", body: { username, password } });
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
        <div className="login-brand">
          <div className="brand-logo">{Icon.shield}</div>
          <div>
            <div className="login-title">XDP Firewall</div>
            <div className="login-h">Sign in</div>
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Username</label>
          <input
            className="form-inp"
            value={username}
            onChange={e => setUsername(e.target.value)}
            placeholder="admin"
            autoFocus
          />
        </div>
        <div className="form-group">
          <label className="form-label">Password</label>
          <input
            className="form-inp"
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="••••••••"
          />
        </div>
        {error && <div className="err-msg">{Icon.alert}{error}</div>}
        <button className="btn-login" type="submit" disabled={loading || !username || !password}>
          {loading ? "Authenticating…" : <>Continue {Icon.arrowRight}</>}
        </button>
      </form>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   CONFIRM MODAL
════════════════════════════════════════════════════════════════════ */
function ConfirmModal({ title, message, confirmLabel = "Confirm", onConfirm, onCancel, loading }) {
  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && !loading && onCancel()}>
      <div className="modal">
        <div className="modal-icon">{Icon.alert}</div>
        <div className="modal-title">{title}</div>
        <div className="modal-body">{message}</div>
        <div className="modal-actions">
          <button className="btn btn-ghost" onClick={onCancel} disabled={loading}>Cancel</button>
          <button className="btn btn-danger" onClick={onConfirm} disabled={loading}>
            {loading ? "Stopping…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   STATS PANEL — top row of dashboard
════════════════════════════════════════════════════════════════════ */
function StatsPanel({ stats, fwOnline, blacklistCount, portsCount }) {
  const byType = Object.fromEntries((stats?.byType || []).map(r => [r.event_type, r.c]));
  const cards = [
    {
      tone: "violet", icon: Icon.activity,
      label: "Total Blocked", value: stats?.total ?? 0,
      sub: <><span style={{ color: "var(--emerald)" }}>{stats?.last24h ?? 0}</span> in last 24h</>,
    },
    {
      tone: "rose", icon: Icon.ban,
      label: "Blacklisted IPs", value: blacklistCount ?? 0,
      sub: <>{byType.blacklist ?? 0} hits all-time</>,
    },
    {
      tone: "cyan", icon: Icon.lock,
      label: "Blocked Ports", value: portsCount ?? 0,
      sub: <>{byType.port ?? 0} hits all-time</>,
    },
    {
      tone: fwOnline ? "emerald" : "amber",
      icon: Icon.shield,
      label: "Firewall State",
      value: fwOnline ? "ONLINE" : "OFFLINE",
      sub: fwOnline ? "loader.py connected" : "loader.py not connected",
      smallNum: true,
    },
  ];
  return (
    <div className="stats-grid">
      {cards.map(c => (
        <div key={c.label} className={`stat-card ${c.tone}`}>
          <div className="stat-card-top">
            <div className={`stat-icon ${c.tone}`}>{c.icon}</div>
            <div className="stat-label">{c.label}</div>
          </div>
          <div className="stat-num" style={c.smallNum ? { fontSize: 22, letterSpacing: 1 } : null}>
            {typeof c.value === "number" ? c.value.toLocaleString() : c.value}
          </div>
          {c.sub && <div className="stat-sub">{c.sub}</div>}
        </div>
      ))}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   FEATURES PANEL
════════════════════════════════════════════════════════════════════ */
const FEATURES = [
  { id: "blacklist", label: "IP Blacklist", icon: Icon.ban,    desc: "Drop packets from IPs in the blacklist map." },
  { id: "ping",      label: "ICMP Block",  icon: Icon.target, desc: "Drop all ICMP (ping) packets on every interface." },
  { id: "port",      label: "Port Block",  icon: Icon.lock,   desc: "Drop TCP traffic to blocked port numbers." },
];

function FeaturesPanel({ features, onToggle }) {
  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">{Icon.shield} Feature Control</span>
      </div>
      <div className="card-body">
        <div className="feature-grid">
          {FEATURES.map(f => {
            const on = !!features[f.id];
            return (
              <div key={f.id} className={`feature-card ${on ? "enabled" : ""}`}>
                <div className="feature-icon-wrap">{f.icon}</div>
                <div>
                  <div className="feature-label">{f.label}</div>
                  <div className="feature-desc">{f.desc}</div>
                </div>
                <div className="feature-footer">
                  <span className={`feature-status ${on ? "on" : "off"}`}>
                    {on ? "Active" : "Inactive"}
                  </span>
                  <div
                    className={`toggle-track ${on ? "on" : ""}`}
                    onClick={() => onToggle(f.id, !on)}
                    role="switch"
                    aria-checked={on}
                  >
                    <div className="toggle-thumb" />
                  </div>
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
   FLOOD SUMMARY (compact card on dashboard)
════════════════════════════════════════════════════════════════════ */
const FLOOD_TYPES = [
  { id: "udp_flood",  label: "UDP Flood",  icon: Icon.droplet, tone: "cyan",  desc: "Rate-limit UDP packets per source IP." },
  { id: "icmp_flood", label: "ICMP Flood", icon: Icon.target,  tone: "amber", desc: "Rate-limit ICMP echo requests." },
  { id: "syn_flood",  label: "SYN Flood",  icon: Icon.link,    tone: "rose",  desc: "Rate-limit incoming TCP SYN packets." },
];

function FloodSummary({ floodConfigs, onToggle }) {
  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">{Icon.zap} Flood Protection</span>
      </div>
      <div className="card-body">
        <div className="flood-mini-list">
          {FLOOD_TYPES.map(ft => {
            const config = floodConfigs?.find(c => c.flood_type === ft.id);
            const on = !!config?.enabled;
            return (
              <div key={ft.id} className={`flood-mini-row ${on ? "on" : ""}`}>
                <div className={`flood-mini-icon flood-icon-wrap ${ft.tone}`}>{ft.icon}</div>
                <div className="flood-mini-info">
                  <div className="flood-mini-label">{ft.label}</div>
                  <div className="flood-mini-rates">
                    Soft: <b>{config?.soft_limit ?? "—"}</b> · Hard: <b>{config?.hard_limit ?? "—"}</b> pps
                  </div>
                </div>
                <div
                  className={`toggle-track ${on ? "on" : ""}`}
                  onClick={() => onToggle(ft.id, !on)}
                  role="switch" aria-checked={on}
                >
                  <div className="toggle-thumb" />
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
   RECENT EVENTS PANEL
════════════════════════════════════════════════════════════════════ */
function RecentEventsPanel({ logs }) {
  const recent = useMemo(() => logs.slice(-12).reverse(), [logs]);

  function describe(l) {
    if (l.eventType === "blacklist") return <>Blocked IP <span style={{ color: "var(--rose)" }}>{l.ip}</span></>;
    if (l.eventType === "ping")      return <>Blocked ICMP from <span style={{ color: "var(--amber)" }}>{l.ip}</span></>;
    return <>Blocked <span>{l.ip}</span> → port <span style={{ color: "var(--cyan)" }}>:{l.port || "?"}</span></>;
  }

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">{Icon.activity} Recent Events</span>
        <span className="badge-count">{logs.length}</span>
      </div>
      <div className="card-body flush">
        {recent.length === 0 ? (
          <div className="log-empty">
            {Icon.inbox}
            <div>No events yet — waiting for traffic…</div>
          </div>
        ) : (
          <div>
            {recent.map((l, i) => (
              <div key={l.id ?? i} className="log-line">
                <span className="log-ts">{l.timestamp ? fmtTime(l.timestamp) : "??:??:??"}</span>
                <span className={`log-badge ${l.eventType}`}>{l.eventType}</span>
                <span className="log-body">{describe(l)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   TOP BLOCKED IPS
════════════════════════════════════════════════════════════════════ */
function TopIpsPanel({ logs }) {
  const top = useMemo(() => {
    const counts = {};
    for (const l of logs) {
      if (!l.ip) continue;
      counts[l.ip] = (counts[l.ip] || 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  }, [logs]);

  const max = top[0]?.[1] || 1;
  const uniqueCount = useMemo(() => {
    const s = new Set();
    for (const l of logs) if (l.ip) s.add(l.ip);
    return s.size;
  }, [logs]);

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">{Icon.trending} Top Blocked Sources</span>
        <span className="badge-count">{uniqueCount}</span>
      </div>
      <div className="card-body">
        {top.length === 0 ? (
          <div className="empty-pad">
            {Icon.globe}
            <div>No source IPs yet</div>
          </div>
        ) : (
          <div className="ip-rank-list">
            {top.map(([ip, count], i) => (
              <div key={ip} className="ip-rank">
                <div className="ip-rank-num">{i + 1}</div>
                <div className="ip-rank-info">
                  <div className="ip-rank-ip">{ip}</div>
                  <div className="ip-rank-bar">
                    <div className="ip-rank-bar-fill" style={{ width: `${(count / max) * 100}%` }} />
                  </div>
                </div>
                <div className="ip-rank-count">{count}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   BLACKLIST PANEL
════════════════════════════════════════════════════════════════════ */
function BlacklistPanel({ onChange }) {
  const [rows, setRows] = useState([]);
  const [ip, setIp] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function load() {
    try {
      const data = await apiFetch("/api/blacklist");
      setRows(data);
      onChange?.(data.length);
    } catch { }
  }

  useEffect(() => { load(); }, []);

  async function add() {
    if (!ip) return;
    setError(""); setLoading(true);
    try {
      await apiFetch("/api/blacklist", { method: "POST", body: { ip, note } });
      setIp(""); setNote("");
      await load();
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }

  async function del(id) {
    try { await apiFetch(`/api/blacklist/${id}`, { method: "DELETE" }); await load(); } catch { }
  }

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">{Icon.ban} IP Blacklist</span>
        <span className="badge-count">{rows.length}</span>
      </div>
      <div className="card-body">
        <div className="input-row" style={{ marginBottom: 16 }}>
          <input
            className="inp inp-ip" placeholder="192.168.1.100"
            value={ip} onChange={e => setIp(e.target.value)}
            onKeyDown={e => e.key === "Enter" && add()}
          />
          <input
            className="inp inp-note" placeholder="Note (optional)"
            value={note} onChange={e => setNote(e.target.value)}
            onKeyDown={e => e.key === "Enter" && add()}
          />
          <button type="button" className="btn btn-primary" onClick={add} disabled={!ip || loading}>
            {Icon.plus} Add IP
          </button>
        </div>
        {error && <div className="err-msg" style={{ marginBottom: 14 }}>{Icon.alert} {error}</div>}
        <table className="tbl">
          <thead>
            <tr><th>IP Address</th><th>Note</th><th>Added</th><th></th></tr>
          </thead>
          <tbody>
            {rows.length === 0
              ? <tr className="empty-row"><td colSpan={4}>No IPs in blacklist</td></tr>
              : rows.map(r => (
                <tr key={r.id}>
                  <td className="mono" style={{ color: "var(--rose)" }}>{r.ip}</td>
                  <td className="note-text">{r.note || "—"}</td>
                  <td className="ts-text">{fmtDate(r.created_at)}</td>
                  <td style={{ textAlign: "right" }}>
                    <button type="button" className="btn btn-danger btn-sm" onClick={() => del(r.id)}>
                      {Icon.trash} Remove
                    </button>
                  </td>
                </tr>
              ))
            }
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   PORT BLOCK PANEL
════════════════════════════════════════════════════════════════════ */
const WELL_KNOWN = [
  { port: 80, label: "HTTP" }, { port: 443, label: "HTTPS" },
  { port: 8000, label: "Dev" }, { port: 22, label: "SSH" }, { port: 3306, label: "MySQL" },
];

function PortsPanel({ onChange }) {
  const [rows, setRows] = useState([]);
  const [port, setPort] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function load() {
    try {
      const data = await apiFetch("/api/ports");
      setRows(data);
      onChange?.(data.length);
    } catch { }
  }

  useEffect(() => { load(); }, []);

  async function add() {
    if (!port) return;
    setError(""); setLoading(true);
    try {
      await apiFetch("/api/ports", { method: "POST", body: { port: Number(port), note } });
      setPort(""); setNote("");
      await load();
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }

  async function del(id) {
    try { await apiFetch(`/api/ports/${id}`, { method: "DELETE" }); await load(); } catch { }
  }

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">{Icon.lock} Port Blocklist</span>
        <span className="badge-count">{rows.length}</span>
      </div>
      <div className="card-body">
        <div className="well-known-btns">
          {WELL_KNOWN.map(w => (
            <button type="button" key={w.port} className="chip" onClick={() => setPort(String(w.port))}>
              {w.label} :{w.port}
            </button>
          ))}
        </div>
        <div className="input-row" style={{ marginBottom: 16 }}>
          <input
            className="inp inp-port" placeholder="8080"
            type="number" min="1" max="65535"
            value={port} onChange={e => setPort(e.target.value)}
            onKeyDown={e => e.key === "Enter" && add()}
          />
          <input
            className="inp inp-note" placeholder="Note (optional)"
            value={note} onChange={e => setNote(e.target.value)}
            onKeyDown={e => e.key === "Enter" && add()}
          />
          <button type="button" className="btn btn-primary" onClick={add} disabled={!port || loading}>
            {Icon.plus} Add Port
          </button>
        </div>
        {error && <div className="err-msg" style={{ marginBottom: 14 }}>{Icon.alert} {error}</div>}
        <table className="tbl">
          <thead>
            <tr><th>Port</th><th>Note</th><th>Added</th><th></th></tr>
          </thead>
          <tbody>
            {rows.length === 0
              ? <tr className="empty-row"><td colSpan={4}>No ports blocked</td></tr>
              : rows.map(r => (
                <tr key={r.id}>
                  <td className="mono" style={{ color: "var(--cyan)", fontSize: 15, fontWeight: 600 }}>:{r.port}</td>
                  <td className="note-text">{r.note || "—"}</td>
                  <td className="ts-text">{fmtDate(r.created_at)}</td>
                  <td style={{ textAlign: "right" }}>
                    <button type="button" className="btn btn-danger btn-sm" onClick={() => del(r.id)}>
                      {Icon.trash} Remove
                    </button>
                  </td>
                </tr>
              ))
            }
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   FLOOD PROTECTION PANEL (full)
════════════════════════════════════════════════════════════════════ */
function FloodPanel({ floodConfigs, onToggle, onUpdateRates }) {
  const [editingType, setEditingType] = useState(null);
  const [softLimit, setSoftLimit] = useState("");
  const [hardLimit, setHardLimit] = useState("");
  const [editError, setEditError] = useState("");
  const [saving, setSaving] = useState(false);

  function openEdit(config) {
    setEditingType(config.flood_type);
    setSoftLimit(String(config.soft_limit));
    setHardLimit(String(config.hard_limit));
    setEditError("");
  }

  function closeEdit() {
    setEditingType(null); setSoftLimit(""); setHardLimit(""); setEditError("");
  }

  async function saveRates() {
    setEditError(""); setSaving(true);
    try {
      await onUpdateRates(editingType, Number(softLimit), Number(hardLimit));
      closeEdit();
    } catch (e) { setEditError(e.message); }
    finally { setSaving(false); }
  }

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">{Icon.zap} Flood Protection</span>
      </div>
      <div className="card-body">
        <div className="flood-grid">
          {FLOOD_TYPES.map(ft => {
            const config = floodConfigs?.find(c => c.flood_type === ft.id);
            const on = !!config?.enabled;
            const isEditing = editingType === ft.id;
            return (
              <div key={ft.id} className={`flood-card ${on ? "enabled" : ""}`}>
                <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
                  <div className={`flood-icon-wrap ${ft.tone}`}>{ft.icon}</div>
                  <div
                    className={`toggle-track ${on ? "on" : ""}`}
                    onClick={() => onToggle(ft.id, !on)}
                    role="switch" aria-checked={on}
                  >
                    <div className="toggle-thumb" />
                  </div>
                </div>
                <div>
                  <div className="flood-title">{ft.label}</div>
                  <div className="feature-desc" style={{ marginTop: 4 }}>{ft.desc}</div>
                </div>
                <div className="flood-limits">
                  <div className="flood-limit-item">
                    <div className="flood-limit-label">Soft</div>
                    <div className="flood-limit-val">{config?.soft_limit ?? "—"} <small>pps</small></div>
                  </div>
                  <div className="flood-limit-item">
                    <div className="flood-limit-label">Hard</div>
                    <div className="flood-limit-val">{config?.hard_limit ?? "—"} <small>pps</small></div>
                  </div>
                </div>
                {!isEditing && (
                  <button type="button" className="btn btn-edit btn-sm" onClick={() => openEdit(config)}>
                    {Icon.edit} Edit limits
                  </button>
                )}
                {isEditing && (
                  <div className="flood-edit">
                    <input className="inp" placeholder="Soft (pps)" type="number" value={softLimit} onChange={e => setSoftLimit(e.target.value)} />
                    <input className="inp" placeholder="Hard (pps)" type="number" value={hardLimit} onChange={e => setHardLimit(e.target.value)} />
                    {editError && <div className="err-msg" style={{ fontSize: 11, padding: "6px 10px" }}>{Icon.alert} {editError}</div>}
                    <div style={{ display: "flex", gap: 6 }}>
                      <button type="button" className="btn btn-primary btn-sm" onClick={saveRates} disabled={saving} style={{ flex: 1, justifyContent: "center" }}>
                        {Icon.check} {saving ? "Saving…" : "Save"}
                      </button>
                      <button type="button" className="btn btn-ghost btn-sm" onClick={closeEdit} style={{ flex: 1, justifyContent: "center" }}>
                        {Icon.x} Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   LIVE LOGS PANEL (full screen)
════════════════════════════════════════════════════════════════════ */
function LogsPanel({ logs }) {
  const [autoScroll, setAutoScroll] = useState(true);
  const [filter, setFilter] = useState("all");
  const wrapRef = useRef(null);

  const filtered = filter === "all" ? logs : logs.filter(l => l.eventType === filter);

  // Auto-scroll within the log container only — never the page
  useEffect(() => {
    if (autoScroll && wrapRef.current) {
      wrapRef.current.scrollTop = wrapRef.current.scrollHeight;
    }
  }, [filtered.length, autoScroll]);

  function describe(l) {
    if (l.eventType === "blacklist") return <>Blocked IP <span style={{ color: "var(--rose)" }}>{l.ip}</span></>;
    if (l.eventType === "ping")      return <>Blocked ICMP ping from <span style={{ color: "var(--amber)" }}>{l.ip}</span></>;
    return <>Blocked <span>{l.ip}</span> → port <span style={{ color: "var(--cyan)" }}>:{l.port || "?"}</span></>;
  }

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">{Icon.activity} Live Event Log</span>
        <div className="log-controls">
          {["all", "blacklist", "ping", "port"].map(f => (
            <button type="button" key={f} className={`filter-btn ${filter === f ? "active" : ""}`} onClick={() => setFilter(f)}>
              {f}
            </button>
          ))}
          <label className="checkbox-label">
            <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} />
            Auto-scroll
          </label>
          <span className="badge-count">{filtered.length}</span>
        </div>
      </div>
      <div className="log-wrap" ref={wrapRef}>
        {filtered.length === 0
          ? (
            <div className="log-empty">
              {Icon.inbox}
              <div>No events — waiting for traffic…</div>
            </div>
          )
          : filtered.map((l, i) => (
            <div key={l.id ?? i} className="log-line">
              <span className="log-ts">{l.timestamp ? fmtTime(l.timestamp) : "??:??:??"}</span>
              <span className={`log-badge ${l.eventType}`}>{l.eventType}</span>
              <span className="log-body">{describe(l)}</span>
            </div>
          ))
        }
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   MAIN APP
════════════════════════════════════════════════════════════════════ */
const TABS = [
  { id: "overview",  label: "Dashboard",        icon: Icon.layout },
  { id: "flood",     label: "Flood Protection", icon: Icon.zap },
  { id: "blacklist", label: "IP Blacklist",      icon: Icon.ban },
  { id: "ports",     label: "Port Block",        icon: Icon.lock },
  { id: "logs",      label: "Live Logs",         icon: Icon.activity },
];

const PAGE_META = {
  overview:  { title: "Dashboard",        sub: "System status & live activity at a glance" },
  flood:     { title: "Flood Protection", sub: "UDP / ICMP / SYN rate limiting" },
  blacklist: { title: "IP Blacklist",     sub: "Manage blocked IP addresses" },
  ports:     { title: "Port Blocklist",   sub: "Manage blocked TCP ports" },
  logs:      { title: "Live Event Log",   sub: "Real-time packet block events" },
};

const MAIN_FEATURE_IDS = ["blacklist", "ping", "port"];
const PILL_LABELS = { blacklist: "BLACKLIST", ping: "ICMP", port: "PORT" };

export default function App() {
  injectCSS(CSS);

  const [user, setUser]                 = useState(localStorage.getItem("fw_user") || null);
  const [tab, setTab]                   = useState("overview");
  const [features, setFeatures]         = useState({});
  const [stats, setStats]               = useState(null);
  const [floodConfigs, setFloodConfigs] = useState([]);
  const [logs, setLogs]                 = useState([]);
  const [fwOnline, setFwOnline]         = useState(false);
  const [blacklistCount, setBlacklistCount] = useState(0);
  const [portsCount, setPortsCount]     = useState(0);
  const [showStopModal, setShowStopModal] = useState(false);
  const [stopping, setStopping]         = useState(false);
  const wsRef = useRef(null);

  /* ── Load initial data — each fetch is independent so one failure doesn't block others ── */
  async function loadData() {
    const safe = (p) => p.catch(() => null);
    const [f, s, fc, ls, status, bl, pt] = await Promise.all([
      safe(apiFetch("/api/features")),
      safe(apiFetch("/api/stats")),
      safe(apiFetch("/api/flood/config")),
      safe(apiFetch("/api/logs?limit=300")),
      safe(apiFetch("/api/firewall/status")),
      safe(apiFetch("/api/blacklist")),
      safe(apiFetch("/api/ports")),
    ]);
    if (f)      setFeatures(f);
    if (s)      setStats(s);
    if (fc)     setFloodConfigs(fc);
    if (ls)     setLogs(ls.map(r => ({
      id: r.id, eventType: r.event_type,
      ip: r.ip, port: r.port, timestamp: r.created_at,
    })));
    if (status) setFwOnline(status.connected);
    if (bl)     setBlacklistCount(bl.length);
    if (pt)     setPortsCount(pt.length);
  }

  /* ── WebSocket ── */
  function connectWS() {
    const token = getToken();
    if (!token) return;
    const ws = new WebSocket(`${API.replace(/^http/, "ws")}/ws?token=${token}`);
    wsRef.current = ws;

    ws.onmessage = e => {
      const msg = JSON.parse(e.data);

      if (msg.type === "state") {
        setFeatures(msg.features); // backend sends Record<string, boolean>

      } else if (msg.type === "log") {
        const entry = {
          id: `live-${Date.now()}-${Math.random()}`,
          eventType: msg.eventType,
          ip: msg.ip,
          port: msg.port ?? null,
          timestamp: msg.timestamp,
        };
        setLogs(prev => [...prev.slice(-999), entry]);
        setStats(s => {
          if (!s) return s;
          const byType = [...(s.byType || [])];
          const idx = byType.findIndex(r => r.event_type === msg.eventType);
          if (idx !== -1) byType[idx] = { ...byType[idx], c: byType[idx].c + 1 };
          else byType.push({ event_type: msg.eventType, c: 1 });
          return { ...s, total: (s.total || 0) + 1, last24h: (s.last24h || 0) + 1, byType };
        });

      } else if (msg.type === "firewall_status") {
        setFwOnline(msg.connected);
      }
    };

    ws.onclose = () => { wsRef.current = null; setTimeout(connectWS, 3000); };
    ws.onerror = () => { };
  }

  useEffect(() => {
    if (!user) return;
    loadData();
    connectWS();
    return () => { wsRef.current?.close(); wsRef.current = null; };
  }, [user]);

  /* ── Refresh blacklist/ports counts when their tabs change them ── */
  // Instead of forcing re-fetch, let the panels report counts via callback
  // (BlacklistPanel & PortsPanel call onChange after mutations)

  /* ── Toggle main feature ── */
  async function onToggle(feature, enabled) {
    setFeatures(f => ({ ...f, [feature]: enabled }));
    try {
      await apiFetch(`/api/features/${feature}`, { method: "PATCH", body: { enabled } });
    } catch {
      setFeatures(f => ({ ...f, [feature]: !enabled }));
    }
  }


  /* ── Toggle flood feature ── */
  async function onToggleFlood(floodType, enabled) {
    setFloodConfigs(prev => {
      const found = prev.find(c => c.flood_type === floodType);
      if (found) return prev.map(c => c.flood_type === floodType ? { ...c, enabled } : c);
      // If config wasn't loaded yet, add a placeholder so the toggle responds
      return [...prev, { flood_type: floodType, enabled, soft_limit: 0, hard_limit: 0 }];
    });
    try {
      await apiFetch(`/api/flood/config/${floodType}/enabled`, { method: "PATCH", body: { enabled } });
      // Re-fetch authoritative flood state after toggle to ensure rates are in sync
      const fc = await apiFetch("/api/flood/config");
      if (fc) setFloodConfigs(fc);
    } catch {
      setFloodConfigs(prev => prev.map(c => c.flood_type === floodType ? { ...c, enabled: !enabled } : c));
    }
  }

  /* ── Update flood rate limits ── */
  async function onUpdateFloodRates(floodType, softLimit, hardLimit) {
    setFloodConfigs(prev => prev.map(c => c.flood_type === floodType ? { ...c, soft_limit: softLimit, hard_limit: hardLimit } : c));
    try {
      await apiFetch(`/api/flood/config/${floodType}/rates`, { method: "PATCH", body: { soft_limit: softLimit, hard_limit: hardLimit } });
    } catch (e) {
      await loadData();
      throw e;
    }
  }

  /* ── Stop firewall ── */
  async function onStopFirewall() {
    setStopping(true);
    try {
      await apiFetch("/api/firewall/shutdown", { method: "POST" });
      setShowStopModal(false);
    } catch (e) {
      alert(`Failed to send shutdown: ${e.message}`);
    } finally {
      setStopping(false);
    }
  }

  /* ── Auth ── */
  function handleLogin(u) { setUser(u); }
  function handleLogout() {
    localStorage.removeItem("fw_token");
    localStorage.removeItem("fw_user");
    wsRef.current?.close();
    setUser(null);
  }

  if (!user) return <LoginPage onLogin={handleLogin} />;

  const meta = PAGE_META[tab];
  const userInitial = (user || "?").charAt(0).toUpperCase();

  return (
    <div className="layout">
      {showStopModal && (
        <ConfirmModal
          title={fwOnline ? "Stop firewall?" : "Firewall appears offline"}
          message={
            fwOnline
              ? "This sends a shutdown signal to the XDP loader and detaches the program from all interfaces. Network traffic will be unprotected until the firewall is manually restarted."
              : "The firewall does not appear to be connected. Sending a shutdown signal anyway — it will take effect if loader.py is still running."
          }
          confirmLabel={fwOnline ? "Stop firewall" : "Send signal anyway"}
          onConfirm={onStopFirewall}
          onCancel={() => !stopping && setShowStopModal(false)}
          loading={stopping}
        />
      )}

      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-logo">{Icon.shield}</div>
          <div className="brand-text">
            <div className="brand-name">XDP Firewall</div>
            <div className="brand-tag">v1.0 · eBPF</div>
          </div>
        </div>

        <div className={`status-banner ${fwOnline ? "online" : "offline"}`}>
          <div className="pulse-wrap">
            <div className={`pulse-dot ${fwOnline ? "green" : "red"}`} />
            {fwOnline && <div className="pulse-ring" />}
          </div>
          <div>
            <div className="status-text">{fwOnline ? "Firewall online" : "Firewall offline"}</div>
            <div className="status-label">{fwOnline ? "loader.py connected" : "no loader connection"}</div>
          </div>
        </div>

        <nav className="nav">
          <div className="nav-group-label">Navigation</div>
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

        <div className="stop-fw-wrap">
          <button
            type="button"
            className="btn-stop-fw"
            onClick={() => setShowStopModal(true)}
            title={fwOnline ? "Stop the XDP firewall" : "Send shutdown signal"}
          >
            {Icon.power} {fwOnline ? "Stop Firewall" : "Force Stop"}
          </button>
        </div>

        <div className="user-card">
          <div className="user-avatar">{userInitial}</div>
          <div className="user-info">
            <div className="user-name">{user}</div>
            <div className="user-role">Administrator</div>
          </div>
          <button type="button" className="icon-btn" onClick={handleLogout} title="Logout">
            {Icon.logout}
          </button>
        </div>
      </aside>

      {/* ── Main ── */}
      <div className="main">
        <div className="topbar">
          <div>
            <div className="page-title">{meta.title}</div>
            <div className="page-sub">{meta.sub}</div>
          </div>
          <div className="feature-pills">
            {MAIN_FEATURE_IDS.map(id => (
              <span key={id} className={`pill ${features[id] ? "on" : "off"}`}>
                {PILL_LABELS[id]}
              </span>
            ))}
          </div>
        </div>

        <div className="content">
          {tab === "overview" && (
            <>
              <StatsPanel
                stats={stats}
                fwOnline={fwOnline}
                blacklistCount={blacklistCount}
                portsCount={portsCount}
                onNavigate={setTab}
              />

              <div className="dash-row cols-2">
                <FeaturesPanel features={features} onToggle={onToggle} />
                <FloodSummary floodConfigs={floodConfigs} onToggle={onToggleFlood} onManage={() => setTab("flood")} />
              </div>

              <div className="dash-row cols-2-asym">
                <RecentEventsPanel logs={logs} onViewAll={() => setTab("logs")} />
                <TopIpsPanel logs={logs} onViewAll={() => setTab("logs")} />
              </div>
            </>
          )}
          {tab === "flood" && (
            <FloodPanel floodConfigs={floodConfigs} onToggle={onToggleFlood} onUpdateRates={onUpdateFloodRates} />
          )}
          {tab === "blacklist" && <BlacklistPanel onChange={setBlacklistCount} />}
          {tab === "ports"     && <PortsPanel onChange={setPortsCount} />}
          {tab === "logs"      && <LogsPanel logs={logs} onClear={() => setLogs([])} />}
        </div>
      </div>
    </div>
  );
}
