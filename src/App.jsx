import { useState, useRef, useCallback } from "react";

// ─── Models ───────────────────────────────────────────────────────────────────
const MODELS = [
  { id: "claude-opus-4-6",           name: "Opus 4.6",   color: "#e879f9", cost: { in: 0.015,   out: 0.075   } },
  { id: "claude-sonnet-4-6",         name: "Sonnet 4.6", color: "#38bdf8", cost: { in: 0.003,   out: 0.015   } },
  { id: "claude-haiku-4-5-20251001", name: "Haiku 4.5",  color: "#4ade80", cost: { in: 0.00025, out: 0.00125 } },
];

// ─── Tier fingerprints (Anthropic rate-limit tiers) ───────────────────────────
// RPM / TPM limits sourced from: https://docs.anthropic.com/en/api/rate-limits
const TIERS = [
  {
    tier: "Free Tier",
    badge: "FREE",
    color: "#9ca3af", bg: "#111827", border: "#374151",
    rpmMin: 1,    rpmMax: 5,
    tpmMin: 1,    tpmMax: 25000,
    icon: "○",
    desc: "No credit card on file. Very limited access, testing only.",
  },
  {
    tier: "Build – Tier 1",
    badge: "TIER 1",
    color: "#34d399", bg: "#022c22", border: "#065f46",
    rpmMin: 50,   rpmMax: 50,
    tpmMin: 50000, tpmMax: 50000,
    icon: "◐",
    desc: "Minimum $5 credit purchase. Entry-level paid access.",
  },
  {
    tier: "Build – Tier 2",
    badge: "TIER 2",
    color: "#38bdf8", bg: "#082f49", border: "#0369a1",
    rpmMin: 1000, rpmMax: 1000,
    tpmMin: 100000, tpmMax: 100000,
    icon: "◑",
    desc: "$50+ spend or 30 days after first payment.",
  },
  {
    tier: "Build – Tier 3",
    badge: "TIER 3",
    color: "#a78bfa", bg: "#1e1b4b", border: "#6d28d9",
    rpmMin: 2000, rpmMax: 2000,
    tpmMin: 200000, tpmMax: 200000,
    icon: "◕",
    desc: "$250+ cumulative spend.",
  },
  {
    tier: "Build – Tier 4",
    badge: "TIER 4",
    color: "#fb923c", bg: "#1c0a00", border: "#9a3412",
    rpmMin: 4000, rpmMax: 4000,
    tpmMin: 400000, tpmMax: 400000,
    icon: "●",
    desc: "$1,000+ cumulative spend.",
  },
  {
    tier: "Scale / Enterprise",
    badge: "ENTERPRISE",
    color: "#fbbf24", bg: "#1a1200", border: "#b45309",
    rpmMin: 4001, rpmMax: Infinity,
    tpmMin: 400001, tpmMax: Infinity,
    icon: "★",
    desc: "Custom limits negotiated with Anthropic sales.",
  },
];

function detectTier(rpm, tpm) {
  if (!rpm && !tpm) return null;
  for (const t of TIERS) {
    const rpmOk = rpm == null || (rpm >= t.rpmMin && rpm <= t.rpmMax);
    const tpmOk = tpm == null || (tpm >= t.tpmMin && tpm <= t.tpmMax);
    if (rpmOk && tpmOk) return t;
  }
  if (rpm != null && rpm > 4000) return TIERS[5];
  return { tier: "Unknown", badge: "UNKNOWN", color: "#6b7280", bg: "#111", border: "#374151", icon: "?", desc: "Could not match to a known Anthropic tier." };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
const PRESETS = [
  "Respond with exactly: PONG",
  "List 3 HTTP status codes and their meanings.",
  "What is your model name and version?",
  "Explain SQL injection in one sentence.",
  "Generate a UUID v4 format example.",
];

function calcCost(modelId, inp, out) {
  const m = MODELS.find(m => m.id === modelId);
  if (!m) return 0;
  return (inp / 1000) * m.cost.in + (out / 1000) * m.cost.out;
}
const fmt     = n => n?.toLocaleString() ?? "0";
const fmtCost = n => n < 0.000001 ? "<$0.000001" : `$${n.toFixed(6)}`;

// ─── Component ────────────────────────────────────────────────────────────────
export default function App() {
  const [key,         setKey]         = useState("");
  const [keyMasked,   setKeyMasked]   = useState(true);
  const [keyState,    setKeyState]    = useState("idle"); // idle | checking | valid | invalid
  const [planInfo,    setPlanInfo]    = useState(null);   // detected tier info
  const [rlRaw,       setRlRaw]       = useState(null);   // raw rate-limit headers
  const [model,       setModel]       = useState("claude-sonnet-4-6");
  const [prompt,      setPrompt]      = useState("");
  const [maxTokens,   setMaxTokens]   = useState(512);
  const [temp,        setTemp]        = useState(1.0);
  const [running,     setRunning]     = useState(false);
  const [log,         setLog]         = useState([]);
  const [stats,       setStats]       = useState({ calls: 0, inputTok: 0, outputTok: 0, cost: 0, errors: 0 });
  const [activeTab,   setActiveTab]   = useState("test");
  const logRef = useRef(null);

  const addLog = useCallback(entry => setLog(prev => [entry, ...prev].slice(0, 100)), []);

  // ── Validate key + detect plan tier ────────────────────────────────────────
  const validateKey = async () => {
    if (!key.trim()) return;
    setKeyState("checking");
    setPlanInfo(null);
    setRlRaw(null);
    try {
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": key.trim(),
          "anthropic-version": "2023-06-01",
          "anthropic-dangerous-direct-browser-access": "true",
        },
        body: JSON.stringify({
          model: "claude-haiku-4-5-20251001",
          max_tokens: 5,
          messages: [{ role: "user", content: "ping" }],
        }),
      });

      if (r.ok) {
        // Capture all rate-limit headers
        const rl = {};
        [
          "anthropic-ratelimit-requests-limit",
          "anthropic-ratelimit-requests-remaining",
          "anthropic-ratelimit-requests-reset",
          "anthropic-ratelimit-tokens-limit",
          "anthropic-ratelimit-tokens-remaining",
          "anthropic-ratelimit-tokens-reset",
          "anthropic-ratelimit-input-tokens-limit",
          "anthropic-ratelimit-input-tokens-remaining",
          "anthropic-ratelimit-output-tokens-limit",
          "anthropic-ratelimit-output-tokens-remaining",
          "request-id",
        ].forEach(h => { const v = r.headers.get(h); if (v) rl[h] = v; });
        setRlRaw(rl);

        const rpm = parseInt(rl["anthropic-ratelimit-requests-limit"]) || null;
        const tpm = parseInt(rl["anthropic-ratelimit-tokens-limit"])   || null;
        const tier = detectTier(rpm, tpm);
        setPlanInfo({ ...tier, rpm, tpm });
        setKeyState("valid");

        addLog({
          type: "sys",
          msg: `Key valid ✓  |  Tier: ${tier?.tier ?? "unknown"}  |  ${rpm ?? "?"} RPM  /  ${tpm?.toLocaleString() ?? "?"} TPM`,
          ts: new Date(),
        });
      } else {
        const d = await r.json();
        setKeyState("invalid");
        addLog({ type: "err", msg: `Validation failed: ${d?.error?.message || r.status}`, ts: new Date() });
      }
    } catch (e) {
      setKeyState("invalid");
      addLog({ type: "err", msg: `Network error: ${e.message}`, ts: new Date() });
    }
  };

  // ── Send prompt ─────────────────────────────────────────────────────────────
  const sendPrompt = async () => {
    if (!key.trim() || !prompt.trim() || running) return;
    setRunning(true);
    const t0 = performance.now();
    const m = MODELS.find(m => m.id === model);
    addLog({ type: "req", msg: `→ ${m.name} | "${prompt.slice(0, 60)}${prompt.length > 60 ? "…" : ""}"`, ts: new Date() });

    try {
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": key.trim(),
          "anthropic-version": "2023-06-01",
          "anthropic-dangerous-direct-browser-access": "true",
        },
        body: JSON.stringify({
          model,
          max_tokens: maxTokens,
          temperature: temp,
          messages: [{ role: "user", content: prompt }],
        }),
      });

      const d = await r.json();
      const elapsed = Math.round(performance.now() - t0);

      if (!r.ok) {
        setStats(s => ({ ...s, errors: s.errors + 1 }));
        addLog({ type: "err", msg: `✗ ${d?.error?.type}: ${d?.error?.message}`, ts: new Date() });
        setRunning(false);
        return;
      }

      const inp  = d.usage?.input_tokens  ?? 0;
      const out  = d.usage?.output_tokens ?? 0;
      const cost = calcCost(model, inp, out);
      const text = d.content?.[0]?.text   ?? "";

      setStats(s => ({ calls: s.calls+1, inputTok: s.inputTok+inp, outputTok: s.outputTok+out, cost: s.cost+cost, errors: s.errors }));
      addLog({ type: "res", msg: text, model: m.name, color: m.color, inp, out, cost, elapsed, ts: new Date(), stopReason: d.stop_reason });
    } catch (e) {
      setStats(s => ({ ...s, errors: s.errors + 1 }));
      addLog({ type: "err", msg: `✗ Network: ${e.message}`, ts: new Date() });
    }
    setRunning(false);
  };

  const activeModel = MODELS.find(m => m.id === model);
  const keyColor = { idle: "#374151", checking: "#f59e0b", valid: "#22c55e", invalid: "#ef4444" }[keyState];
  const keyLabel = { idle: "●", checking: "◌", valid: "✓ VALID", invalid: "✗ INVALID" }[keyState];

  // ─── Styles ────────────────────────────────────────────────────────────────
  const S = {
    app:      { minHeight: "100vh", background: "#080b0f", color: "#c9d1d9", fontFamily: "'Fira Code','JetBrains Mono','Courier New',monospace", fontSize: 13, display: "flex", flexDirection: "column" },
    topBar:   { background: "#0d1117", borderBottom: "1px solid #21262d", padding: "12px 24px", display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" },
    tabBar:   { background: "#0d1117", borderBottom: "1px solid #21262d", paddingLeft: 20, display: "flex", alignItems: "center" },
    content:  { flex: 1, overflow: "auto", padding: "20px 24px" },
    statusBar:{ background: "#010409", borderTop: "1px solid #21262d", padding: "5px 24px", display: "flex", gap: 24, alignItems: "center" },
    label:    { fontSize: 10, color: "#30363d", letterSpacing: "0.1em" },
    card:     { background: "#0d1117", border: "1px solid #21262d", borderRadius: 4, padding: "16px 18px" },
    input:    { background: "#010409", border: "1px solid #21262d", color: "#c9d1d9", padding: "7px 10px", borderRadius: 4, fontFamily: "inherit", fontSize: 13, width: "100%" },
    textarea: { background: "#010409", border: "1px solid #21262d", color: "#c9d1d9", padding: "10px 12px", borderRadius: 4, fontFamily: "inherit", fontSize: 13, width: "100%", height: 130, resize: "vertical", lineHeight: 1.6 },
  };

  return (
    <div style={S.app}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@300;400;500;600&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #080b0f; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #0d1117; }
        ::-webkit-scrollbar-thumb { background: #21262d; border-radius: 2px; }
        input:focus, textarea:focus { outline: none; border-color: #38bdf8 !important; box-shadow: 0 0 0 1px #38bdf820; }
        .tab-btn  { font-family:inherit; font-size:11px; background:none; border:none; cursor:pointer; padding:8px 16px; letter-spacing:0.08em; transition:all 0.15s; text-transform:uppercase; }
        .act-btn  { font-family:inherit; cursor:pointer; border:none; transition:all 0.15s; letter-spacing:0.06em; }
        .act-btn:hover:not(:disabled) { opacity:0.8; }
        .act-btn:active:not(:disabled) { transform:scale(0.97); }
        .act-btn:disabled { opacity:0.3; cursor:not-allowed; }
        .model-btn { font-family:inherit; font-size:12px; background:transparent; cursor:pointer; padding:9px 14px; border-radius:4px; text-align:left; display:flex; justify-content:space-between; align-items:center; width:100%; transition:all 0.15s; }
        .preset-chip { font-family:inherit; font-size:11px; background:#0d1117; border:1px solid #21262d; color:#64748b; padding:4px 10px; border-radius:3px; cursor:pointer; transition:all 0.15s; white-space:nowrap; }
        .preset-chip:hover { border-color:#38bdf840; color:#94a3b8; }
        @keyframes spin { to { transform:rotate(360deg); } }
        .spin { animation:spin 1s linear infinite; display:inline-block; }
        @keyframes slideIn { from{opacity:0;transform:translateX(-6px)} to{opacity:1;transform:translateX(0)} }
        .log-entry { animation:slideIn 0.2s ease; }
        @keyframes fadeUp { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
        .fade-up { animation:fadeUp 0.35s ease both; }
      `}</style>

      {/* ── TOP BAR ── */}
      <div style={S.topBar}>
        <div style={{ fontFamily:"'Segoe UI',system-ui,sans-serif", fontSize:17, fontWeight:800, color:"#f0f6fc", letterSpacing:"-0.02em" }}>
          CLAUDE<span style={{ color:"#38bdf8" }}>.API</span>
        </div>
        <div style={{ width:1, height:20, background:"#21262d" }} />
        <div style={{ fontSize:11, color:"#30363d", letterSpacing:"0.06em" }}>INSPECTOR v1.1</div>

        <div style={{ marginLeft:"auto", display:"flex", alignItems:"center", gap:10, flexWrap:"wrap" }}>
          <span style={S.label}>API KEY</span>
          <div style={{ position:"relative" }}>
            <input
              type={keyMasked ? "password" : "text"}
              value={key}
              onChange={e => { setKey(e.target.value); setKeyState("idle"); setPlanInfo(null); }}
              placeholder="sk-ant-api03-···"
              style={{ background:"#010409", border:"1px solid #21262d", color:"#c9d1d9", padding:"6px 30px 6px 10px", borderRadius:4, width:280, fontFamily:"inherit", fontSize:13 }}
            />
            <button onClick={() => setKeyMasked(v => !v)} style={{ position:"absolute", right:6, top:"50%", transform:"translateY(-50%)", background:"none", border:"none", cursor:"pointer", color:"#30363d", fontSize:12 }}>
              {keyMasked ? "○" : "●"}
            </button>
          </div>
          <button className="act-btn" onClick={validateKey} disabled={!key.trim() || keyState==="checking"}
            style={{ background:"#161b22", border:"1px solid #30363d", color:"#8b949e", padding:"6px 14px", borderRadius:4, fontSize:12 }}>
            {keyState==="checking" ? <span className="spin">◌</span> : "VALIDATE"}
          </button>
          <span style={{ fontSize:11, color:keyColor, fontWeight:500, minWidth:70 }}>{keyLabel}</span>
        </div>
      </div>

      {/* ── PLAN BANNER (shown after validation) ── */}
      {planInfo && (
        <div className="fade-up" style={{ background: planInfo.bg, borderBottom: `1px solid ${planInfo.border}`, padding: "10px 24px", display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
          <span style={{ fontSize: 18 }}>{planInfo.icon}</span>
          <div>
            <span style={{ fontSize: 11, fontWeight: 700, color: planInfo.color, letterSpacing: "0.1em" }}>{planInfo.badge}</span>
            <span style={{ fontSize: 13, color: "#c9d1d9", marginLeft: 10 }}>{planInfo.tier}</span>
          </div>
          <div style={{ width: 1, height: 20, background: planInfo.border }} />
          <span style={{ fontSize: 11, color: "#6b7280" }}>{planInfo.desc}</span>
          <div style={{ marginLeft: "auto", display: "flex", gap: 24 }}>
            {planInfo.rpm != null && (
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 15, fontWeight: 600, color: planInfo.color }}>{planInfo.rpm.toLocaleString()}</div>
                <div style={{ fontSize: 9, color: "#374151", letterSpacing: "0.08em" }}>REQ / MIN</div>
              </div>
            )}
            {planInfo.tpm != null && (
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 15, fontWeight: 600, color: planInfo.color }}>{planInfo.tpm.toLocaleString()}</div>
                <div style={{ fontSize: 9, color: "#374151", letterSpacing: "0.08em" }}>TOKENS / MIN</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── TABS ── */}
      <div style={S.tabBar}>
        {[["test","Test Request"],["stats","Usage Stats"],["plan","Plan Info"],["log","Event Log"]].map(([id,label]) => (
          <button key={id} className="tab-btn" onClick={() => setActiveTab(id)}
            style={{ color: activeTab===id ? "#38bdf8" : "#30363d", borderBottom: activeTab===id ? "2px solid #38bdf8" : "2px solid transparent" }}>
            {label}
          </button>
        ))}
        <div style={{ marginLeft:"auto", display:"flex", alignItems:"center", gap:16, paddingRight:20 }}>
          <span style={{ fontSize:10, color:"#21262d" }}>requests: <span style={{ color:"#30363d" }}>{stats.calls}</span></span>
          <span style={{ fontSize:10, color:"#21262d" }}>cost: <span style={{ color:"#30363d" }}>{fmtCost(stats.cost)}</span></span>
        </div>
      </div>

      {/* ── CONTENT ── */}
      <div style={S.content}>

        {/* TEST TAB */}
        {activeTab === "test" && (
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20, maxWidth:1100 }}>
            <div>
              <div style={{ marginBottom:18 }}>
                <div style={{ ...S.label, marginBottom:10 }}>MODEL</div>
                {MODELS.map(m => (
                  <button key={m.id} className="model-btn" onClick={() => setModel(m.id)}
                    style={{ background: model===m.id ? "#0d1117":"transparent", border:`1px solid ${model===m.id ? m.color+"60":"#21262d"}`, color: model===m.id ? m.color:"#4b5563", marginBottom:6 }}>
                    <span>{m.name}</span>
                    <span style={{ fontSize:10, color: model===m.id ? m.color+"90":"#21262d" }}>${m.cost.in}/1k in · ${m.cost.out}/1k out</span>
                  </button>
                ))}
              </div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:18 }}>
                <div>
                  <div style={{ ...S.label, marginBottom:8 }}>MAX TOKENS</div>
                  <input type="number" value={maxTokens} min={1} max={4096} onChange={e => setMaxTokens(Number(e.target.value))} style={S.input} />
                </div>
                <div>
                  <div style={{ ...S.label, marginBottom:8 }}>TEMPERATURE</div>
                  <input type="number" value={temp} min={0} max={1} step={0.1} onChange={e => setTemp(Number(e.target.value))} style={S.input} />
                </div>
              </div>
              <div>
                <div style={{ ...S.label, marginBottom:8 }}>QUICK PROMPTS</div>
                <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
                  {PRESETS.map(p => <button key={p} className="preset-chip" onClick={() => setPrompt(p)}>{p.slice(0,30)}{p.length>30?"…":""}</button>)}
                </div>
              </div>
            </div>

            <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
              <div>
                <div style={{ ...S.label, marginBottom:8 }}>PROMPT</div>
                <textarea value={prompt} onChange={e => setPrompt(e.target.value)} placeholder="Enter prompt… (Ctrl+Enter to send)"
                  onKeyDown={e => { if (e.key==="Enter" && (e.metaKey||e.ctrlKey)) sendPrompt(); }} style={S.textarea} />
                <div style={{ fontSize:10, color:"#21262d", marginTop:4 }}>Ctrl+Enter to send</div>
              </div>

              <button className="act-btn" onClick={sendPrompt}
                disabled={!key.trim()||!prompt.trim()||running||keyState==="invalid"}
                style={{ background: running ? "#0d1117":`${activeModel.color}18`, border:`1px solid ${running ? "#21262d":activeModel.color+"50"}`, color: running ? "#30363d":activeModel.color, padding:"10px", borderRadius:4, fontWeight:600, letterSpacing:"0.1em", fontSize:12 }}>
                {running ? <><span className="spin" style={{ marginRight:8 }}>◌</span>AWAITING RESPONSE…</> : "▶  SEND REQUEST"}
              </button>

              {log.find(e => e.type==="res") && (() => {
                const r = log.find(e => e.type==="res");
                return (
                  <div style={{ background:"#010409", border:`1px solid ${r.color}30`, borderRadius:4, overflow:"hidden" }}>
                    <div style={{ background:`${r.color}0c`, borderBottom:`1px solid ${r.color}20`, padding:"8px 14px", display:"flex", gap:16, alignItems:"center", flexWrap:"wrap" }}>
                      <span style={{ fontSize:10, color:r.color }}>{r.model}</span>
                      <span style={{ fontSize:10, color:"#30363d" }}>{r.elapsed}ms</span>
                      <span style={{ fontSize:10, color:"#30363d" }}>↑{r.inp} ↓{r.out} tokens</span>
                      <span style={{ fontSize:10, color:"#fbbf24", marginLeft:"auto" }}>{fmtCost(r.cost)}</span>
                      <span style={{ fontSize:10, color:"#30363d" }}>{r.stopReason}</span>
                    </div>
                    <div style={{ padding:"14px", color:"#c9d1d9", lineHeight:1.7, whiteSpace:"pre-wrap", maxHeight:240, overflowY:"auto" }}>{r.msg}</div>
                  </div>
                );
              })()}
              {log[0]?.type==="err" && (
                <div style={{ background:"#1a0a0a", border:"1px solid #7f1d1d", borderRadius:4, padding:"10px 14px", fontSize:12, color:"#fca5a5" }}>{log[0].msg}</div>
              )}
            </div>
          </div>
        )}

        {/* STATS TAB */}
        {activeTab === "stats" && (
          <div style={{ maxWidth:700 }}>
            <div style={{ ...S.label, marginBottom:20 }}>SESSION USAGE</div>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12, marginBottom:28 }}>
              {[
                { label:"API Calls",        value:stats.calls,                              color:"#38bdf8" },
                { label:"Input Tokens",     value:fmt(stats.inputTok),                      color:"#a78bfa" },
                { label:"Output Tokens",    value:fmt(stats.outputTok),                     color:"#4ade80" },
                { label:"Total Tokens",     value:fmt(stats.inputTok+stats.outputTok),      color:"#fb923c" },
                { label:"Total Cost (USD)", value:fmtCost(stats.cost),                      color:"#fbbf24" },
                { label:"Errors",           value:stats.errors, color:stats.errors>0?"#ef4444":"#21262d" },
              ].map(s => (
                <div key={s.label} style={S.card}>
                  <div style={{ fontSize:22, fontWeight:600, color:s.color, marginBottom:6 }}>{s.value}</div>
                  <div style={{ fontSize:10, color:"#30363d", letterSpacing:"0.08em" }}>{s.label}</div>
                </div>
              ))}
            </div>
            <div style={{ ...S.label, marginBottom:12 }}>BY MODEL</div>
            {MODELS.map(m => {
              const entries = log.filter(e => e.type==="res" && e.model===m.name);
              if (!entries.length) return <div key={m.id} style={{ padding:"10px 14px", borderBottom:"1px solid #0d1117", color:"#21262d", fontSize:12 }}>{m.name} — no requests this session</div>;
              const inp  = entries.reduce((a,b)=>a+b.inp,0);
              const out  = entries.reduce((a,b)=>a+b.out,0);
              const cost = entries.reduce((a,b)=>a+b.cost,0);
              const avg  = Math.round(entries.reduce((a,b)=>a+b.elapsed,0)/entries.length);
              return (
                <div key={m.id} style={{ background:"#0d1117", border:`1px solid ${m.color}20`, borderRadius:4, padding:"12px 16px", marginBottom:8, display:"flex", gap:16, alignItems:"center", flexWrap:"wrap" }}>
                  <span style={{ color:m.color, fontWeight:500, minWidth:100 }}>{m.name}</span>
                  <span style={{ fontSize:11, color:"#4b5563" }}>{entries.length} calls</span>
                  <span style={{ fontSize:11, color:"#4b5563" }}>↑{fmt(inp)}</span>
                  <span style={{ fontSize:11, color:"#4b5563" }}>↓{fmt(out)}</span>
                  <span style={{ fontSize:11, color:"#4b5563" }}>avg {avg}ms</span>
                  <span style={{ fontSize:11, color:"#fbbf24", marginLeft:"auto" }}>{fmtCost(cost)}</span>
                </div>
              );
            })}
            {stats.calls===0 && <div style={{ color:"#21262d", textAlign:"center", paddingTop:60, fontSize:12 }}>No requests yet. Send a prompt from the Test tab.</div>}
          </div>
        )}

        {/* PLAN INFO TAB */}
        {activeTab === "plan" && (
          <div style={{ maxWidth:760 }}>
            <div style={{ ...S.label, marginBottom:20 }}>ANTHROPIC API TIER REFERENCE</div>

            {/* Detected tier highlight */}
            {planInfo ? (
              <div className="fade-up" style={{ background: planInfo.bg, border: `1px solid ${planInfo.border}`, borderRadius:6, padding:"18px 22px", marginBottom:24 }}>
                <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:10 }}>
                  <span style={{ fontSize:22 }}>{planInfo.icon}</span>
                  <div>
                    <div style={{ fontSize:11, color: planInfo.color, letterSpacing:"0.1em", fontWeight:700 }}>YOUR KEY IS ON: {planInfo.badge}</div>
                    <div style={{ fontSize:15, color:"#f0f6fc", marginTop:2 }}>{planInfo.tier}</div>
                  </div>
                </div>
                <div style={{ fontSize:12, color:"#6b7280", marginBottom:14 }}>{planInfo.desc}</div>
                <div style={{ display:"flex", gap:32 }}>
                  {planInfo.rpm != null && (
                    <div>
                      <div style={{ fontSize:22, fontWeight:700, color:planInfo.color }}>{planInfo.rpm.toLocaleString()}</div>
                      <div style={{ fontSize:10, color:"#374151" }}>REQUESTS / MINUTE</div>
                    </div>
                  )}
                  {planInfo.tpm != null && (
                    <div>
                      <div style={{ fontSize:22, fontWeight:700, color:planInfo.color }}>{planInfo.tpm.toLocaleString()}</div>
                      <div style={{ fontSize:10, color:"#374151" }}>TOKENS / MINUTE</div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div style={{ background:"#0d1117", border:"1px solid #21262d", borderRadius:6, padding:"16px 20px", marginBottom:24, fontSize:12, color:"#374151" }}>
                ↑ Validate your API key first to detect your plan tier.
              </div>
            )}

            {/* All tiers reference table */}
            <div style={{ ...S.label, marginBottom:12 }}>ALL TIERS</div>
            {TIERS.map(t => {
              const isYours = planInfo?.tier === t.tier;
              return (
                <div key={t.tier} style={{ background: isYours ? t.bg : "#0d1117", border:`1px solid ${isYours ? t.border:"#1e1e2e"}`, borderRadius:4, padding:"12px 16px", marginBottom:8, display:"grid", gridTemplateColumns:"28px 160px 1fr 90px 110px", gap:12, alignItems:"center" }}>
                  <span style={{ color:t.color, fontSize:16 }}>{t.icon}</span>
                  <span style={{ color: isYours ? t.color:"#4b5563", fontWeight: isYours ? 600:400, fontSize:12 }}>{t.tier}</span>
                  <span style={{ fontSize:11, color:"#374151" }}>{t.desc}</span>
                  <span style={{ fontSize:11, color:"#4b5563", textAlign:"right" }}>{t.rpmMax === Infinity ? `${t.rpmMin.toLocaleString()}+` : t.rpmMax.toLocaleString()} RPM</span>
                  <span style={{ fontSize:11, color:"#4b5563", textAlign:"right" }}>{t.tpmMax === Infinity ? `${t.tpmMin.toLocaleString()}+` : t.tpmMax.toLocaleString()} TPM</span>
                </div>
              );
            })}

            {/* Raw headers */}
            {rlRaw && (
              <>
                <div style={{ ...S.label, marginTop:28, marginBottom:12 }}>RAW RATE-LIMIT HEADERS</div>
                <div style={{ background:"#010409", border:"1px solid #21262d", borderRadius:4, overflow:"hidden" }}>
                  {Object.entries(rlRaw).map(([k,v]) => (
                    <div key={k} style={{ display:"flex", gap:16, padding:"8px 14px", borderBottom:"1px solid #0d1117", alignItems:"center" }}>
                      <span style={{ fontSize:11, color:"#374151", minWidth:340, fontFamily:"inherit" }}>{k}</span>
                      <span style={{ fontSize:12, color:"#c9d1d9" }}>{v}</span>
                    </div>
                  ))}
                </div>
              </>
            )}

            <div style={{ fontSize:10, color:"#21262d", marginTop:16 }}>
              Tier is inferred from rate-limit response headers. For authoritative info visit console.anthropic.com
            </div>
          </div>
        )}

        {/* LOG TAB */}
        {activeTab === "log" && (
          <div style={{ maxWidth:800 }}>
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:16 }}>
              <div style={S.label}>EVENT LOG ({log.length})</div>
              <button className="act-btn" onClick={() => setLog([])}
                style={{ background:"none", border:"1px solid #21262d", color:"#30363d", padding:"4px 12px", borderRadius:3, fontSize:10, fontFamily:"inherit" }}>CLEAR</button>
            </div>
            <div ref={logRef} style={{ display:"flex", flexDirection:"column", gap:4 }}>
              {log.length===0 && <div style={{ color:"#21262d", fontSize:12 }}>No events yet.</div>}
              {log.map((entry,i) => {
                const tsStr = entry.ts?.toLocaleTimeString("en-US",{hour12:false,hour:"2-digit",minute:"2-digit",second:"2-digit"});
                const tc = {sys:"#38bdf8",req:"#a78bfa",res:entry.color||"#4ade80",err:"#ef4444"}[entry.type];
                const tag = {sys:"SYS",req:"REQ",res:"RES",err:"ERR"}[entry.type];
                return (
                  <div key={i} className="log-entry" style={{ display:"flex", gap:12, padding:"8px 12px", background:"#0d1117", borderRadius:3, borderLeft:`2px solid ${tc}40`, alignItems:"flex-start" }}>
                    <span style={{ fontSize:10, color:"#21262d", whiteSpace:"nowrap", paddingTop:1 }}>{tsStr}</span>
                    <span style={{ fontSize:10, color:tc, minWidth:28, paddingTop:1 }}>{tag}</span>
                    <span style={{ fontSize:12, color:entry.type==="err"?"#fca5a5":"#8b949e", lineHeight:1.6, flex:1, wordBreak:"break-word" }}>
                      {entry.type==="res"
                        ? <>{entry.msg.slice(0,200)}{entry.msg.length>200?"…":""}<br/><span style={{ fontSize:10, color:"#30363d" }}>↑{entry.inp} ↓{entry.out} · {entry.elapsed}ms · {fmtCost(entry.cost)}</span></>
                        : entry.msg}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* STATUS BAR */}
      <div style={S.statusBar}>
        <span style={{ fontSize:10, color:"#21262d" }}>key in-memory only · never persisted · direct → anthropic.com</span>
        {planInfo && <span style={{ fontSize:10, color:planInfo.color, fontWeight:600 }}>{planInfo.badge}</span>}
        <span style={{ fontSize:10, color:"#21262d", marginLeft:"auto" }}>session · {fmt(stats.inputTok+stats.outputTok)} tokens · {fmtCost(stats.cost)}</span>
      </div>
    </div>
  );
}
