'use strict';

// ─── Config ────────────────────────────────────────────────────────────────
// Set API_BASE_URL in window before this script, or deploy with env var.
const API = (window.API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

// ─── Palette (matches CSS vars) ────────────────────────────────────────────
const C = {
  bg:      '#050505',
  surface: '#0a0a0a',
  border:  '#181818',
  text:    '#dedede',
  muted:   '#484848',
  muted2:  '#2a2a2a',
  orange:  '#f7931a',
  green:   '#00d46a',
  red:     '#ff3d3d',
  yellow:  '#f5c542',
  blue:    '#4499ff',
};

const RISK_COLOR = {
  CRITICAL: C.red,
  HIGH:     C.orange,
  MEDIUM:   C.yellow,
  LOW:      C.green,
  NONE:     C.muted,
  UNKNOWN:  C.muted,
};

const TYPE_DESC = {
  P2PK:      'Pay-to-Public-Key (legacy)',
  P2TR:      'Taproot (P2TR)',
  P2MS:      'Bare multisig',
  P2PKH:     'Pay-to-Public-Key-Hash',
  P2WPKH:    'SegWit v0 (P2WPKH)',
  P2SH:      'Pay-to-Script-Hash',
  P2WSH:     'SegWit v0 script (P2WSH)',
  'OP_RETURN':'Provably unspendable',
  UNKNOWN:   'Other / unrecognised',
};

const QUANTUM_RISK = {
  CRITICAL: 'CRITICAL',
  HIGH:     'HIGH',
  MEDIUM:   'MEDIUM',
  LOW:      'LOW',
  NONE:     'NONE',
};

// ─── Utilities ─────────────────────────────────────────────────────────────

function q(id) { return document.getElementById(id); }

function fmtBTC(sat) {
  if (sat == null || sat === 0) return '0';
  const b = sat / 1e8;
  if (b >= 1e6) return (b / 1e6).toFixed(3) + 'M';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + 'K';
  return b.toFixed(4);
}

function fmtNum(n) {
  if (n == null) return '—';
  if (n >= 1e9) return (n / 1e9).toFixed(2) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(0) + 'K';
  return n.toLocaleString();
}

function fmtPct(v) {
  if (v == null) return '—';
  return v.toFixed(2) + '%';
}

function animateVal(el, target, dur = 1300, fmt = fmtNum) {
  if (!el || target == null) return;
  const t0 = performance.now();
  const tick = (now) => {
    const p = Math.min((now - t0) / dur, 1);
    const ease = 1 - Math.pow(1 - p, 4);
    el.textContent = fmt(target * ease);
    if (p < 1) requestAnimationFrame(tick);
    else el.textContent = fmt(target);
  };
  requestAnimationFrame(tick);
}

async function apiFetch(path) {
  const r = await fetch(API + path);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ─── Tab navigation ─────────────────────────────────────────────────────────

const _tabLoaded = {};

document.querySelectorAll('.nav-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => {
      p.classList.remove('active');
      p.classList.add('hidden');
    });
    btn.classList.add('active');
    const id = 'tab-' + btn.dataset.tab;
    const panel = document.getElementById(id);
    panel.classList.remove('hidden');
    panel.classList.add('active');

    const t = btn.dataset.tab;
    if (!_tabLoaded[t]) {
      _tabLoaded[t] = true;
      if (t === 'distribution') loadDistribution();
      if (t === 'timelocks')    loadTimelocks();
    }
  });
});

// ─── Charts ─────────────────────────────────────────────────────────────────

function drawQuantumClock(canvas, current, needed, years) {
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const cx = W / 2, cy = H / 2 + 10;
  const rOuter = Math.min(W, H) / 2 - 8;
  const rInner = rOuter - 12;

  ctx.clearRect(0, 0, W, H);

  const START  = Math.PI * 0.75;
  const SWEEP  = Math.PI * 1.5;
  const threat = Math.min(current / needed, 1);

  // Track (background arc)
  ctx.beginPath();
  ctx.arc(cx, cy, rOuter - 6, START, START + SWEEP);
  ctx.strokeStyle = C.muted2;
  ctx.lineWidth = 12;
  ctx.lineCap = 'round';
  ctx.stroke();

  // Tick marks for years
  for (let y = 0; y <= Math.ceil(years); y++) {
    const pct = y / years * threat;  // not yet useful — just draw year marks
    const frac = y / (years + 0.5);
    const angle = START + frac * SWEEP;
    const x1 = cx + Math.cos(angle) * (rOuter - 2);
    const y1 = cy + Math.sin(angle) * (rOuter - 2);
    const x2 = cx + Math.cos(angle) * (rOuter - 16);
    const y2 = cy + Math.sin(angle) * (rOuter - 16);
    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    ctx.strokeStyle = C.border;
    ctx.lineWidth = 1;
    ctx.stroke();
  }

  // Threat arc (filled portion = current qubits / needed)
  if (threat > 0) {
    ctx.beginPath();
    ctx.arc(cx, cy, rOuter - 6, START, START + SWEEP * threat);
    ctx.strokeStyle = C.orange;
    ctx.lineWidth = 12;
    ctx.lineCap = 'round';
    ctx.stroke();
  }

  // Needle tip dot
  const needleAngle = START + SWEEP * threat;
  const nx = cx + Math.cos(needleAngle) * (rOuter - 6);
  const ny = cy + Math.sin(needleAngle) * (rOuter - 6);
  ctx.beginPath();
  ctx.arc(nx, ny, 5, 0, Math.PI * 2);
  ctx.fillStyle = C.orange;
  ctx.fill();

  // Center text
  ctx.textAlign = 'center';
  ctx.font = `700 22px 'IBM Plex Mono', monospace`;
  ctx.fillStyle = C.text;
  ctx.fillText(`~${years}`, cx, cy - 8);

  ctx.font = `400 9px 'IBM Plex Mono', monospace`;
  ctx.fillStyle = C.muted;
  ctx.fillText('YRS TO Q-DAY', cx, cy + 8);

  // Small label at bottom of arc
  ctx.font = `500 9px 'IBM Plex Mono', monospace`;
  ctx.fillStyle = C.muted;
  ctx.fillText('SAFE', cx - rOuter + 10, cy + rOuter - 2);
  ctx.fillStyle = C.red;
  ctx.fillText('Q-DAY', cx + rOuter - 28, cy + rOuter - 2);
}

function drawSparkline(canvas, points) {
  if (!points || points.length < 2) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const P = { t: 8, r: 8, b: 22, l: 8 };
  const iW = W - P.l - P.r, iH = H - P.t - P.b;

  ctx.clearRect(0, 0, W, H);

  const vals = points.map(p => (p.vuln_value_sat || 0) / 1e8);
  const lo = Math.min(...vals) * 0.998;
  const hi = Math.max(...vals) * 1.002;
  const rng = hi - lo || 1;

  const tx = i => P.l + (i / (points.length - 1)) * iW;
  const ty = v => P.t + iH - ((v - lo) / rng * iH);

  // Area
  const grad = ctx.createLinearGradient(0, P.t, 0, P.t + iH);
  grad.addColorStop(0, 'rgba(247,147,26,.18)');
  grad.addColorStop(1, 'rgba(247,147,26,0)');
  ctx.beginPath();
  ctx.moveTo(tx(0), P.t + iH);
  vals.forEach((v, i) => ctx.lineTo(tx(i), ty(v)));
  ctx.lineTo(tx(vals.length - 1), P.t + iH);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  vals.forEach((v, i) => i === 0 ? ctx.moveTo(tx(i), ty(v)) : ctx.lineTo(tx(i), ty(v)));
  ctx.strokeStyle = C.orange;
  ctx.lineWidth = 1.5;
  ctx.stroke();

  // First & last labels
  ctx.font = `400 9px 'IBM Plex Mono', monospace`;
  ctx.fillStyle = C.muted;
  if (points.length >= 2) {
    ctx.textAlign = 'left';
    ctx.fillText(points[0].date.slice(5), P.l, H - 4);
    ctx.textAlign = 'right';
    ctx.fillText(points[points.length - 1].date.slice(5), W - P.r, H - 4);
  }
}

function drawDistBar(canvas, segments) {
  // segments: [{label, pct, color}]
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  let x = 0;
  segments.forEach(s => {
    const w = W * (s.pct / 100);
    ctx.fillStyle = s.color;
    ctx.fillRect(x, 0, Math.max(w - 1, 0), H);
    x += w;
  });
}

function drawTLBars(canvas, items) {
  // items: [{label, count, color}]
  if (!items || !items.length) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const max = Math.max(...items.map(i => i.count), 1);
  const barH = 28;
  const gap  = 12;
  const labelW = 90;
  const pad = 12;
  const totalH = items.length * (barH + gap) - gap;

  items.forEach((item, idx) => {
    const y = pad + idx * (barH + gap);
    const bw = (W - labelW - pad * 2 - 20) * (item.count / max);

    ctx.font = `400 10px 'IBM Plex Mono', monospace`;
    ctx.fillStyle = C.muted;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.fillText(item.label, labelW, y + barH / 2);

    ctx.fillStyle = C.muted2;
    ctx.fillRect(labelW + pad, y, W - labelW - pad * 2, barH);

    ctx.fillStyle = item.color;
    ctx.fillRect(labelW + pad, y, Math.max(bw, 0), barH);

    ctx.font = `500 10px 'IBM Plex Mono', monospace`;
    ctx.fillStyle = C.text;
    ctx.textAlign = 'left';
    ctx.fillText(fmtNum(item.count), labelW + pad + Math.max(bw, 0) + 6, y + barH / 2);
  });
}

// ─── Tab 1: Overview ────────────────────────────────────────────────────────

async function loadOverview() {
  let data;
  try {
    data = await apiFetch('/api/v1/overview');
  } catch (e) {
    console.error('overview fetch failed', e);
    return;
  }

  // Header meta
  if (data.block_height) {
    q('hdr-block').textContent = fmtNum(data.block_height);
    q('live-dot').style.background = C.green;
  }
  if (data.last_scan_at) {
    q('hdr-scan').textContent = data.last_scan_at.slice(0, 10);
  }

  // Stat tiles
  const totalBTC  = data.total_value_sat;
  const safeBTC   = data.safe_value_sat;
  const riskBTC   = data.vuln_value_sat;
  const riskPct   = data.vuln_pct;
  const totalUTXO = data.total_utxos;

  animateVal(q('v-total-btc'), totalBTC, 1300, v => fmtBTC(v) + ' BTC');
  animateVal(q('v-safe-btc'),  safeBTC,  1300, v => fmtBTC(v) + ' BTC');
  animateVal(q('v-risk-btc'),  riskBTC,  1300, v => fmtBTC(v) + ' BTC');
  animateVal(q('v-risk-pct'),  riskPct,  1300, v => v.toFixed(2) + '%');
  animateVal(q('v-total-utxos'), totalUTXO, 1300);

  if (safeBTC && totalBTC) {
    q('s-safe-pct').textContent = fmtPct(safeBTC / totalBTC * 100) + ' of supply';
    q('s-risk-pct').textContent = fmtPct(riskBTC / totalBTC * 100) + ' of supply';
  }

  // Safety bar
  const safePct = totalBTC ? (100 - riskPct) : 0;
  setTimeout(() => {
    q('safety-fill').style.width = safePct + '%';
    q('safety-fill-d').style.left  = safePct + '%';
    q('safety-fill-d').style.width = (riskPct || 0) + '%';
  }, 200);
  q('safety-pct-label').textContent = fmtPct(safePct) + ' SAFE';

  // Vulnerable list
  renderVulnList(data.breakdown);

  // Quantum clock
  const qc = data.quantum_clock || {};
  drawQuantumClock(
    q('clock-canvas'),
    qc.qubits_current || 1500,
    qc.qubits_needed  || 500000,
    qc.years_to_qday  || 8.4,
  );
  q('clock-detail').innerHTML = `
    <div class="clock-row">
      <div class="clock-key">EST. Q-DAY</div>
      <div class="clock-val-warn">~${qc.estimated_year || 2034}</div>
    </div>
    <div class="clock-row">
      <div class="clock-key">CURRENT QUBITS</div>
      <div class="clock-val">${fmtNum(qc.qubits_current)}</div>
    </div>
    <div class="clock-row">
      <div class="clock-key">NEEDED QUBITS</div>
      <div class="clock-val">${fmtNum(qc.qubits_needed)}</div>
    </div>
    <div class="clock-row">
      <div class="clock-key">THREAT LEVEL</div>
      <div class="clock-val" style="color:${C.orange}">${qc.threat_pct}%</div>
    </div>
    <div class="clock-row">
      <div class="clock-key">GROWTH RATE</div>
      <div class="clock-val">${qc.growth_rate_per_year}x / year</div>
    </div>
    <div class="clock-row">
      <div class="clock-key">SOURCE</div>
      <div class="clock-val" style="color:${C.muted}">Google 2025</div>
    </div>
  `;

  // Migration sparkline
  const trend = data.migration_trend || [];
  drawSparkline(q('spark-canvas'), trend);

  const delta = data.migration_30d;
  if (delta) {
    const dir   = delta.btc_change <= 0 ? 'spark-down' : 'spark-up';
    const arrow = delta.btc_change <= 0 ? '▼' : '▲';
    const sign  = delta.btc_change <= 0 ? '' : '+';
    q('spark-meta').innerHTML = `
      <span class="${dir}">${arrow} ${sign}${delta.btc_change.toFixed(1)} BTC</span>
      <span>30-day migration activity</span>
      <span class="${dir}">${sign}${delta.pct_change.toFixed(2)}% change</span>
    `;
  } else {
    q('spark-meta').textContent = trend.length < 2
      ? 'Run multiple daily scans to build trend data'
      : 'Insufficient history for delta';
  }

  // Satoshi panel
  const sat = data.satoshi || {};
  q('satoshi-content').innerHTML = `
    <div class="sat-big">${fmtBTC(sat.total_value_sat)} BTC</div>
    <div class="sat-sub">${fmtNum(sat.address_count)} P2PK addresses</div>
    <div class="sat-sub">mined in blocks 0 – 50,000</div>
    <div class="sat-sub">value per address: ~50 BTC</div>
    <div class="sat-warning">⚠ NEVER MOVED · QUANTUM ATTACK FIRST TARGET</div>
    <div class="sat-detail" style="margin-top:8px">
      These early P2PK outputs have public keys permanently on-chain.
      The first large-scale quantum attacker would likely target these
      known, high-value, zero-activity addresses.
    </div>
  `;
}

function renderVulnList(breakdown) {
  if (!breakdown) return;
  const list = q('vuln-list');
  list.innerHTML = '';

  const order = ['P2PK', 'P2TR', 'P2MS'];
  const maxVal = Math.max(...order.map(t => (breakdown[t] || {}).value_sat || 0), 1);
  let totalSat = 0;

  order.forEach(type => {
    const bd = breakdown[type];
    if (!bd) return;
    totalSat += bd.value_sat;
    const pct  = bd.value_sat / maxVal * 100;
    const risk = type === 'P2MS' ? 'HIGH' : 'CRITICAL';
    const fillClass = risk === 'CRITICAL' ? 'fill-critical' : 'fill-high';
    const badgeClass = risk === 'CRITICAL' ? 'badge-critical' : 'badge-high';

    const row = document.createElement('div');
    row.className = 'vuln-row';
    row.innerHTML = `
      <div class="vuln-type">${type}</div>
      <div class="vuln-bar-wrap">
        <div class="vuln-bar-bg">
          <div class="vuln-bar-fill ${fillClass}" style="width:0%" data-pct="${pct}"></div>
        </div>
      </div>
      <div class="vuln-btc">${fmtBTC(bd.value_sat)} BTC</div>
      <div class="vuln-badge ${badgeClass}">${risk}</div>
    `;
    list.appendChild(row);
  });

  // Animate bars
  setTimeout(() => {
    list.querySelectorAll('.vuln-bar-fill').forEach(el => {
      el.style.transition = 'width 1.4s cubic-bezier(.16,1,.3,1)';
      el.style.width = el.dataset.pct + '%';
    });
  }, 300);

  // Total
  q('vuln-total').innerHTML = `
    <span class="vuln-total-label">TOTAL AT RISK</span>
    <span class="vuln-total-val">${fmtBTC(totalSat)} BTC</span>
  `;
}

// ─── Tab 2: Address Check ────────────────────────────────────────────────────

q('addr-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') checkAddress();
});

async function checkAddress() {
  const addr = q('addr-input').value.trim();
  const result = q('addr-result');
  const tiers  = q('tier-grid');
  if (!addr) return;

  result.classList.remove('hidden');
  result.innerHTML = '<span class="loader"></span>Scanning…';

  // Hide tier cards during result display
  tiers.style.display = 'none';

  let data;
  try {
    data = await apiFetch('/api/v1/address/' + encodeURIComponent(addr));
  } catch (e) {
    result.innerHTML = `<span style="color:${C.red}">Error: ${e.message}</span>`;
    tiers.style.display = '';
    return;
  }

  const rd = data.risk_details || {};
  const ud = data.utxo_data || {};

  result.innerHTML = `
    <div class="res-header">
      <div class="risk-badge rb-${data.risk_level || 'UNKNOWN'}">${data.risk_level || 'UNKNOWN'}</div>
      <div>
        <div class="res-addr-type">${data.address_type || '—'} · Risk Score ${data.risk_score || 0}/5</div>
        <div class="res-addr">${data.address}</div>
      </div>
    </div>

    <div class="res-grid">
      <div class="res-box">
        <div class="res-box-label">REASON</div>
        <div class="res-box-val">${rd.reason || '—'}</div>
        ${rd.reuse_warning ? `<div class="res-warn">⚠ ${rd.reuse_warning}</div>` : ''}
      </div>

      <div class="res-box">
        <div class="res-box-label">UTXO DATA</div>
        <div class="res-box-val">
          ${ud.found_in_scan
            ? `Found: <strong>${fmtNum(ud.utxo_count)}</strong> UTXO(s) · ${fmtBTC(ud.total_value_sat)} BTC`
            : 'Not found in vulnerable set'}
        </div>
        <div style="color:${C.muted};font-size:10px;margin-top:4px">
          Scan: ${ud.last_scan_at ? ud.last_scan_at.slice(0,10) : '—'}
          ${ud.scan_block_height ? `· block ${fmtNum(ud.scan_block_height)}` : ''}
        </div>
      </div>

      <div class="res-box full">
        <div class="res-box-label">QUANTUM EXPLANATION</div>
        <div class="res-box-val" style="color:${C.muted};line-height:1.7">${rd.quantum_explanation || '—'}</div>
      </div>

      <div class="res-box full">
        <div class="res-box-label">RECOMMENDATION</div>
        <div class="res-box-val">${rd.recommendation || '—'}</div>
      </div>
    </div>

    ${ud.utxos && ud.utxos.length ? `
      <details style="margin-top:12px">
        <summary style="cursor:pointer;color:${C.muted};font-size:10px;letter-spacing:.08em">
          SHOW ${ud.utxos.length} VULNERABLE UTXO(S)
        </summary>
        <table class="data-table" style="margin-top:8px">
          <thead><tr><th>TXID</th><th>VOUT</th><th class="num">VALUE SAT</th><th>PUBKEY (HEX)</th></tr></thead>
          <tbody>
            ${ud.utxos.map(u => `
              <tr>
                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${u.txid}</td>
                <td>${u.vout}</td>
                <td class="num">${fmtNum(u.value_sat)}</td>
                <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis">${u.pubkey_hex || '—'}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </details>` : ''}
    <div style="margin-top:12px;text-align:right">
      <button onclick="resetCheck()" style="background:none;border:1px solid ${C.border};color:${C.muted};cursor:pointer;font-family:var(--f);font-size:10px;padding:6px 12px;letter-spacing:.08em">
        ✕ CLEAR
      </button>
    </div>
  `;
}

function resetCheck() {
  q('addr-result').classList.add('hidden');
  q('tier-grid').style.display = '';
  q('addr-input').value = '';
  q('addr-input').focus();
}

// ─── Tab 3: Distribution ────────────────────────────────────────────────────

const DIST_COLORS = {
  P2PKH:    C.green,
  P2WPKH:   '#00a854',
  P2SH:     C.blue,
  P2WSH:    '#2266cc',
  P2TR:     C.orange,
  P2PK:     C.red,
  P2MS:     '#cc6600',
  'OP_RETURN': C.muted,
  UNKNOWN:  '#333',
};

const DIST_RISK = {
  P2PK: 'CRITICAL', P2TR: 'CRITICAL',
  P2MS: 'HIGH',
  P2SH: 'MEDIUM', P2WSH: 'MEDIUM',
  P2PKH: 'LOW', P2WPKH: 'LOW',
  'OP_RETURN': 'NONE',
  UNKNOWN: 'UNKNOWN',
};

async function loadDistribution() {
  let data;
  try {
    data = await apiFetch('/api/v1/scan/distribution');
  } catch (e) {
    q('dist-tbody').innerHTML = `<tr><td colspan="8" style="color:${C.red}">Error: ${e.message}</td></tr>`;
    return;
  }

  if (data.status === 'no_scan') {
    q('dist-tbody').innerHTML = `<tr><td colspan="8" style="color:${C.muted}">No distribution scan data yet.</td></tr>`;
    return;
  }

  const dist = data.distribution || [];
  const totalU = data.total_utxos || 0;
  const totalV = data.total_value_sat || 1;

  // Stat tiles
  animateVal(q('dv-total-utxos'), totalU, 1300);
  q('dv-block').textContent = data.block_height ? fmtNum(data.block_height) : '—';

  // Compute safe vs risk pct
  let safeSat = 0, riskSat = 0;
  dist.forEach(d => {
    const r = DIST_RISK[d.script_type] || 'UNKNOWN';
    if (r === 'LOW' || r === 'NONE') safeSat += d.total_value_sat;
    else riskSat += d.total_value_sat;
  });
  q('dv-safe-pct').textContent = fmtPct(safeSat / totalV * 100);
  q('dv-risk-pct').textContent = fmtPct(riskSat / totalV * 100);

  // Stacked supply bar
  const segments = dist.map(d => ({
    label: d.script_type,
    pct: d.pct_of_value,
    color: DIST_COLORS[d.script_type] || C.muted,
  }));
  drawDistBar(q('dist-bar-canvas'), segments);

  // Legend
  const legend = q('dist-bar-legend');
  legend.innerHTML = segments.map(s =>
    `<div class="dbl-item">
       <div class="dbl-swatch" style="background:${s.color}"></div>
       <span>${s.label} (${s.pct.toFixed(1)}%)</span>
     </div>`
  ).join('');

  // Table
  const tbody = q('dist-tbody');
  tbody.innerHTML = dist.map(d => {
    const risk  = DIST_RISK[d.script_type] || 'UNKNOWN';
    const color = RISK_COLOR[risk] || C.muted;
    const desc  = TYPE_DESC[d.script_type] || '—';
    const pctU  = d.pct_of_utxos || 0;
    const pctV  = d.pct_of_value || 0;
    const btcVal = (d.total_value_sat / 1e8).toFixed(2);
    return `
      <tr>
        <td><strong>${d.script_type}</strong></td>
        <td style="color:${C.muted}">${desc}</td>
        <td class="num">${fmtNum(d.utxo_count)}</td>
        <td class="num">${btcVal}</td>
        <td class="num">${pctV.toFixed(2)}%</td>
        <td class="num">${pctU.toFixed(2)}%</td>
        <td><span style="color:${color};font-size:9px;font-weight:700;letter-spacing:.1em">${risk}</span></td>
        <td>
          <div class="inline-bar-wrap">
            <div class="inline-bar-fill" style="background:${DIST_COLORS[d.script_type]||C.muted};width:${Math.min(pctV,100)}%"></div>
          </div>
        </td>
      </tr>`;
  }).join('');
}

// ─── Tab 4: Timelocks ────────────────────────────────────────────────────────

async function loadTimelocks() {
  let data;
  try {
    data = await apiFetch('/api/v1/scan/timelocks/status');
  } catch (e) {
    q('tl-status-content').innerHTML = `<span style="color:${C.red}">Error: ${e.message}</span>`;
    return;
  }

  if (data.status === 'no_scan') {
    q('tl-status-content').className = 'tl-status tl-none';
    q('tl-status-content').textContent =
      'No timelock scan data yet. Run scan_timelocks.py to start the 3-5 day background job.';
    return;
  }

  const bd = data.breakdown || [];
  const totalInherit = bd.reduce((s, r) => s + (r.inheritance_patterns || 0), 0);
  const cltv = bd.find(r => r.lock_type === 'CLTV');
  const csv  = bd.find(r => r.lock_type === 'CSV');
  const both = bd.find(r => r.lock_type === 'CLTV_CSV');

  const totalCount = (cltv?.utxo_count||0) + (csv?.utxo_count||0) + (both?.utxo_count||0);

  animateVal(q('tv-total'),   data.records_found || totalCount, 1200);
  animateVal(q('tv-cltv'),    cltv?.utxo_count || 0, 1200);
  animateVal(q('tv-csv'),     csv?.utxo_count  || 0, 1200);
  animateVal(q('tv-inherit'), totalInherit, 1200);
  q('iv-count').textContent = fmtNum(totalInherit);

  // Bar chart
  const items = bd.map(r => ({
    label: r.lock_type,
    count: r.utxo_count,
    color: r.lock_type.includes('CLTV') ? C.orange : C.blue,
  }));
  if (totalInherit > 0) items.push({ label: 'INHERIT', count: totalInherit, color: C.yellow });
  drawTLBars(q('tl-bar-canvas'), items);

  // Status bar
  const statusCls = data.status === 'complete' ? 'tl-complete'
                  : data.status === 'running'  ? 'tl-running'
                  : 'tl-none';
  q('tl-status-content').className = 'tl-status ' + statusCls;
  q('tl-status-content').innerHTML = `
    Status: <strong>${data.status}</strong> ·
    Records: <strong>${fmtNum(data.records_found)}</strong> ·
    Block: <strong>${fmtNum(data.block_height)}</strong> ·
    Started: ${data.started_at ? data.started_at.slice(0,16) : '—'}
    ${data.status === 'running' ? '<br>Phase 2 block scan in progress — expected 3-5 days.' : ''}
  `;
}

// ─── Footer stats ────────────────────────────────────────────────────────────

async function loadFooter() {
  try {
    const s = await apiFetch('/api/v1/stats');
    if (s.total_queries != null) {
      q('footer-queries').textContent = fmtNum(s.total_queries) + ' address queries';
    }
  } catch (_) {}
}

// ─── Init ────────────────────────────────────────────────────────────────────

async function init() {
  loadOverview();
  loadFooter();
}

document.addEventListener('DOMContentLoaded', init);
