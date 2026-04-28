import { WSClient, rttStr, rttClass, escHtml } from '../client.js';

const MAX_DOTS = 48;

// Map rttClass colour names to solid background classes for the dot chips.
const DOT_BG = {
  'c-green':  'gp-green',
  'c-yellow': 'gp-yellow',
  'c-orange': 'gp-orange',
  'c-red':    'gp-red',
  'c-dim':    'gp-timeout',
};

function dotBg(ms) {
  return DOT_BG[rttClass(ms)] ?? 'gp-timeout';
}

export default {
  mount(container, prefill) {
    let ws   = null;
    let mode = 'ping'; // 'ping' | 'trace'
    const state = {}; // nodeId → { sent, recv, rtts }

    // ── Shell ─────────────────────────────────────────────────────────
    container.innerHTML = `
      <div class="input-bar">
        <input id="gp-host" type="text"
               placeholder="hostname or IP — probe from all nodes"
               autocomplete="off" autocorrect="off"
               autocapitalize="none" spellcheck="false"
               value="${escHtml(prefill || '')}"/>
        <div class="input-sep"></div>
        <label style="color:var(--fg-dim);font-size:13px;white-space:nowrap">Every</label>
        <select id="gp-ivl"
                style="background:none;border:none;color:var(--fg);
                       font-family:var(--mono);font-size:13px;
                       outline:none;width:56px;cursor:pointer">
          <option value="1">1 s</option>
          <option value="2" selected>2 s</option>
          <option value="5">5 s</option>
          <option value="10">10 s</option>
          <option value="30">30 s</option>
        </select>
        <div class="input-sep"></div>
        <button id="gp-ping-btn"  class="btn btn-start">▶ Ping All</button>
        <button id="gp-trace-btn" class="btn btn-ghost">⇢ Trace All</button>
      </div>

      <!-- Ping grid -->
      <div id="gp-grid" class="gping-grid" style="display:none">
        <div class="gping-header">
          <span class="gping-lbl">Node</span>
          <span></span>
          <span class="gping-lbl gping-r">Avg</span>
          <span class="gping-lbl gping-r">Loss</span>
          <span class="gping-lbl gping-r">Last</span>
          <span class="gping-lbl" style="padding-left:6px">
            Results &nbsp;<span style="opacity:.4;font-weight:400">older ← → newer</span>
          </span>
        </div>
        <div id="gp-rows"></div>
      </div>

      <!-- Traceroute sections (one card per node) -->
      <div id="gp-trace-wrap" style="display:none"></div>`;

    const $host      = container.querySelector('#gp-host');
    const $ivl       = container.querySelector('#gp-ivl');
    const $pingBtn   = container.querySelector('#gp-ping-btn');
    const $traceBtn  = container.querySelector('#gp-trace-btn');
    const $grid      = container.querySelector('#gp-grid');
    const $rows      = container.querySelector('#gp-rows');
    const $traceWrap = container.querySelector('#gp-trace-wrap');

    // ── Build ping row ─────────────────────────────────────────────────
    function buildPingRow(n) {
      const d = document.createElement('div');
      d.className = 'gping-row';
      d.innerHTML = `
        <span class="gping-node-info">
          <span class="gping-flag">${escHtml(n.flag || '◈')}</span>
          <span style="min-width:0;overflow:hidden">
            <span class="gping-name">${escHtml(n.name)}</span>
            ${n.city
              ? `<br><span class="gping-city">${escHtml(n.city)}</span>`
              : ''}
          </span>
        </span>
        <span id="gp-s-${n.id}"
              class="gping-status status-pending" title="Waiting…">◌</span>
        <span id="gp-avg-${n.id}"  class="gping-r c-dim">—</span>
        <span id="gp-loss-${n.id}" class="gping-r c-dim">—</span>
        <span id="gp-last-${n.id}" class="gping-r c-dim">—</span>
        <span class="gping-dots-wrap">
          <span id="gp-d-${n.id}" class="gping-dots"></span>
        </span>`;
      return d;
    }

    // ── Build trace card ───────────────────────────────────────────────
    function buildTraceCard(n) {
      const d = document.createElement('div');
      d.className = 'card';
      d.style.marginBottom = '10px';
      d.innerHTML = `
        <div class="gping-trace-hdr">
          <span class="gping-flag">${escHtml(n.flag || '◈')}</span>
          <span class="gping-name">${escHtml(n.name)}</span>
          ${n.city
            ? `<span class="c-dim" style="font-size:12px">${escHtml(n.city)}</span>`
            : ''}
          <span id="gp-ts-${n.id}"
                class="gping-status status-pending"
                style="margin-left:auto">◌</span>
        </div>
        <div style="overflow-x:auto;margin-top:8px">
          <table class="result-table">
            <thead><tr>
              <th>Hop</th><th>IP</th><th>Hostname</th>
              <th>RTT 1</th><th>RTT 2</th><th>RTT 3</th><th>Loss</th>
            </tr></thead>
            <tbody id="gp-tb-${n.id}"></tbody>
          </table>
        </div>`;
      return d;
    }

    // ── Init grid from "nodes" message ─────────────────────────────────
    function initNodes(nodes) {
      $rows.innerHTML      = '';
      $traceWrap.innerHTML = '';
      Object.keys(state).forEach(k => delete state[k]);

      nodes.forEach(n => {
        state[n.id] = { sent: 0, recv: 0, rtts: [] };
        if (mode === 'ping') $rows.appendChild(buildPingRow(n));
        else                 $traceWrap.appendChild(buildTraceCard(n));
      });

      $grid.style.display      = mode === 'ping'  ? '' : 'none';
      $traceWrap.style.display = mode === 'trace' ? '' : 'none';
    }

    // ── Handle ping result ─────────────────────────────────────────────
    function handlePing(d) {
      const s = state[d.node_id];
      if (!s) return;
      const rtt     = d.rtt_ms ?? -1;
      const timeout = rtt < 0;
      s.sent++;
      if (!timeout) { s.recv++; s.rtts.push(rtt); }

      // Status dot
      const $st = container.querySelector(`#gp-s-${d.node_id}`);
      if ($st) {
        if (d.error && !timeout) {
          $st.className = 'gping-status status-offline';
          $st.textContent = '✗';
          $st.title = d.error;
        } else {
          $st.className   = `gping-status ${timeout ? 'status-timeout' : 'status-ok'}`;
          $st.textContent = timeout ? '○' : '●';
          $st.title       = timeout ? 'Timeout' : `${rtt.toFixed(1)} ms`;
        }
      }

      // Stats
      const lossN = s.sent ? (s.sent - s.recv) / s.sent * 100 : 0;
      const avgN  = s.rtts.length
        ? s.rtts.reduce((a, b) => a + b, 0) / s.rtts.length : -1;

      const $avg  = container.querySelector(`#gp-avg-${d.node_id}`);
      const $loss = container.querySelector(`#gp-loss-${d.node_id}`);
      const $last = container.querySelector(`#gp-last-${d.node_id}`);

      if ($avg) {
        $avg.textContent = avgN >= 0 ? avgN.toFixed(1) + ' ms' : '—';
        $avg.className   = `gping-r ${avgN >= 0 ? rttClass(avgN) : 'c-dim'}`;
      }
      if ($loss) {
        $loss.textContent = lossN.toFixed(0) + '%';
        $loss.className   = `gping-r ${
          lossN >= 20 ? 'c-red' : lossN > 0 ? 'c-yellow' : 'c-green'}`;
      }
      if ($last) {
        $last.textContent = rttStr(rtt);
        $last.className   = `gping-r ${rttClass(rtt)}`;
      }

      // Ping dot chip
      const $dots = container.querySelector(`#gp-d-${d.node_id}`);
      if ($dots) {
        const dot       = document.createElement('span');
        dot.className   = `gping-dot ${dotBg(rtt)}`;
        dot.title       = timeout ? 'Timeout' : rtt.toFixed(1) + ' ms';
        $dots.appendChild(dot);
        while ($dots.children.length > MAX_DOTS) $dots.firstChild.remove();
      }
    }

    // ── Handle traceroute hop ──────────────────────────────────────────
    function handleHop(d) {
      const $tb = container.querySelector(`#gp-tb-${d.node_id}`);
      if (!$tb) return;
      const rtts  = d.rtts || [];
      const cells = [0, 1, 2].map(i => {
        const v = rtts[i] ?? -1;
        return `<td class="${rttClass(v)}">${rttStr(v)}</td>`;
      }).join('');
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="c-cyan">${d.hop}</td>
        <td class="c-bright">${escHtml(d.ip || '*')}</td>
        <td class="c-dim"
            style="max-width:160px;overflow:hidden;text-overflow:ellipsis">
          ${escHtml(d.hostname || '')}</td>
        ${cells}
        <td class="${(d.loss_pct ?? 0) > 0 ? 'c-yellow' : 'c-dim'}">
          ${(d.loss_pct ?? 0).toFixed(0)}%</td>`;
      $tb.appendChild(tr);
    }

    // ── Node trace finished ────────────────────────────────────────────
    function handleTraceDone(d) {
      const $st = container.querySelector(`#gp-ts-${d.node_id}`);
      if ($st) {
        $st.className   = 'gping-status status-ok';
        $st.textContent = '✓';
      }
    }

    // ── Connect / disconnect ───────────────────────────────────────────
    function start(m) {
      const host = $host.value.trim();
      if (!host) { $host.focus(); return; }
      if (ws) stop();
      mode = m;

      const path   = m === 'ping' ? '/ws/globalping' : '/ws/globaltrace';
      const params = m === 'ping'
        ? { host, interval: $ivl.value }
        : { host };

      ws = new WSClient(path, params)
        .onResult((data, type) => {
          if (type === 'nodes')      { initNodes(data);       return; }
          if (type === 'ping')       { handlePing(data);      return; }
          if (type === 'hop')        { handleHop(data);       return; }
          if (type === 'trace_done') { handleTraceDone(data); return; }
        })
        .onDone(stop)
        .onError(err => { console.error('GlobalPing WS:', err); })
        .connect();

      if (m === 'ping') {
        $pingBtn.textContent  = '■ Stop';
        $pingBtn.className    = 'btn btn-stop';
        $traceBtn.disabled    = true;
      } else {
        $traceBtn.textContent = '… Tracing';
        $traceBtn.className   = 'btn btn-stop';
        $traceBtn.disabled    = true;
        $pingBtn.disabled     = true;
      }
    }

    function stop() {
      ws?.close(); ws = null;
      $pingBtn.textContent  = '▶ Ping All'; $pingBtn.className  = 'btn btn-start';
      $traceBtn.textContent = '⇢ Trace All'; $traceBtn.className = 'btn btn-ghost';
      $pingBtn.disabled = false; $traceBtn.disabled = false;
    }

    $pingBtn.addEventListener('click',
      () => (ws && mode === 'ping') ? stop() : start('ping'));
    $traceBtn.addEventListener('click',
      () => !$traceBtn.disabled && start('trace'));
    $host.addEventListener('keydown',
      e => { if (e.key === 'Enter') ws ? stop() : start('ping'); });

    return { cleanup: stop };
  },
};
