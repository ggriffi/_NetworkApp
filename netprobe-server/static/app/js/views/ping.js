import { WSClient, rttStr, rttClass, escHtml, Sparkline } from '../client.js';

export default {
  mount(container, prefill) {
    let ws = null;
    let results = [];
    let spark = null;

    container.innerHTML = `
      <div class="input-bar">
        <input id="p-host" type="text" placeholder="hostname or IP" autocomplete="off"
               autocorrect="off" autocapitalize="none" spellcheck="false"
               value="${escHtml(prefill || '')}"/>
        <div class="input-sep"></div>
        <button id="p-btn" class="btn btn-start">▶ Start</button>
      </div>

      <div class="stat-row">
        <div class="stat-chip"><span class="stat-val" id="p-sent">—</span><span class="stat-label">Sent</span></div>
        <div class="stat-chip"><span class="stat-val c-green" id="p-recv">—</span><span class="stat-label">Recv</span></div>
        <div class="stat-chip"><span class="stat-val" id="p-loss">—</span><span class="stat-label">Loss</span></div>
        <div class="stat-chip"><span class="stat-val" id="p-last">—</span><span class="stat-label">Last</span></div>
        <div class="stat-chip"><span class="stat-val" id="p-avg">—</span><span class="stat-label">Avg</span></div>
        <div class="stat-chip"><span class="stat-val" id="p-best">—</span><span class="stat-label">Best</span></div>
        <div class="stat-chip"><span class="stat-val" id="p-worst">—</span><span class="stat-label">Worst</span></div>
        <div class="stat-chip"><span class="stat-val" id="p-jitter">—</span><span class="stat-label">Jitter</span></div>
      </div>

      <div class="sparkline-wrap">
        <canvas class="sparkline" id="p-spark" height="60"></canvas>
      </div>

      <div class="card">
        <div class="card-title">Results</div>
        <div style="overflow-x:auto">
          <table class="result-table">
            <thead><tr>
              <th>#</th><th>Host</th><th>IP</th><th>RTT</th><th>TTL</th>
            </tr></thead>
            <tbody id="p-tbody"></tbody>
          </table>
        </div>
      </div>`;

    const $host  = container.querySelector('#p-host');
    const $btn   = container.querySelector('#p-btn');
    const $tbody = container.querySelector('#p-tbody');
    const $sent  = container.querySelector('#p-sent');
    const $recv  = container.querySelector('#p-recv');
    const $loss  = container.querySelector('#p-loss');
    const $last  = container.querySelector('#p-last');
    const $avg   = container.querySelector('#p-avg');
    const $best  = container.querySelector('#p-best');
    const $worst = container.querySelector('#p-worst');
    const $jitter= container.querySelector('#p-jitter');

    const canvas = container.querySelector('#p-spark');
    spark = new Sparkline(canvas);

    let sent = 0, recv = 0, rtts = [], minR = Infinity, maxR = -Infinity;

    function updateStats() {
      const loss = sent ? ((sent - recv) / sent * 100).toFixed(1) + '%' : '—';
      const avg  = rtts.length ? (rtts.reduce((a,b)=>a+b,0)/rtts.length).toFixed(1) : '—';
      const jitter = rtts.length > 1
        ? (() => { const m=+avg; return Math.sqrt(rtts.reduce((a,v)=>a+(v-m)**2,0)/rtts.length).toFixed(1); })()
        : '—';

      $sent.textContent  = sent;
      $recv.textContent  = recv;
      $loss.textContent  = loss;
      $avg.textContent   = avg !== '—' ? avg + ' ms' : '—';
      $best.textContent  = minR < Infinity ? minR.toFixed(1) + ' ms' : '—';
      $worst.textContent = maxR > -Infinity ? maxR.toFixed(1) + ' ms' : '—';
      $jitter.textContent = jitter !== '—' ? jitter + ' ms' : '—';

      const lossNum = parseFloat(loss);
      $loss.className = 'stat-val ' + (lossNum >= 20 ? 'red' : lossNum > 0 ? 'yellow' : 'green');
    }

    function onResult(r) {
      sent++;
      const isTimeout = r.rtt_ms < 0;
      if (!isTimeout) {
        recv++;
        rtts.push(r.rtt_ms);
        if (r.rtt_ms < minR) minR = r.rtt_ms;
        if (r.rtt_ms > maxR) maxR = r.rtt_ms;
      }
      spark.push(r.rtt_ms);

      const cls = rttClass(r.rtt_ms);
      $last.textContent = rttStr(r.rtt_ms);
      $last.className   = 'stat-val ' + cls.replace('c-','');

      const row = document.createElement('tr');
      row.innerHTML = `
        <td class="c-dim">${r.seq}</td>
        <td class="c-bright">${escHtml(r.host)}</td>
        <td class="c-dim">${escHtml(r.ip)}</td>
        <td class="${cls}">${rttStr(r.rtt_ms)}</td>
        <td class="c-dim">${isTimeout ? '—' : r.ttl}</td>`;

      $tbody.prepend(row);
      if ($tbody.children.length > 100) $tbody.lastChild.remove();
      updateStats();
    }

    function start() {
      const host = $host.value.trim();
      if (!host) { $host.focus(); return; }
      results = []; sent = 0; recv = 0; rtts = [];
      minR = Infinity; maxR = -Infinity;
      $tbody.innerHTML = '';
      updateStats();

      ws = new WSClient('/ws/ping', { host, interval: 1 })
        .onResult(onResult)
        .onDone(stop)
        .onError(err => { stop(); console.error('Ping WS:', err); })
        .connect();

      $btn.textContent  = '■ Stop';
      $btn.className    = 'btn btn-stop';
    }

    function stop() {
      ws?.close(); ws = null;
      $btn.textContent = '▶ Start';
      $btn.className   = 'btn btn-start';
    }

    $btn.addEventListener('click', () => ws ? stop() : start());
    $host.addEventListener('keydown', e => { if (e.key === 'Enter') ws ? stop() : start(); });

    return { cleanup: stop };
  },
};
