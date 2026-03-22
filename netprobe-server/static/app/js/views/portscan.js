import { WSClient, escHtml } from '../client.js';

export default {
  mount(container, prefill) {
    let ws = null;
    let openCount = 0;

    container.innerHTML = `
      <div class="input-bar">
        <input id="ps-host" type="text" placeholder="IP, host, or 10.0.0.0/24" autocomplete="off"
               autocorrect="off" autocapitalize="none" spellcheck="false"
               value="${escHtml(prefill || '')}"/>
        <div class="input-sep"></div>
        <input id="ps-ports" type="text" value="1-1024"
               style="width:100px;background:none;border:none;color:var(--fg);font-family:var(--mono);font-size:14px;outline:none"/>
        <div class="input-sep"></div>
        <select id="ps-proto" style="background:none;border:none;color:var(--fg);font-family:var(--mono);font-size:14px;outline:none">
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>
        <div class="input-sep"></div>
        <button id="ps-btn" class="btn btn-run">▶ Scan</button>
      </div>

      <div class="stat-row">
        <div class="stat-chip"><span class="stat-val" id="ps-total">—</span><span class="stat-label">Checked</span></div>
        <div class="stat-chip"><span class="stat-val c-green" id="ps-open">—</span><span class="stat-label">Open</span></div>
        <div class="stat-chip"><span class="stat-val c-yellow" id="ps-filtered">—</span><span class="stat-label">Filtered</span></div>
      </div>

      <div class="card" style="overflow-x:auto">
        <table class="result-table">
          <thead><tr>
            <th>Host</th><th>Port</th><th>State</th><th>Service</th><th>RTT</th><th>Banner</th>
          </tr></thead>
          <tbody id="ps-tbody"></tbody>
        </table>
      </div>`;

    const $host     = container.querySelector('#ps-host');
    const $ports    = container.querySelector('#ps-ports');
    const $proto    = container.querySelector('#ps-proto');
    const $btn      = container.querySelector('#ps-btn');
    const $tbody    = container.querySelector('#ps-tbody');
    const $total    = container.querySelector('#ps-total');
    const $open     = container.querySelector('#ps-open');
    const $filtered = container.querySelector('#ps-filtered');

    let total = 0, open = 0, filtered = 0;

    function stateTag(s) {
      if (s === 'open')          return `<span class="tag tag-open">open</span>`;
      if (s === 'open|filtered') return `<span class="tag tag-filtered">open|filtered</span>`;
      return `<span class="tag tag-closed">${escHtml(s)}</span>`;
    }

    function onResult(r) {
      total++;
      if (r.state === 'open') open++;
      if (r.state === 'open|filtered' || r.state === 'filtered') filtered++;
      $total.textContent    = total;
      $open.textContent     = open;
      $filtered.textContent = filtered;

      if (r.state === 'closed') return; // skip closed to keep table clean

      const row = document.createElement('tr');
      row.innerHTML = `
        <td class="c-dim">${escHtml(r.host)}</td>
        <td class="c-cyan">${r.port}</td>
        <td>${stateTag(r.state)}</td>
        <td class="c-bright">${escHtml(r.service || '')}</td>
        <td class="c-dim">${r.rtt_ms > 0 ? r.rtt_ms.toFixed(1) + ' ms' : '—'}</td>
        <td class="c-dim" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;font-size:12px">${escHtml(r.banner || '')}</td>`;
      $tbody.appendChild(row);
    }

    function start() {
      const host = $host.value.trim();
      if (!host) { $host.focus(); return; }

      total = 0; open = 0; filtered = 0;
      $total.textContent = '—';
      $open.textContent  = '—';
      $filtered.textContent = '—';
      $tbody.innerHTML   = '';

      ws = new WSClient('/ws/portscan', {
        host,
        ports: $ports.value.trim() || '1-1024',
        proto: $proto.value,
        threads: 100,
      })
        .onResult(onResult)
        .onDone(() => { done(); })
        .onError(err => { done(); console.error('PortScan WS:', err); })
        .connect();

      $btn.textContent = '■ Stop';
      $btn.className   = 'btn btn-stop';
    }

    function done() {
      ws = null;
      $btn.textContent = '▶ Scan';
      $btn.className   = 'btn btn-run';
    }

    function stop() { ws?.close(); done(); }

    $btn.addEventListener('click', () => ws ? stop() : start());
    $host.addEventListener('keydown', e => { if (e.key === 'Enter') ws ? stop() : start(); });

    return { cleanup: stop };
  },
};
