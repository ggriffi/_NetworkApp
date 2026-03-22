import { WSClient, rttStr, rttClass, escHtml } from '../client.js';

export default {
  mount(container, prefill) {
    let ws = null;

    container.innerHTML = `
      <div class="input-bar">
        <input id="mtr-host" type="text" placeholder="hostname or IP" autocomplete="off"
               autocorrect="off" autocapitalize="none" spellcheck="false"
               value="${escHtml(prefill || '')}"/>
        <div class="input-sep"></div>
        <button id="mtr-btn" class="btn btn-start">▶ Start</button>
      </div>

      <div class="card" style="overflow-x:auto">
        <table class="result-table">
          <thead><tr>
            <th>Hop</th><th>Host</th><th>Loss%</th>
            <th>Snt</th><th>Last</th><th>Avg</th><th>Best</th><th>Worst</th><th>StDev</th>
          </tr></thead>
          <tbody id="mtr-tbody"></tbody>
        </table>
      </div>`;

    const $host  = container.querySelector('#mtr-host');
    const $btn   = container.querySelector('#mtr-btn');
    const $tbody = container.querySelector('#mtr-tbody');

    // rowMap: hop_num → <tr>
    const rowMap = new Map();

    function onUpdate(rows) {
      rows.forEach(r => {
        const lossNum = parseFloat(r.loss_pct);
        const lossClass = lossNum >= 20 ? 'c-red' : lossNum > 0 ? 'c-yellow' : 'c-green';
        const host = r.hostname || r.ip || '*';

        if (!rowMap.has(r.hop)) {
          const tr = document.createElement('tr');
          $tbody.appendChild(tr);
          rowMap.set(r.hop, tr);
        }
        const tr = rowMap.get(r.hop);
        tr.innerHTML = `
          <td class="c-cyan">${r.hop}</td>
          <td class="c-bright" style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${escHtml(host)}</td>
          <td class="${lossClass}">${r.loss_pct.toFixed(1)}%</td>
          <td class="c-dim">${r.sent}</td>
          <td class="${rttClass(r.last_ms)}">${rttStr(r.last_ms)}</td>
          <td class="${rttClass(r.avg_ms)}">${rttStr(r.avg_ms)}</td>
          <td class="c-green">${rttStr(r.best_ms === 999999 ? -1 : r.best_ms)}</td>
          <td class="c-orange">${rttStr(r.worst_ms)}</td>
          <td class="c-dim">${r.stdev_ms > 0 ? r.stdev_ms.toFixed(1) + ' ms' : '—'}</td>`;
      });
    }

    function start() {
      const host = $host.value.trim();
      if (!host) { $host.focus(); return; }
      $tbody.innerHTML = '';
      rowMap.clear();

      ws = new WSClient('/ws/mtr', { host, interval: 1 })
        .onResult((data, type) => { if (type === 'update') onUpdate(data); })
        .onError(err => { stop(); console.error('MTR WS:', err); })
        .connect();

      $btn.textContent = '■ Stop';
      $btn.className   = 'btn btn-stop';
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
