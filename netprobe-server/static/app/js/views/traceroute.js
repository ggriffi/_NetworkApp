import { WSClient, rttStr, rttClass, escHtml } from '../client.js';

export default {
  mount(container, prefill) {
    let ws = null;

    container.innerHTML = `
      <div class="input-bar">
        <input id="tr-host" type="text" placeholder="hostname or IP" autocomplete="off"
               autocorrect="off" autocapitalize="none" spellcheck="false"
               value="${escHtml(prefill || '')}"/>
        <div class="input-sep"></div>
        <label style="color:var(--fg-dim);font-size:13px;white-space:nowrap">Hops</label>
        <input id="tr-hops" type="number" value="30" min="1" max="64"
               style="width:52px;background:none;border:none;color:var(--fg);font-family:var(--mono);outline:none"/>
        <div class="input-sep"></div>
        <button id="tr-btn" class="btn btn-run">▶ Trace</button>
      </div>

      <div class="card">
        <div style="overflow-x:auto">
          <table class="result-table">
            <thead><tr>
              <th>Hop</th><th>IP</th><th>Hostname</th>
              <th>RTT 1</th><th>RTT 2</th><th>RTT 3</th>
            </tr></thead>
            <tbody id="tr-tbody"></tbody>
          </table>
        </div>
      </div>`;

    const $host  = container.querySelector('#tr-host');
    const $hops  = container.querySelector('#tr-hops');
    const $btn   = container.querySelector('#tr-btn');
    const $tbody = container.querySelector('#tr-tbody');

    function onHop(hop) {
      const rtts = hop.rtts || [];
      const rttCells = [0,1,2].map(i => {
        const v = rtts[i] ?? -1;
        return `<td class="${rttClass(v)}">${rttStr(v)}</td>`;
      }).join('');

      const row = document.createElement('tr');
      row.innerHTML = `
        <td class="c-cyan">${hop.hop}</td>
        <td class="c-bright">${escHtml(hop.ip || '*')}</td>
        <td class="c-dim" style="max-width:180px;overflow:hidden;text-overflow:ellipsis">${escHtml(hop.hostname || '')}</td>
        ${rttCells}`;
      $tbody.appendChild(row);
    }

    function start() {
      const host = $host.value.trim();
      if (!host) { $host.focus(); return; }
      $tbody.innerHTML = '';
      $btn.disabled = true;
      $btn.textContent = '… Tracing';

      ws = new WSClient('/ws/traceroute', { host, max_hops: $hops.value })
        .onResult(onHop)
        .onDone(() => {
          $btn.disabled = false;
          $btn.textContent = '▶ Trace';
          ws = null;
        })
        .onError(err => {
          $btn.disabled = false;
          $btn.textContent = '▶ Trace';
          console.error('Traceroute WS:', err);
          ws = null;
        })
        .connect();
    }

    $btn.addEventListener('click', start);
    $host.addEventListener('keydown', e => { if (e.key === 'Enter') start(); });

    return { cleanup() { ws?.close(); } };
  },
};
