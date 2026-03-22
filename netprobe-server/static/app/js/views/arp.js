import { WSClient, escHtml } from '../client.js';
import { navigate } from '../app.js';

export default {
  mount(container, prefill) {
    let ws = null;

    container.innerHTML = `
      <div class="input-bar">
        <input id="arp-net" type="text" placeholder="192.168.1.0/24" autocomplete="off"
               autocorrect="off" autocapitalize="none" spellcheck="false"
               value="${escHtml(prefill || '')}"/>
        <div class="input-sep"></div>
        <button id="arp-btn" class="btn btn-run">▶ Scan</button>
      </div>

      <div class="stat-row">
        <div class="stat-chip"><span class="stat-val" id="arp-found">—</span><span class="stat-label">Found</span></div>
      </div>

      <div class="card" style="overflow-x:auto;padding:0">
        <table class="result-table">
          <thead><tr>
            <th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th></th>
          </tr></thead>
          <tbody id="arp-tbody"></tbody>
        </table>
      </div>`;

    const $net   = container.querySelector('#arp-net');
    const $btn   = container.querySelector('#arp-btn');
    const $tbody = container.querySelector('#arp-tbody');
    const $found = container.querySelector('#arp-found');
    let count = 0;

    function onResult(r) {
      count++;
      $found.textContent = count;
      const row = document.createElement('tr');
      row.innerHTML = `
        <td class="c-cyan" style="font-family:var(--mono)">${escHtml(r.ip)}</td>
        <td class="c-bright" style="font-family:var(--mono);font-size:12px">${escHtml(r.mac || '—')}</td>
        <td class="c-dim" style="font-size:12px">${escHtml(r.vendor || '')}</td>
        <td class="c-dim" style="font-size:12px">${escHtml(r.hostname || '')}</td>
        <td style="white-space:nowrap">
          <button class="icon-btn" style="font-size:12px" title="Ping" data-ping="${escHtml(r.ip)}">◈</button>
          <button class="icon-btn" style="font-size:12px" title="Port Scan" data-scan="${escHtml(r.ip)}">⬡</button>
          <button class="icon-btn" style="font-size:12px" title="WHOIS" data-whois="${escHtml(r.ip)}">?</button>
          <button class="icon-btn" style="font-size:12px" title="Wake-on-LAN" data-wol="${escHtml(r.mac || '')}">⏻</button>
        </td>`;

      row.querySelector('[data-ping]').addEventListener('click', e =>
        navigate('ping', e.currentTarget.dataset.ping));
      row.querySelector('[data-scan]').addEventListener('click', e =>
        navigate('portscan', e.currentTarget.dataset.scan));
      row.querySelector('[data-whois]').addEventListener('click', e =>
        navigate('whois', e.currentTarget.dataset.whois));
      row.querySelector('[data-wol]').addEventListener('click', e =>
        navigate('wol', e.currentTarget.dataset.wol));

      $tbody.appendChild(row);
    }

    function start() {
      const net = $net.value.trim();
      if (!net) { $net.focus(); return; }
      $tbody.innerHTML = '';
      count = 0;
      $found.textContent = '0';

      ws = new WSClient('/ws/arp', { network: net })
        .onResult(onResult)
        .onDone(() => { done(); })
        .onError(err => { done(); console.error('ARP WS:', err); })
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
    $net.addEventListener('keydown', e => { if (e.key === 'Enter') ws ? stop() : start(); });

    return { cleanup: stop };
  },
};
