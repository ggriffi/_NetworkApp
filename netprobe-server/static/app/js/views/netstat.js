import { apiFetch, escHtml } from '../client.js';

export default {
  mount(container) {
    let timer = null;

    container.innerHTML = `
      <div class="input-bar" style="flex-wrap:wrap;gap:8px">
        <select id="ns-proto" style="background:none;border:none;color:var(--fg);font-family:var(--mono);font-size:14px;outline:none">
          <option value="">All Proto</option>
          <option value="TCP">TCP</option><option value="UDP">UDP</option>
          <option value="TCP6">TCP6</option><option value="UDP6">UDP6</option>
        </select>
        <div class="input-sep"></div>
        <select id="ns-state" style="background:none;border:none;color:var(--fg);font-family:var(--mono);font-size:14px;outline:none">
          <option value="">All States</option>
          <option value="LISTEN">LISTEN</option>
          <option value="ESTABLISHED">ESTABLISHED</option>
          <option value="TIME_WAIT">TIME_WAIT</option>
          <option value="CLOSE_WAIT">CLOSE_WAIT</option>
        </select>
        <div class="input-sep"></div>
        <input id="ns-port" type="number" placeholder="Port" min="1" max="65535"
               style="width:76px;background:none;border:none;color:var(--fg);font-family:var(--mono);font-size:14px;outline:none"/>
        <div class="input-sep"></div>
        <input id="ns-proc" type="text" placeholder="Process" autocomplete="off"
               style="width:100px;background:none;border:none;color:var(--fg);font-family:var(--mono);font-size:14px;outline:none"/>
        <div class="input-sep"></div>
        <select id="ns-refresh" style="background:none;border:none;color:var(--fg);font-family:var(--mono);font-size:14px;outline:none">
          <option value="0">Manual</option>
          <option value="2000">2s</option>
          <option value="5000" selected>5s</option>
          <option value="10000">10s</option>
        </select>
        <div class="input-sep"></div>
        <button id="ns-btn" class="btn btn-run">▶ Refresh</button>
      </div>

      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <span id="ns-count" style="font-family:var(--mono);font-size:12px;color:var(--fg-dim)">— connections</span>
        <span id="ns-badge" class="badge badge-idle">IDLE</span>
      </div>

      <div class="card" style="overflow-x:auto;padding:0">
        <table class="result-table">
          <thead><tr>
            <th>Proto</th><th>Local</th><th>Port</th><th>Remote</th><th>Port</th><th>State</th><th>PID</th><th>Process</th>
          </tr></thead>
          <tbody id="ns-tbody"></tbody>
        </table>
      </div>`;

    const $proto   = container.querySelector('#ns-proto');
    const $state   = container.querySelector('#ns-state');
    const $port    = container.querySelector('#ns-port');
    const $proc    = container.querySelector('#ns-proc');
    const $refresh = container.querySelector('#ns-refresh');
    const $btn     = container.querySelector('#ns-btn');
    const $tbody   = container.querySelector('#ns-tbody');
    const $count   = container.querySelector('#ns-count');
    const $badge   = container.querySelector('#ns-badge');

    function stateTag(s) {
      const cls = s === 'LISTEN'      ? 'tag-listen'
                : s === 'ESTABLISHED' ? 'tag-estab'
                : s === 'TIME_WAIT'   ? 'tag-timewait'
                : '';
      return cls ? `<span class="tag ${cls}">${escHtml(s)}</span>` : `<span class="c-dim">${escHtml(s)}</span>`;
    }

    async function refresh() {
      $badge.className = 'badge badge-running';
      $badge.textContent = 'RUNNING';
      try {
        const params = {};
        if ($proto.value)  params.proto   = $proto.value;
        if ($state.value)  params.state   = $state.value;
        if ($port.value)   params.port    = $port.value;
        if ($proc.value)   params.process = $proc.value;

        const data = await apiFetch('/api/netstat', params);
        $count.textContent = `${data.length} connection${data.length !== 1 ? 's' : ''}`;

        $tbody.innerHTML = data.map(r => `
          <tr>
            <td style="font-family:var(--mono);font-size:12px;color:var(--cyan)">${escHtml(r.proto)}</td>
            <td class="c-bright" style="font-family:var(--mono);font-size:12px">${escHtml(r.local_addr || '*')}</td>
            <td class="c-cyan" style="font-family:var(--mono);font-size:12px">${r.local_port || '*'}</td>
            <td class="c-dim" style="font-family:var(--mono);font-size:12px">${escHtml(r.remote_addr || '')}</td>
            <td class="c-dim" style="font-family:var(--mono);font-size:12px">${r.remote_port || ''}</td>
            <td>${stateTag(r.state)}</td>
            <td class="c-dim" style="font-family:var(--mono);font-size:12px">${r.pid || ''}</td>
            <td class="c-bright" style="font-size:12px">${escHtml(r.process || '')}</td>
          </tr>`).join('');

        $badge.className   = 'badge badge-done';
        $badge.textContent = 'DONE';
      } catch (e) {
        $badge.className   = 'badge badge-error';
        $badge.textContent = 'ERROR';
        $count.textContent = e.message;
      }
    }

    function scheduleRefresh() {
      clearInterval(timer);
      const interval = parseInt($refresh.value);
      if (interval > 0) timer = setInterval(refresh, interval);
    }

    $btn.addEventListener('click', () => { refresh(); scheduleRefresh(); });
    $refresh.addEventListener('change', scheduleRefresh);

    // Auto-start
    refresh();
    scheduleRefresh();

    return { cleanup() { clearInterval(timer); } };
  },
};
