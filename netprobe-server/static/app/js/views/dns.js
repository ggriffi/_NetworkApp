import { apiFetch, escHtml, copyText } from '../client.js';

export default {
  mount(container, prefill) {
    container.innerHTML = `
      <div class="input-bar">
        <input id="dns-host" type="text" placeholder="domain or IP" autocomplete="off"
               autocorrect="off" autocapitalize="none" spellcheck="false"
               value="${escHtml(prefill || '')}"/>
        <div class="input-sep"></div>
        <select id="dns-type" style="background:none;border:none;color:var(--fg);font-family:var(--mono);font-size:14px;outline:none">
          <option value="A,AAAA,MX,NS,TXT,CNAME,SOA">ALL</option>
          <option value="A">A</option>
          <option value="AAAA">AAAA</option>
          <option value="MX">MX</option>
          <option value="NS">NS</option>
          <option value="TXT">TXT</option>
          <option value="CNAME">CNAME</option>
          <option value="SOA">SOA</option>
          <option value="PTR">PTR</option>
        </select>
        <div class="input-sep"></div>
        <button id="dns-btn" class="btn btn-run">▶ Lookup</button>
      </div>

      <div id="dns-doh-row" style="display:flex;gap:8px;margin-bottom:12px;align-items:center">
        <button id="dns-doh-btn" class="btn btn-ghost" style="font-size:12px">Compare DoH</button>
        <span id="dns-doh-status" style="font-size:12px;color:var(--fg-dim)"></span>
      </div>

      <div id="dns-results"></div>
      <div id="dns-doh-results"></div>`;

    const $host    = container.querySelector('#dns-host');
    const $type    = container.querySelector('#dns-type');
    const $btn     = container.querySelector('#dns-btn');
    const $dohBtn  = container.querySelector('#dns-doh-btn');
    const $dohStat = container.querySelector('#dns-doh-status');
    const $results = container.querySelector('#dns-results');
    const $dohRes  = container.querySelector('#dns-doh-results');

    function renderResults(data) {
      if (!data.length) {
        $results.innerHTML = `<div class="empty-state"><div class="empty-icon">◎</div><div class="empty-text">No records found</div></div>`;
        return;
      }
      const rows = data.map(r => `
        <tr>
          <td class="c-cyan">${escHtml(r.record_type || r.type || '')}</td>
          <td class="c-bright" style="word-break:break-all">${escHtml(r.value || r.data || '')}</td>
          <td class="c-dim">${r.ttl != null ? r.ttl + 's' : '—'}</td>
          <td style="text-align:right">
            <button class="icon-btn" style="font-size:12px" onclick="navigator.clipboard?.writeText('${escHtml(r.value || '')}')">⎘</button>
          </td>
        </tr>`).join('');

      $results.innerHTML = `
        <div class="card" style="overflow-x:auto">
          <div class="card-title">DNS Records (${data.length})</div>
          <table class="result-table">
            <thead><tr><th>Type</th><th>Value</th><th>TTL</th><th></th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>`;
    }

    async function lookup() {
      const host = $host.value.trim();
      if (!host) { $host.focus(); return; }
      $results.innerHTML = `<div class="empty-state pulsing"><div class="empty-icon">◎</div><div class="empty-text">Resolving…</div></div>`;
      $dohRes.innerHTML  = '';
      try {
        const data = await apiFetch('/api/dns', { host, types: $type.value });
        renderResults(data);
      } catch (e) {
        $results.innerHTML = `<div class="empty-state"><div class="empty-icon" style="color:var(--red)">✕</div><div class="empty-text">${escHtml(e.message)}</div></div>`;
      }
    }

    async function dohCompare() {
      const host = $host.value.trim();
      if (!host) { $host.focus(); return; }
      $dohStat.textContent = 'Querying…';
      $dohRes.innerHTML = '';
      try {
        const data = await apiFetch('/api/doh', { domain: host, type: 'A' });
        const makeList = (arr) => arr.length
          ? arr.map(v => `<div class="c-bright" style="font-family:var(--mono);font-size:13px;padding:2px 0">${escHtml(v)}</div>`).join('')
          : '<span class="c-dim">no results</span>';

        $dohRes.innerHTML = `
          <div class="stat-row">
            <div class="card" style="flex:1">
              <div class="card-title" style="color:var(--cyan)">Google DoH</div>
              ${makeList(data.google || [])}
            </div>
            <div class="card" style="flex:1">
              <div class="card-title" style="color:var(--orange)">Cloudflare DoH</div>
              ${makeList(data.cloudflare || [])}
            </div>
          </div>`;
        $dohStat.textContent = '';
      } catch (e) {
        $dohStat.textContent = e.message;
      }
    }

    $btn.addEventListener('click', lookup);
    $dohBtn.addEventListener('click', dohCompare);
    $host.addEventListener('keydown', e => { if (e.key === 'Enter') lookup(); });

    return { cleanup() {} };
  },
};
