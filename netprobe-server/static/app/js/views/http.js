import { apiFetch, escHtml, rttClass } from '../client.js';

export default {
  mount(container, prefill) {
    container.innerHTML = `
      <div class="input-bar">
        <input id="http-url" type="url" placeholder="https://example.com" autocomplete="off"
               autocorrect="off" autocapitalize="none" spellcheck="false"
               value="${escHtml(prefill || '')}"/>
        <div class="input-sep"></div>
        <select id="http-method" style="background:none;border:none;color:var(--fg);font-family:var(--mono);font-size:14px;outline:none">
          <option>GET</option><option>HEAD</option>
        </select>
        <div class="input-sep"></div>
        <button id="http-btn" class="btn btn-run">▶ Probe</button>
      </div>
      <div id="http-results"></div>`;

    const $url     = container.querySelector('#http-url');
    const $method  = container.querySelector('#http-method');
    const $btn     = container.querySelector('#http-btn');
    const $results = container.querySelector('#http-results');

    async function probe() {
      let url = $url.value.trim();
      if (!url) { $url.focus(); return; }
      if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

      $results.innerHTML = `<div class="empty-state pulsing"><div class="empty-icon">↯</div><div class="empty-text">Probing…</div></div>`;

      try {
        const r = await apiFetch('/api/http', { url, method: $method.value, follow_redirects: true });

        if (r.error) throw new Error(r.error);

        const statusClass = r.status_code < 300 ? 'c-green'
                          : r.status_code < 400 ? 'c-yellow'
                          : r.status_code < 500 ? 'c-orange'
                          : 'c-red';

        const redirectChain = (r.redirect_chain || []).map(u =>
          `<div style="font-family:var(--mono);font-size:12px;padding:3px 0;color:var(--fg-mid)">${escHtml(u)}</div>`
        ).join('→ ');

        const headers = Object.entries(r.headers || {}).map(([k,v]) => `
          <tr>
            <td class="c-dim" style="white-space:nowrap">${escHtml(k)}</td>
            <td class="c-bright" style="word-break:break-all;font-size:12px">${escHtml(v)}</td>
          </tr>`).join('');

        $results.innerHTML = `
          <div class="stat-row">
            <div class="stat-chip"><span class="stat-val ${statusClass}">${r.status_code}</span><span class="stat-label">Status</span></div>
            <div class="stat-chip"><span class="stat-val ${rttClass(r.ttfb_ms)}">${r.ttfb_ms > 0 ? r.ttfb_ms.toFixed(0) + ' ms' : '—'}</span><span class="stat-label">TTFB</span></div>
            <div class="stat-chip"><span class="stat-val">${r.total_ms > 0 ? r.total_ms.toFixed(0) + ' ms' : '—'}</span><span class="stat-label">Total</span></div>
            <div class="stat-chip"><span class="stat-val c-dim">${r.content_length > 0 ? (r.content_length/1024).toFixed(1) + ' KB' : '—'}</span><span class="stat-label">Size</span></div>
          </div>

          ${redirectChain ? `
          <div class="card">
            <div class="card-title">Redirect chain</div>
            ${redirectChain}
            <div style="font-family:var(--mono);font-size:12px;padding:3px 0;color:var(--cyan)">${escHtml(r.final_url)}</div>
          </div>` : `
          <div class="card">
            <div class="card-title">Final URL</div>
            <div style="font-family:var(--mono);font-size:13px;color:var(--cyan);word-break:break-all">${escHtml(r.final_url)}</div>
          </div>`}

          <div class="card" style="overflow-x:auto">
            <div class="card-title">Response Headers</div>
            <table class="result-table">
              <thead><tr><th>Header</th><th>Value</th></tr></thead>
              <tbody>${headers}</tbody>
            </table>
          </div>`;
      } catch (e) {
        $results.innerHTML = `<div class="empty-state"><div class="empty-icon" style="color:var(--red)">✕</div><div class="empty-text">${escHtml(e.message)}</div></div>`;
      }
    }

    $btn.addEventListener('click', probe);
    $url.addEventListener('keydown', e => { if (e.key === 'Enter') probe(); });

    return { cleanup() {} };
  },
};
