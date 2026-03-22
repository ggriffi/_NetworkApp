import { apiFetch, escHtml } from '../client.js';

export default {
  mount(container, prefill) {
    container.innerHTML = `
      <div class="input-bar">
        <input id="ssl-host" type="text" placeholder="hostname" autocomplete="off"
               autocorrect="off" autocapitalize="none" spellcheck="false"
               value="${escHtml(prefill || '')}"/>
        <div class="input-sep"></div>
        <input id="ssl-port" type="number" value="443" min="1" max="65535"
               style="width:64px;background:none;border:none;color:var(--fg);font-family:var(--mono);outline:none"/>
        <div class="input-sep"></div>
        <button id="ssl-btn" class="btn btn-run">▶ Inspect</button>
      </div>
      <div id="ssl-results"></div>`;

    const $host    = container.querySelector('#ssl-host');
    const $port    = container.querySelector('#ssl-port');
    const $btn     = container.querySelector('#ssl-btn');
    const $results = container.querySelector('#ssl-results');

    async function inspect() {
      const host = $host.value.trim();
      if (!host) { $host.focus(); return; }
      $results.innerHTML = `<div class="empty-state pulsing"><div class="empty-icon">🔒</div><div class="empty-text">Connecting…</div></div>`;

      try {
        const r = await apiFetch('/api/ssl', { host, port: $port.value });

        if (r.error) throw new Error(r.error);

        const daysClass = r.days_remaining < 14 ? 'c-red'
                        : r.days_remaining < 30  ? 'c-orange'
                        : r.days_remaining < 90  ? 'c-yellow'
                        : 'c-green';

        const expiredBadge = r.expired
          ? `<span class="badge badge-error">EXPIRED</span>`
          : `<span class="badge badge-done">VALID</span>`;

        const sans = (r.san || []).map(s =>
          `<span style="background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:2px 8px;font-size:12px;font-family:var(--mono)">${escHtml(s)}</span>`
        ).join(' ');

        $results.innerHTML = `
          <div class="card">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
              <span style="font-size:28px">🔒</span>
              <div>
                <div style="font-size:17px;font-weight:700;color:var(--fg)">${escHtml(r.subject_cn || host)}</div>
                <div style="font-size:13px;color:var(--fg-dim)">${escHtml(r.issuer)}</div>
              </div>
              <div style="margin-left:auto">${expiredBadge}</div>
            </div>

            <div class="stat-row">
              <div class="stat-chip"><span class="stat-val ${daysClass}">${r.days_remaining}</span><span class="stat-label">Days left</span></div>
              <div class="stat-chip"><span class="stat-val c-cyan">${escHtml(r.version || '—')}</span><span class="stat-label">TLS</span></div>
              <div class="stat-chip"><span class="stat-val">${r.verified ? '✓' : '✗'}</span><span class="stat-label">Verified</span></div>
            </div>

            <table class="result-table" style="margin-bottom:12px">
              <tbody>
                <tr><td class="c-dim" style="width:120px">Subject</td><td class="c-bright">${escHtml(r.subject)}</td></tr>
                <tr><td class="c-dim">Issuer</td><td class="c-bright">${escHtml(r.issuer)}</td></tr>
                <tr><td class="c-dim">Cipher</td><td class="c-bright">${escHtml(r.cipher)}</td></tr>
                <tr><td class="c-dim">Valid from</td><td>${escHtml(r.not_before)}</td></tr>
                <tr><td class="c-dim">Expires</td><td class="${daysClass}">${escHtml(r.not_after)}</td></tr>
              </tbody>
            </table>

            ${sans ? `<div class="card-title">Subject Alt Names</div><div style="display:flex;flex-wrap:wrap;gap:6px">${sans}</div>` : ''}
          </div>`;
      } catch (e) {
        $results.innerHTML = `<div class="empty-state"><div class="empty-icon" style="color:var(--red)">✕</div><div class="empty-text">${escHtml(e.message)}</div></div>`;
      }
    }

    $btn.addEventListener('click', inspect);
    $host.addEventListener('keydown', e => { if (e.key === 'Enter') inspect(); });

    return { cleanup() {} };
  },
};
