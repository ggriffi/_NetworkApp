import { getSettings, saveSettings, apiFetch, escHtml } from '../client.js';

export default {
  mount(container) {
    const s = getSettings();

    container.innerHTML = `
      <div class="card">
        <div class="card-title">Server</div>
        <div class="field-group">
          <label class="field-label">API Key</label>
          <input id="cfg-key" class="field-input" type="password"
                 placeholder="Leave blank if no auth configured"
                 value="${escHtml(s.apiKey)}" autocomplete="off" autocorrect="off"/>
        </div>
        <div style="display:flex;gap:8px;margin-top:4px">
          <button id="cfg-save" class="btn btn-start" style="flex:1">Save</button>
          <button id="cfg-test" class="btn btn-ghost">Test connection</button>
        </div>
        <div id="cfg-status" style="margin-top:10px;font-family:var(--mono);font-size:13px;min-height:20px"></div>
      </div>

      <div class="card">
        <div class="card-title">About</div>
        <table class="result-table">
          <tbody>
            <tr><td class="c-dim">App</td><td class="c-bright">NetProbe PWA</td></tr>
            <tr><td class="c-dim">Server</td><td class="c-bright" id="cfg-ver">—</td></tr>
            <tr><td class="c-dim">URL</td><td class="c-dim" style="font-family:var(--mono);font-size:12px">${escHtml(location.origin)}</td></tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="card-title">Install</div>
        <p style="color:var(--fg-mid);font-size:14px;line-height:1.6;margin-bottom:12px">
          To install NetProbe on your iPhone: open this page in <strong>Safari</strong>,
          tap the <strong>Share</strong> button, then tap <strong>Add to Home Screen</strong>.
        </p>
        <p style="color:var(--fg-dim);font-size:13px">
          The app will open full-screen with no browser chrome, just like a native app.
        </p>
      </div>`;

    const $key    = container.querySelector('#cfg-key');
    const $save   = container.querySelector('#cfg-save');
    const $test   = container.querySelector('#cfg-test');
    const $status = container.querySelector('#cfg-status');
    const $ver    = container.querySelector('#cfg-ver');

    function showStatus(msg, ok) {
      $status.textContent = msg;
      $status.className   = ok ? 'c-green' : 'c-red';
    }

    $save.addEventListener('click', () => {
      saveSettings({ apiKey: $key.value });
      showStatus('✓ Saved', true);
    });

    async function testConn() {
      $status.textContent = 'Testing…';
      $status.className   = 'c-dim';
      try {
        const r = await apiFetch('/health');
        $ver.textContent = r.version || '—';
        showStatus(`✓ Connected — server v${r.version}`, true);
      } catch (e) {
        showStatus(`✕ ${e.message}`, false);
      }
    }

    $test.addEventListener('click', testConn);

    // Auto-fetch version
    apiFetch('/health').then(r => { $ver.textContent = r.version || '—'; }).catch(() => {});

    return { cleanup() {} };
  },
};
