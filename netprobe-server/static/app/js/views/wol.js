import { apiFetch, escHtml } from '../client.js';

const STORAGE_KEY = 'np_wol_targets';

function loadTargets() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); }
  catch { return []; }
}

function saveTargets(arr) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(arr));
}

export default {
  mount(container, prefill) {
    let targets = loadTargets();

    container.innerHTML = `
      <div class="card">
        <div class="card-title">Send Magic Packet</div>
        <div class="field-group">
          <label class="field-label">MAC Address</label>
          <input id="wol-mac" class="field-input" placeholder="AA:BB:CC:DD:EE:FF" autocomplete="off"
                 autocorrect="off" autocapitalize="none" spellcheck="false"
                 value="${escHtml(prefill || '')}"/>
        </div>
        <div class="field-group">
          <label class="field-label">Broadcast Address</label>
          <input id="wol-bc" class="field-input" value="255.255.255.255" autocomplete="off"/>
        </div>
        <div class="field-group">
          <label class="field-label">Port</label>
          <input id="wol-port" class="field-input" type="number" value="9" min="1" max="65535" style="max-width:120px"/>
        </div>
        <div style="display:flex;gap:8px;margin-top:4px">
          <button id="wol-send" class="btn btn-start" style="flex:1">⏻ Send</button>
          <button id="wol-save" class="btn btn-ghost">Save target</button>
        </div>
        <div id="wol-status" style="margin-top:10px;font-family:var(--mono);font-size:13px;min-height:20px"></div>
      </div>

      <div class="card">
        <div class="card-title">Saved Targets</div>
        <div id="wol-list"></div>
        <div id="wol-empty" class="c-dim" style="font-size:13px;padding:8px 0">No saved targets yet.</div>
      </div>`;

    const $mac    = container.querySelector('#wol-mac');
    const $bc     = container.querySelector('#wol-bc');
    const $port   = container.querySelector('#wol-port');
    const $send   = container.querySelector('#wol-send');
    const $save   = container.querySelector('#wol-save');
    const $status = container.querySelector('#wol-status');
    const $list   = container.querySelector('#wol-list');
    const $empty  = container.querySelector('#wol-empty');

    function renderList() {
      $empty.hidden = targets.length > 0;
      $list.innerHTML = targets.map((t, i) => `
        <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)">
          <div style="flex:1">
            <div style="font-family:var(--mono);font-size:13px;color:var(--fg)">${escHtml(t.name || t.mac)}</div>
            <div style="font-size:11px;color:var(--fg-dim)">${escHtml(t.mac)} · ${escHtml(t.broadcast)}:${t.port}</div>
          </div>
          <button class="btn btn-start" style="font-size:12px;padding:5px 10px" data-i="${i}">⏻</button>
          <button class="icon-btn c-dim" data-del="${i}" style="font-size:14px">✕</button>
        </div>`).join('');

      $list.querySelectorAll('[data-i]').forEach(btn => {
        btn.addEventListener('click', () => {
          const t = targets[+btn.dataset.i];
          $mac.value  = t.mac;
          $bc.value   = t.broadcast;
          $port.value = t.port;
          sendPacket();
        });
      });

      $list.querySelectorAll('[data-del]').forEach(btn => {
        btn.addEventListener('click', () => {
          targets.splice(+btn.dataset.del, 1);
          saveTargets(targets);
          renderList();
        });
      });
    }

    async function sendPacket() {
      const mac = $mac.value.trim();
      if (!mac) { $mac.focus(); return; }
      $status.textContent = '⏳ Sending…';
      $status.className   = 'c-dim';
      try {
        const r = await apiFetch('/api/wol', {}, 'POST', {
          mac,
          broadcast: $bc.value.trim() || '255.255.255.255',
          port: parseInt($port.value) || 9,
        });
        if (r.success) {
          $status.textContent = `✓ Magic packet sent to ${r.mac}`;
          $status.className   = 'c-green';
        } else {
          throw new Error('Server returned failure');
        }
      } catch (e) {
        $status.textContent = `✕ ${e.message}`;
        $status.className   = 'c-red';
      }
    }

    $send.addEventListener('click', sendPacket);

    $save.addEventListener('click', () => {
      const mac = $mac.value.trim();
      if (!mac) { $mac.focus(); return; }
      const name = prompt('Label for this target (optional):', mac);
      if (name === null) return;
      targets.push({ name: name || mac, mac, broadcast: $bc.value.trim(), port: parseInt($port.value) || 9 });
      saveTargets(targets);
      renderList();
    });

    renderList();

    return { cleanup() {} };
  },
};
