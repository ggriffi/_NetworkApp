import { apiFetch, escHtml, copyText } from '../client.js';

const KEYWORDS = {
  domain:  /\b(Domain Name|Domain|domain_name)\b/i,
  ip:      /\b(NetRange|inetnum|CIDR|IP Address|Address)\b/i,
  date:    /\b(Updated|Created|Expir|Registration|Last Modified)\b/i,
  email:   /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i,
};

function colorize(raw) {
  return escHtml(raw).split('\n').map(line => {
    if (!line.trim() || line.startsWith('%') || line.startsWith('#')) {
      return `<span class="c-dim">${line}</span>`;
    }
    const [key, ...rest] = line.split(':');
    if (!rest.length) return line;
    const val = rest.join(':');
    let cls = '';
    if (KEYWORDS.domain.test(key)) cls = 'kw-domain';
    else if (KEYWORDS.ip.test(key)) cls = 'kw-ip';
    else if (KEYWORDS.date.test(key)) cls = 'kw-date';
    const valHtml = KEYWORDS.email.test(val)
      ? val.replace(KEYWORDS.email, m => `<span class="kw-email">${m}</span>`)
      : val;
    return `<span class="kw-key">${escHtml(key)}:</span>${cls ? `<span class="${cls}">${valHtml}</span>` : valHtml}`;
  }).join('\n');
}

export default {
  mount(container, prefill) {
    container.innerHTML = `
      <div class="input-bar">
        <input id="w-target" type="text" placeholder="domain or IP" autocomplete="off"
               autocorrect="off" autocapitalize="none" spellcheck="false"
               value="${escHtml(prefill || '')}"/>
        <div class="input-sep"></div>
        <button id="w-btn" class="btn btn-run">▶ Lookup</button>
        <button id="w-copy" class="btn btn-ghost" style="font-size:12px">⎘ Copy</button>
      </div>
      <div class="log-box" id="w-output" style="min-height:120px">
        <span class="c-dim">Enter a domain or IP and click Lookup.</span>
      </div>`;

    const $target = container.querySelector('#w-target');
    const $btn    = container.querySelector('#w-btn');
    const $copy   = container.querySelector('#w-copy');
    const $output = container.querySelector('#w-output');

    let rawText = '';

    async function lookup() {
      const target = $target.value.trim();
      if (!target) { $target.focus(); return; }
      $output.innerHTML = `<span class="c-dim pulsing">Querying WHOIS for ${escHtml(target)}…</span>`;
      rawText = '';
      try {
        const r = await apiFetch('/api/whois', { target });
        rawText = r.raw || '';
        $output.innerHTML = colorize(rawText);
      } catch (e) {
        $output.innerHTML = `<span class="c-red">${escHtml(e.message)}</span>`;
      }
    }

    $btn.addEventListener('click', lookup);
    $copy.addEventListener('click', () => { if (rawText) copyText(rawText); });
    $target.addEventListener('keydown', e => { if (e.key === 'Enter') lookup(); });

    return { cleanup() {} };
  },
};
