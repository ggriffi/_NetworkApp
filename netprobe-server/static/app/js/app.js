// ── Tool registry ─────────────────────────────────────────────────────────────

import PingView       from './views/ping.js';
import TracerouteView from './views/traceroute.js';
import MTRView        from './views/mtr.js';
import GlobalPingView from './views/globalping.js';
import PortScanView   from './views/portscan.js';
import DNSView        from './views/dns.js';
import SSLView        from './views/ssl.js';
import HTTPView       from './views/http.js';
import WHOISView      from './views/whois.js';
import NetstatView    from './views/netstat.js';
import WoLView        from './views/wol.js';
import ARPView        from './views/arp.js';
import SettingsView   from './views/settings.js';

const TOOLS = [
  // group, id, label, icon, view-module
  { group: 'NETWORK',   id: 'globalping', label: 'Global Ping',  icon: '⊛', view: GlobalPingView },
  { group: 'NETWORK',   id: 'ping',       label: 'Ping',         icon: '◈', view: PingView       },
  { group: 'NETWORK',   id: 'traceroute', label: 'Traceroute',   icon: '⇢', view: TracerouteView },
  { group: 'NETWORK',   id: 'mtr',        label: 'MTR',          icon: '⊞', view: MTRView        },
  { group: 'DISCOVERY', id: 'portscan',   label: 'Port Scan',    icon: '⬡', view: PortScanView   },
  { group: 'DISCOVERY', id: 'dns',        label: 'DNS',          icon: '◎', view: DNSView        },
  { group: 'DISCOVERY', id: 'arp',        label: 'ARP Scan',     icon: '⬟', view: ARPView        },
  { group: 'DISCOVERY', id: 'netstat',    label: 'Netstat',      icon: '⊟', view: NetstatView    },
  { group: 'SECURITY',  id: 'ssl',        label: 'SSL / TLS',    icon: '🔒', view: SSLView        },
  { group: 'SECURITY',  id: 'http',       label: 'HTTP Probe',   icon: '↯', view: HTTPView       },
  { group: 'SECURITY',  id: 'whois',      label: 'WHOIS',        icon: '?', view: WHOISView      },
  { group: 'TOOLS',     id: 'wol',        label: 'Wake-on-LAN',  icon: '⏻', view: WoLView        },
  { group: 'TOOLS',     id: 'settings',   label: 'Settings',     icon: '⚙', view: SettingsView   },
];

// ── State ─────────────────────────────────────────────────────────────────────

let _currentTool  = null;  // { ...toolDef }
let _currentClean = null;  // cleanup fn from active view
let _wsMonitor    = null;  // connection health WS

// ── DOM refs ──────────────────────────────────────────────────────────────────

const $sidebar  = document.getElementById('sidebar');
const $overlay  = document.getElementById('overlay');
const $navList  = document.getElementById('nav-list');
const $view     = document.getElementById('view');
const $title    = document.getElementById('topbar-title');
const $connBadge = document.getElementById('conn-badge');
const $menuBtn  = document.getElementById('menu-btn');
const $closeBtn = document.getElementById('sidebar-close');

// ── Sidebar nav builder ───────────────────────────────────────────────────────

function buildNav() {
  let lastGroup = null;
  TOOLS.forEach(tool => {
    if (tool.group !== lastGroup) {
      const g = document.createElement('div');
      g.className = 'nav-group-label';
      g.textContent = tool.group;
      $navList.appendChild(g);
      lastGroup = tool.group;
    }

    const item = document.createElement('div');
    item.className  = 'nav-item';
    item.dataset.id = tool.id;
    item.innerHTML  = `<span class="nav-icon">${tool.icon}</span>${tool.label}`;
    item.addEventListener('click', () => { navigate(tool.id); closeSidebar(); });
    $navList.appendChild(item);
  });
}

function setActiveNav(id) {
  $navList.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.id === id);
  });
}

// ── Navigation ────────────────────────────────────────────────────────────────

export function navigate(id, prefill = null) {
  const tool = TOOLS.find(t => t.id === id);
  if (!tool) return;

  // Teardown current view
  if (_currentClean) { try { _currentClean(); } catch {} }
  _currentClean = null;
  _currentTool  = tool;

  // Update chrome
  setActiveNav(id);
  $title.textContent = tool.label;
  $view.innerHTML    = '';
  $view.classList.add('fadein');
  $view.addEventListener('animationend', () => $view.classList.remove('fadein'), { once: true });

  // Mount new view
  const result = tool.view.mount($view, prefill);
  if (result?.cleanup) _currentClean = result.cleanup;

  // Persist last route
  sessionStorage.setItem('np_route', id);
}

// ── Connection health badge ───────────────────────────────────────────────────

async function checkHealth() {
  try {
    const resp = await fetch('/health', { cache: 'no-store' });
    if (resp.ok) {
      $connBadge.className = 'conn-badge connected';
      $connBadge.title     = 'Server reachable';
    } else {
      throw new Error();
    }
  } catch {
    $connBadge.className = 'conn-badge error';
    $connBadge.title     = 'Server unreachable';
  }
}

// ── Mobile drawer ─────────────────────────────────────────────────────────────

function openSidebar() {
  $sidebar.classList.add('open');
  $overlay.hidden = false;
}

function closeSidebar() {
  $sidebar.classList.remove('open');
  $overlay.hidden = true;
}

$menuBtn.addEventListener('click', openSidebar);
$closeBtn.addEventListener('click', closeSidebar);
$overlay.addEventListener('click', closeSidebar);

// ── Service worker registration ───────────────────────────────────────────────

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/app/sw.js', { scope: '/app/' })
      .catch(() => {}); // non-fatal
  });
}

// ── Boot ──────────────────────────────────────────────────────────────────────

buildNav();
checkHealth();
setInterval(checkHealth, 30_000);

const lastRoute = sessionStorage.getItem('np_route') || 'globalping';
navigate(lastRoute);
