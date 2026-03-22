// NetProbe Service Worker — cache shell assets, pass API/WS through
const CACHE = 'netprobe-v1';
const SHELL = [
  '/app/',
  '/app/index.html',
  '/app/manifest.json',
  '/app/css/app.css',
  '/app/js/app.js',
  '/app/js/client.js',
  '/app/js/views/ping.js',
  '/app/js/views/traceroute.js',
  '/app/js/views/mtr.js',
  '/app/js/views/portscan.js',
  '/app/js/views/dns.js',
  '/app/js/views/ssl.js',
  '/app/js/views/http.js',
  '/app/js/views/whois.js',
  '/app/js/views/netstat.js',
  '/app/js/views/wol.js',
  '/app/js/views/arp.js',
  '/app/js/views/settings.js',
  '/app/icons/icon-192.svg',
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // Let API, WS, docs pass through uncached
  if (url.pathname.startsWith('/api/') ||
      url.pathname.startsWith('/ws/') ||
      url.pathname.startsWith('/docs') ||
      url.pathname === '/health') {
    return;
  }
  e.respondWith(
    caches.match(e.request).then(cached => cached || fetch(e.request))
  );
});
