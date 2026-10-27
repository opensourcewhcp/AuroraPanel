// AuroraPanel service worker: lets the panel be installed as an app and keeps
// its own static files (scripts, styles, icons, fonts) for a quick start.
// It never stores /api/ answers, nothing about the server is kept on the device, 
// and always asks the server first, so a panel update shows up straight away.
const CACHE = "aurora-static-v1";

self.addEventListener("install", () => self.skipWaiting());

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) if (key !== CACHE) await caches.delete(key);
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/ddns/") || url.pathname.startsWith("/nic/")) return;
  const isPage = req.mode === "navigate";
  if (!isPage && !/\.(js|css|png|svg|jpg|ico|woff2?|ttf|json)$/.test(url.pathname)) return;
  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    try {
      const res = await fetch(req);
      if (res.ok && res.type === "basic") {
        // keep one copy per file: drop the previous version's ?v=… entry
        for (const old of await cache.keys()) {
          const o = new URL(old.url);
          if (!isPage && o.pathname === url.pathname && o.search !== url.search) cache.delete(old);
        }
        cache.put(isPage ? "/" : req, res.clone());
      }
      return res;
    } catch (e) {
      const hit = await cache.match(isPage ? "/" : req);
      if (hit) return hit;
      throw e;
    }
  })());
});
