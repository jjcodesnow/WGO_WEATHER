// WGO 9 Weather service worker: shows alert notifications.
// It does not cache anything, so app updates still load right away.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (e) => {
  let m = {};
  try { m = e.data ? e.data.json() : {}; } catch (err) {}
  e.waitUntil(self.registration.showNotification(m.title || 'WGO 9 Weather', {
    body: m.body || 'You have a new weather alert.',
    tag: m.tag,
    icon: 'apple-touch-icon.png',
    badge: 'favicon-32.png',
    data: { url: './' },
  }));
});

// Tapping a notification opens the app on that alert's area of the map.
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const id = e.notification.tag && e.notification.tag !== 'test' ? e.notification.tag : '';
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
    for (const c of list) {
      if ('focus' in c) {
        if (id) c.postMessage({ alert: id });
        return c.focus();
      }
    }
    return self.clients.openWindow(id ? './?alert=' + encodeURIComponent(id) : './');
  }));
});
