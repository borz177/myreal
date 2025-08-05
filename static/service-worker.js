// service-worker.js

const CACHE_NAME = 'pwa-cache-v1';
const STATIC_ASSETS = [
  '/',
  '/offline.html',
  '/manifest.json',
  '/static/css/style.css',
  '/static/css/flatpickr.min.css',
  '/static/js/app.js',
  '/static/js/flatpickr.js',
  '/static/js/inputmask.min.js',
  '/static/icons/icon-192x192.png',
  '/static/icons/icon-512x512.png',
    '/static/js/particles.min.js'
];

// Предварительное кэширование
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(STATIC_ASSETS))
      .then(() => self.skipWaiting())
  );
});

// Удаление старого кэша при обновлении
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.filter(name => name !== CACHE_NAME)
                  .map(name => caches.delete(name))
      );
    })
  );
  self.clients.claim();
});

// Обработка запросов
self.addEventListener('fetch', (event) => {
  // Пропускаем внешние домены и API
  if (new URL(event.request.url).origin !== self.location.origin) {
    event.respondWith(fetch(event.request));
    return;
  }

  // Для HTML-страниц (навигация)
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() => caches.match('/offline.html'))
    );
    return;
  }

  // Для остальных ресурсов — сначала кэш, потом сеть (для обновления)
  event.respondWith(
    caches.match(event.request).then(cached => {
      return cached || fetch(event.request).then(response => {
        const cacheCopy = response.clone();
        caches.open(CACHE_NAME).then(cache => {
          cache.put(event.request, cacheCopy);
        });
        return response;
      });
    })
  );
});

// Отправка сообщения в клиент при активации нового SW
self.addEventListener('message', (event) => {
  if (event.data.action === 'skipWaiting') {
    self.skipWaiting();
  }
});