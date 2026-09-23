'use strict';

// Bump this whenever a file in STATIC below changes. Those paths carry no
// ?v=<mtime> stamp, so they are served cache-first until the cache name changes
// and the activate handler deletes the old one.
var CACHE = 'ngix-v5';
// /image.png and /banner.png were listed here but exist in no document root.
// Because addAll() is atomic they made every install reject, so the worker
// never activated and nothing was ever cached — see the install handler.
var STATIC = [
    '/assets/css/bootstrap.min.css',
    '/assets/css/flags-public.css',
    '/assets/js/jquery.min.js',
    '/assets/js/bootstrap.min.js',
    '/assets/js/jquery.bootgrid.min.js',
    '/favicon.ico'
];

self.addEventListener('install', function (e) {
    e.waitUntil(
        caches.open(CACHE).then(function (cache) {
            // Deliberately NOT cache.addAll(): that call is atomic, so a single
            // 404 rejects the whole promise, the install fails, and the worker
            // never activates — one renamed file costs the entire offline
            // cache, and it surfaces only as
            // "Failed to execute 'addAll' on 'Cache': Request failed".
            //
            // Each module now ships its own assets/ tree, so a path that
            // resolves on one host can legitimately be absent on another.
            // Cache what is there, warn about the rest, and let the fetch
            // handler fall through to the network for the misses.
            return Promise.all(STATIC.map(function (url) {
                return cache.add(url)['catch'](function (err) {
                    console.warn('[sw] precache skipped:', url, err && err.message);
                });
            }));
        })
    );
    self.skipWaiting();
});

self.addEventListener('activate', function (e) {
    e.waitUntil(
        caches.keys().then(function (keys) {
            return Promise.all(
                keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); })
            );
        })
    );
    self.clients.claim();
});

self.addEventListener('fetch', function (e) {
    if (e.request.method !== 'GET') { return; }
    var url = new URL(e.request.url);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') { return; }
    var isStatic = url.pathname.startsWith('/assets/css/') ||
        url.pathname.startsWith('/assets/js/') ||
        url.pathname.startsWith('/assets/img/') ||
        url.pathname.startsWith('/dist/') ||
        /\.(png|ico|svg|webp|jpg|jpeg|gif|css|js|woff|woff2|ttf|eot)(\?|$)/.test(url.pathname);

    if (isStatic) {
        e.respondWith(
            caches.match(e.request).then(function (cached) {
                if (cached) { return cached; }
                return fetch(e.request).then(function (res) {
                    if (res && res.ok) {
                        var clone = res.clone();
                        caches.open(CACHE).then(function (cache) { cache.put(e.request, clone); });
                    }
                    return res;
                });
            })
        );
        return;
    }

    // Dynamic API/XHR/fetch (e.g. ?stats=1 poll) — do NOT intercept. Let it hit
    // the network directly so real responses/errors aren't masked as 503.
    if (e.request.mode !== 'navigate') {
        return;
    }

    // Page navigations: network-first with a minimal offline fallback.
    e.respondWith(
        fetch(e.request).catch(function () {
            return caches.match(e.request).then(function (cached) {
                return cached || new Response('', { status: 503 });
            });
        })
    );
});