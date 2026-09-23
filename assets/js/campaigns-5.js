/* NGIX patch: move public modals to body to avoid backdrop covering modal */
(function() {
    'use strict';

    function moveModalsToBody() {
        document.querySelectorAll('.modal').forEach(function(modal) {
            if (modal.parentElement !== document.body) {
                document.body.appendChild(modal);
            }
        });
    }

    function normalizeDropdowns() {
        document.addEventListener('click', function(event) {
            var button = event.target && typeof event.target.closest === 'function'
                ? event.target.closest('.ddt-btn,[data-toggle="dropdown"]')
                : null;

            if (!button) {
                return;
            }

            var holder = button.closest('.ddt,.dropdown,.btn-group,.actions');
            if (holder) {
                holder.style.position = 'relative';
                holder.style.zIndex = '12100';
            }
        }, true);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            moveModalsToBody();
            normalizeDropdowns();
        }, {once: true});
        return;
    }

    moveModalsToBody();
    normalizeDropdowns();
}());
