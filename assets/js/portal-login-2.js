/* NGIX patch: auto-hide .msg toast */
(function(){
    'use strict';

    function initMsgToasts() {
        var nodes = document.querySelectorAll('.msg');

        if (!nodes.length) {
            return;
        }

        Array.prototype.forEach.call(nodes, function(node, index) {
            var isOk = node.classList.contains('msg-ok');
            var visibleDelay = 40 + (index * 80);
            var hideDelay = 4200 + (index * 350);
            var bottom = 14 + (index * 58);

            node.setAttribute('role', isOk ? 'status' : 'alert');
            node.setAttribute('aria-live', isOk ? 'polite' : 'assertive');
            node.style.bottom = String(bottom) + 'px';

            window.setTimeout(function() {
                node.classList.add('show');
            }, visibleDelay);

            window.setTimeout(function() {
                node.classList.remove('show');
                node.classList.add('is-hiding');

                window.setTimeout(function() {
                    node.hidden = true;
                }, 240);
            }, hideDelay);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initMsgToasts, {once: true});
        return;
    }

    initMsgToasts();
}());
