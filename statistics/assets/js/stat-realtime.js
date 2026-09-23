/* NGIX patch: enable native right-click even when a global blocker exists */
(function () {
    'use strict';

    function clearInlineContextBlockers(root) {
        if (!root || !root.querySelectorAll) {
            return;
        }

        var nodes = [];

        if (root.documentElement) {
            nodes.push(root.documentElement);
        }

        if (root.body) {
            nodes.push(root.body);
        }

        Array.prototype.forEach.call(
            root.querySelectorAll('[oncontextmenu], [onselectstart]'),
            function (node) {
                nodes.push(node);
            }
        );

        nodes.forEach(function (node) {
            node.oncontextmenu = null;
            node.onselectstart = null;
            node.removeAttribute('oncontextmenu');
            node.removeAttribute('onselectstart');
        });
    }

    function allowContextMenu(event) {
        event.stopImmediatePropagation();
    }

    window.oncontextmenu = null;
    document.oncontextmenu = null;

    window.addEventListener('contextmenu', allowContextMenu, true);
    document.addEventListener('contextmenu', allowContextMenu, true);

    clearInlineContextBlockers(document);

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            clearInlineContextBlockers(document);
        }, {once: true});
    } else {
        clearInlineContextBlockers(document);
    }
}());
