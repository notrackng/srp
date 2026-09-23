/* NGIX patch: public logout/button spinner correction */
(function() {
    'use strict';

    var spinner = '<svg class="btn-spin" viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="8" cy="8" r="6" stroke-opacity=".3"></circle><path d="M8 2a6 6 0 0 1 6 6"></path></svg> ';

    function closest(node, selector) {
        return node && typeof node.closest === 'function' ? node.closest(selector) : null;
    }

    function setLoading(button, label) {
        if (!button || button.dataset.ngixLoading === '1') {
            return;
        }

        button.dataset.ngixLoading = '1';
        button.dataset.ngixOriginalHtml = button.innerHTML;
        button.classList.add('is-loading');
        button.setAttribute('aria-busy', 'true');
        button.innerHTML = spinner + label;
    }

    function ensureLogoutToast() {
        var toast = document.getElementById('logout-toast');
        if (toast) {
            return toast;
        }

        toast = document.createElement('div');
        toast.id = 'logout-toast';
        toast.textContent = 'Logging out…';
        document.body.appendChild(toast);
        return toast;
    }

    document.addEventListener('click', function(event) {
        var button = closest(event.target, '#btn-logout,.logout-btn');
        if (!button) {
            return;
        }

        var href = button.getAttribute('href') || button.getAttribute('data-href') || '?logout';
        if (href === '#' || href === '') {
            return;
        }

        event.preventDefault();
        event.stopImmediatePropagation();

        if (button.dataset.ngixSubmitting === '1') {
            return;
        }

        button.dataset.ngixSubmitting = '1';
        setLoading(button, 'Logout…');

        var toast = ensureLogoutToast();
        toast.classList.add('show');

        window.setTimeout(function() {
            window.location.href = href;
        }, 650);
    }, true);
}());
