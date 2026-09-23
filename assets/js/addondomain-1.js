(function (window, document) {
    'use strict';

    function ensureToastRoot() {
        var root = document.querySelector('.admin-toast-root');
        if (root) {
            return root;
        }
        root = document.createElement('div');
        root.className = 'admin-toast-root';
        root.setAttribute('aria-live', 'polite');
        document.body.appendChild(root);
        return root;
    }

    function showToast(type, title, text) {
        var root = ensureToastRoot();
        var item = document.createElement('div');
        var normalizedType = type === 'error' ? 'error' : (type === 'success' ? 'success' : 'info');
        item.className = 'admin-toast admin-toast--' + normalizedType;
        if (title) {
            var strong = document.createElement('strong');
            strong.textContent = title;
            item.appendChild(strong);
        }
        if (text) {
            var span = document.createElement('span');
            span.textContent = text;
            item.appendChild(span);
        }
        root.appendChild(item);
        window.setTimeout(function () {
            item.classList.add('admin-toast--removing');
            window.setTimeout(function () {
                if (item.parentNode) item.parentNode.removeChild(item);
            }, 180);
        }, 2600);
    }

    function confirmDialog(options) {
        return new Promise(function (resolve) {
            var backdrop = document.createElement('div');
            backdrop.className = 'admin-fallback-backdrop';

            var dialog = document.createElement('div');
            dialog.className = 'admin-fallback-dialog';

            var head = document.createElement('div');
            head.className = 'admin-fallback-head';
            head.textContent = options.title || 'Confirm action';

            var body = document.createElement('div');
            body.className = 'admin-fallback-body';
            body.textContent = options.text || 'Continue?';

            var actions = document.createElement('div');
            actions.className = 'admin-fallback-actions';

            var cancel = document.createElement('button');
            cancel.type = 'button';
            cancel.className = 'btn btn-default btn-sm';
            cancel.textContent = options.cancelButtonText || 'Cancel';

            var ok = document.createElement('button');
            ok.type = 'button';
            ok.className = 'btn btn-primary btn-sm';
            ok.textContent = options.confirmButtonText || 'OK';

            function close(value) {
                if (backdrop.parentNode) {
                    backdrop.parentNode.removeChild(backdrop);
                }
                resolve({ value: value, isConfirmed: value });
            }

            cancel.addEventListener('click', function () {
                close(false);
            });
            ok.addEventListener('click', function () {
                close(true);
            });

            actions.appendChild(cancel);
            actions.appendChild(ok);
            dialog.appendChild(head);
            dialog.appendChild(body);
            dialog.appendChild(actions);
            backdrop.appendChild(dialog);
            document.body.appendChild(backdrop);
            ok.focus();
        });
    }

    window.showToast = showToast;

    if (!window.Swal || typeof window.Swal.fire !== 'function') {
        window.Swal = {
            fire: function (argOne, argTwo, argThree) {
                var options = typeof argOne === 'object' ? argOne : {
                    title: String(argOne || ''),
                    text: String(argTwo || ''),
                    type: String(argThree || 'info')
                };

                if (options.showCancelButton) {
                    return confirmDialog(options);
                }

                showToast(options.type || options.icon || 'info', options.title || '', options.text || '');
                return {
                    then: function (callback) {
                        if (typeof callback === 'function') {
                            window.setTimeout(function () {
                                callback({ value: true, isConfirmed: true });
                            }, 0);
                        }
                        return this;
                    }
                };
            }
        };
    }
}(window, document));
