(function($){
    function ddCloseAll() {
        document.querySelectorAll('.dd-wrap.is-open').forEach(function(wrap) {
            wrap.classList.remove('is-open');
            var trigger = wrap.querySelector('.dd-trigger');
            if (trigger) {
                trigger.setAttribute('aria-expanded', 'false');
            }
        });
    }

    function getItemValue(item) {
        return item.getAttribute('data-val') || item.getAttribute('data-value') || '';
    }

    function selectDropdownItem(wrap, item) {
        var label = wrap.querySelector('.dd-trigger-label');
        var optionLabel = item.querySelector('.dd-option-label');
        var select = wrap.querySelector('select');
        var value = getItemValue(item);

        wrap.querySelectorAll('.dd-option').forEach(function(option) {
            option.removeAttribute('aria-selected');
        });
        item.setAttribute('aria-selected', 'true');

        if (label && optionLabel) {
            label.textContent = optionLabel.textContent.trim();
        }

        if (select) {
            select.value = value;
            $(select).trigger('change');
        }

        ddCloseAll();
    }

    document.addEventListener('click', function(event) {
        var trigger = event.target.closest('.dd-trigger');
        var item = event.target.closest('.dd-option');
        var wrap;

        if (trigger) {
            wrap = trigger.closest('.dd-wrap');
            if (!wrap) {
                return;
            }

            event.preventDefault();
            event.stopPropagation();

            if (wrap.classList.contains('is-open')) {
                ddCloseAll();
                return;
            }

            ddCloseAll();
            wrap.classList.add('is-open');
            trigger.setAttribute('aria-expanded', 'true');
            return;
        }

        if (item) {
            wrap = item.closest('.dd-wrap');
            if (!wrap) {
                return;
            }

            event.preventDefault();
            event.stopPropagation();
            selectDropdownItem(wrap, item);
            return;
        }

        if (!event.target.closest('.dd-wrap')) {
            ddCloseAll();
        }
    });

    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            ddCloseAll();
        }
    });
})(jQuery);
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js');
}
document.addEventListener('click', function(e) {
    var target = e.target;
    var btn = target && typeof target.closest === 'function' ? target.closest('#btn-logout') : null;

    if (!btn) {
        return;
    }

    var toast = document.getElementById('logout-toast');

    if (toast) {
        toast.classList.add('show');
    }

    // Let the click proceed as a normal submit of the CSRF-protected
    // logout <form> (see public/index.php) — the browser navigates away
    // as the server processes it, so no manual redirect is needed here.
});
