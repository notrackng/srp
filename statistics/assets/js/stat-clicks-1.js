$(document).ready(function () {
    'use strict';

    $('.pc-nav-toggle').on('click', function (e) {
        var $dropdown = $(this).closest('.pc-nav-dropdown');

        if ($dropdown.length < 1) {
            return;
        }

        e.preventDefault();
        e.stopPropagation();

        $('.pc-nav-dropdown').not($dropdown).removeClass('open')
            .find('.pc-nav-toggle').attr('aria-expanded', 'false');

        $dropdown.toggleClass('open');
        $(this).attr('aria-expanded', $dropdown.hasClass('open') ? 'true' : 'false');
    });

    $(document).on('click', function () {
        $('.pc-nav-dropdown').removeClass('open')
            .find('.pc-nav-toggle').attr('aria-expanded', 'false');
    });

    $('.pc-nav-menu').on('click', function (e) {
        e.stopPropagation();
    });

    if ($.fn.tableExport) {
        $('#perf-click-table').tableExport({
            headers: true,
            footers: false,
            formats: ['xlsx'],
            fileName: 'click-' + new Date().toISOString().slice(0, 10),
            bootstrap: false,
            exportButtons: true,
            position: 'bottom',
            ignoreRows: null,
            ignoreCols: null,
            trimWhitespace: false,
            RTL: false,
            sheetname: 'id'
        });
        var $pcButtons = $('#perf-click-table').find('caption').children().detach();
        $pcButtons.appendTo('#pc-export');
    }

    $('.filter').on('input', function () {
        var needle = String($(this).val() || '').toLowerCase();

        $('.pc-row').each(function () {
            var $row = $(this);
            var clickId = String($row.attr('data-click-id') || '');

            if (clickId.indexOf(needle) !== -1) {
                $row.removeClass('is-hidden');
            } else {
                $row.addClass('is-hidden');
            }
        });
    });

    // column sorting (current page rows; keeps filter + export intact)
    (function () {
        var table = document.getElementById('perf-click-table');
        if (!table) {
            return;
        }

        var tbody = table.querySelector('tbody');
        var ths = Array.prototype.slice.call(table.querySelectorAll('thead th'));
        var numericCols = {0: true};

        ths.forEach(function (th, idx) {
            th.addEventListener('click', function () {
                var dir = th.classList.contains('sort-asc') ? 'desc' : 'asc';
                ths.forEach(function (o) {
                    o.classList.remove('sort-asc', 'sort-desc');
                });
                th.classList.add(dir === 'asc' ? 'sort-asc' : 'sort-desc');

                var mult = dir === 'asc' ? 1 : -1;
                var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr.pc-row'));

                rows.sort(function (a, b) {
                    var av = a.children[idx] ? a.children[idx].textContent.trim() : '';
                    var bv = b.children[idx] ? b.children[idx].textContent.trim() : '';

                    if (numericCols[idx]) {
                        var an = parseFloat(av.replace(/[^0-9.\-]/g, '')) || 0;
                        var bn = parseFloat(bv.replace(/[^0-9.\-]/g, '')) || 0;
                        return (an - bn) * mult;
                    }

                    return av.toLowerCase().localeCompare(bv.toLowerCase()) * mult;
                });

                rows.forEach(function (r) {
                    tbody.appendChild(r);
                });
            });
        });
    })();

    $(document).on('submit', '#logout-form', function(e) {
    e.preventDefault();

    var form = this;
    var toast = document.getElementById('logout-toast');

    if (toast) {
        toast.classList.add('show');
    }

    window.setTimeout(function() {
        form.submit();
    }, 900);
});
});
