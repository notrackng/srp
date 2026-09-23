$(document).ready(function() {
        var state = { current: 1, rowCount: 25, search: '', rows: [] };

        function escHtml(v) {
            return String(v === null || v === undefined ? '' : v)
                .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        }

        function svgIcon(type) {
            var strokeAttrs = ' width="14" height="14" viewBox="0 0 24 24" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"';
            var filledAttrs = ' width="16" height="16" viewBox="0 -960 960 960" fill="currentColor" focusable="false"';
            if (type === 'delete') {
                return '<span class="action-ico action-ico--filled" aria-hidden="true"><svg' + filledAttrs + '><path d="M259-104q-30.75 0-51.87-21.13Q186-146.25 186-177v-575h-41v-73h202v-34h267v34h202v73h-41v575q0 28.73-22.14 50.86Q730.72-104 702-104zm443-648H259v575h443zM357-264h73v-403h-73zm175 0h73v-403h-73zM259-752v575z"/></svg></span>';
            }
            if (type === 'plus') {
                return '<span class="action-ico" aria-hidden="true"><svg' + strokeAttrs + '><path d="M12 5v14"/><path d="M5 12h14"/></svg></span>';
            }
            return '<span class="action-ico action-ico--filled" aria-hidden="true"><svg' + filledAttrs + '><path d="M194-194h57l371-371-57-56-371 371zM88-88v-206l558-558q11-11 24.5-15.5T698-872t26.5 4 23.5 15l105 105q11 11 15 24t4 27-4.5 27-15.5 24L294-88zm666-609-57-56zM594-593l-29-28 57 56z"/></svg></span>';
        }

        var GLOBE_ICON_PATH = 'M99.333-260.667h106q-2-14.667-2.667-29t-.667-29 .667-29.667 2-30.333H99.333Q94.666-364 93-349t-1.667 30.333q0 14.667 1.667 29t6.333 29M114-422h98.667q6.667-32 18-62T260-541.333Q213.333-524.666 175.333-495T114-422m145.333 322Q242-126 230.666-156t-17.333-61.333H114q21.333 44 59.333 74.667t86 42.667m-2-322h126q-8.667-35.333-23.333-68.667t-40-59.333q-24.667 26.667-39.667 59.667t-23 68.332m171.333 0h98q-24-43.333-61.667-73.333t-84.332-45.334q18 26.667 29.333 57T428.667-422M320-42.667q-57.333 0-108-21.667t-88.333-58.999T64.334-211 42.667-318.667q0-58 21.667-108.667t59.333-88.333T212-575.333t108-22q100.667 0 175.333 62.667t95.333 156H249.333q-2 15.333-3 30.333t-1 29.666 1 29 3 29h126v43.333h-118q9.333 34.667 22.667 68.667T320-90q10 0 20.333-.667t20.333-2.667l12 45.333q-13.333 2.667-26.333 4T320-42.667m176.667-8q-8-8-8-19.333t8-19.333 19.333-8 19.333 8 8 19.333-8 19.333-19.333 8-19.333-8m0-82q0-29.333 6.667-45.333t22-25.333q22.667-13.333 28-21.667t5.333-27.667T547-282t-31-10q-20.667 0-32 13t-16.667 27.667l-36-12.667q10.667-30.667 32-48T516-329.333q35.333 0 58.333 20.333t23 57q0 23.333-8.333 37.333T556.667-184q-11.333 7.333-16.333 18.333t-5.001 33z';
        var DEVICE_ICON_PATH = 'M42.667-96v-48.667H332V-96zm74.667-88.667q-19.573 0-34.12-14.547t-14.547-34.119v-262q0-19.147 14.547-33.907T117.333-544h406q19.147 0 33.907 14.353Q572-515.3 572-496H116.667v263.333H332v48zm431.333 40v-262.667h-128v262.667zM408.667-96Q394-96 383-107t-11-25.667v-286.667q0-14.78 11-25.72Q394-456 408.667-456h152.667q14.5 0 25.253 10.947 10.746 10.94 10.746 25.72v286.667q0 14.667-10.747 25.667Q575.833-96 561.333-96zm76.667-238q8.887 0 16.113-6.667 7.22-6.666 7.22-16.666 0-8.887-7.22-16.113-7.227-7.221-16.7-7.221-9.414 0-16.08 7.22-6.667 7.227-6.667 16.7 0 9.414 6.667 16.08T485.334-334m0 58';

        function renderRow(row, idx) {
            var offer = row.offer === null || row.offer === undefined ? '' : String(row.offer);
            var ccLower = escHtml((row.country_code || '').toLowerCase());
            var ccUpper = escHtml((row.country_code || '').toUpperCase());
            // "GLOBAL" is the any-country wildcard sentinel (see offering.country_code /
            // MEETUP_OFFER_ANY_COUNTRY in redirect/_meetups/r.php) — it is not a real ISO
            // code, so the .flag-global sprite class doesn't exist and rendered as a blank
            // broken box. Show the same globe glyph used in the column header instead.
            var ccIcon = ccUpper === 'GLOBAL'
                ? '<svg width="14" height="14" viewBox="42.667 -597.333 554.666 554.666" fill="currentColor" aria-hidden="true" focusable="false"><path d="' + GLOBE_ICON_PATH + '"/></svg>'
                : '<span class="flag flag-' + ccLower + '"></span>';
            var uaRaw   = String(row.ua || '');
            var uaLower = uaRaw.toLowerCase();
            var deviceCls = uaLower.indexOf('mobile') !== -1 ? ' badge-device--mobile'
                          : uaLower.indexOf('tablet') !== -1 ? ' badge-device--tablet'
                          : '';
            // Same any-device wildcard sentinel as country_code's "GLOBAL" — show the
            // device glyph from the column header instead of bare text for that row.
            var deviceIcon = uaLower === 'global'
                ? '<svg width="14" height="14" viewBox="42.667 -544 554.666 448" fill="currentColor" aria-hidden="true" focusable="false"><path d="' + DEVICE_ICON_PATH + '"/></svg> '
                : '';
            var net    = String(row.network || '');
            var netKey = net.toLowerCase().replace(/[^a-z0-9]/g, '');
            var netCls = 'badge-net badge-net--' + (netKey || 'other');
            return '<tr>' +
                '<td><span class="td-num">' + (idx + 1) + '</span></td>' +
                '<td><span class="td-cc">' + ccIcon + '<span class="cc-label">' + ccUpper + '</span></span></td>' +
                '<td><span class="badge-device' + deviceCls + '">' + deviceIcon + escHtml(uaRaw) + '</span></td>' +
                '<td><span class="td-smartlink" title="' + escHtml(offer) + '">' + escHtml(offer) + '</span></td>' +
                '<td><span class="' + netCls + '">' + escHtml(net) + '</span></td>' +
                '<td style="text-align:right;white-space:nowrap;">' +
                    '<button type="button" class="btn btn-xs btn-default action-btn command-edit" data-row-id="' + escHtml(row.id) + '" title="Edit" aria-label="Edit">' + svgIcon('edit') + '</button> ' +
                    '<button type="button" class="btn btn-xs btn-default action-btn command-delete" data-row-id="' + escHtml(row.id) + '" title="Delete" aria-label="Delete">' + svgIcon('delete') + '</button>' +
                '</td>' +
            '</tr>';
        }

        var _netLabels = {IMONETIZEIT:'iMonetizeit',LOSPOLLOS:'LosPollos',TRAFEE:'Trafee',CUSTOM:'Custom'};
        function syncEditNetDdt(val) {
            $('#edit_network_sel').val(val);
            var btn = document.getElementById('ddt-edit-network-btn');
            if (btn) { btn.querySelector('.ddt-label').textContent = (_netLabels[val] || val); }
            var menu = document.getElementById('ddt-edit-network-menu');
            if (menu) { menu.querySelectorAll('a').forEach(function(a) { a.classList.toggle('ddt-active', a.getAttribute('data-val') === val); }); }
        }

        function bindRowActions() {
            var tbody = document.querySelector('#tbl_campaigns tbody');
            $(tbody).find('.command-edit').off('click').on('click', function() {
                var rowId = String($(this).data('row-id'));
                var row = state.rows.filter(function(r) { return String(r.id) === rowId; })[0];
                if (!row) return;
                $('#edit_id').val(row.id);
                $('#edit_country_code').val(row.country_code);
                $('#edit_ua').val(row.ua);
                $('#edit_offer').val(row.offer);
                var knownNets = ['IMONETIZEIT','LOSPOLLOS','TRAFEE','CUSTOM'];
                var rowNet = (row.network || '').toUpperCase();
                if (knownNets.indexOf(rowNet) !== -1) {
                    syncEditNetDdt(rowNet);
                    $('#edit_custom_network').hide().val('');
                    $('#edit_network').val(rowNet);
                } else {
                    syncEditNetDdt('CUSTOM');
                    $('#edit_custom_network').show().val(row.network || '');
                    $('#edit_network').val((row.network || '').toUpperCase());
                }
                $('#edit_model').modal('show');
            });
            $(tbody).find('.command-delete').off('click').on('click', function() {
                var rowId = $(this).data('row-id');
                Swal.fire({
                    title: 'Are you sure?',
                    text: "You won't be able to revert this!",
                    type: 'warning',
                    showCancelButton: true,
                    allowOutsideClick: false,
                    confirmButtonColor: '#343a40',
                    cancelButtonColor: '#6c757d',
                    confirmButtonText: 'Yes, delete it!'
                }).then(function(result) {
                    if (result.value) {
                        $.ajax({
                            type: 'POST', url: 'response.php',
                            data: { id: rowId, action: 'delete' },
                            dataType: 'json',
                            success: function() { loadData(); Swal.fire('Deleted!', 'Your file has been deleted.', 'success'); }
                        });
                    }
                });
            });
        }

        function renderPagination(total, current, rowCount) {
            var info = document.getElementById('tbl-info');
            var pg = document.getElementById('tbl-pagination');
            if (rowCount === -1 || total === 0) {
                info.textContent = total === 0 ? 'No entries' : 'Showing all ' + total + ' entries';
                pg.innerHTML = '';
                return;
            }
            var totalPages = Math.ceil(total / rowCount);
            var start = (current - 1) * rowCount + 1;
            var end = Math.min(current * rowCount, total);
            info.textContent = 'Showing ' + start + '–' + end + ' of ' + total;
            var pages = '<li class="' + (current <= 1 ? 'disabled' : '') + '"><a href="#" data-page="' + (current - 1) + '">&laquo;</a></li>';
            var s = Math.max(1, current - 2), e = Math.min(totalPages, current + 2);
            for (var i = s; i <= e; i++) {
                pages += '<li class="' + (i === current ? 'active' : '') + '"><a href="#" data-page="' + i + '">' + i + '</a></li>';
            }
            pages += '<li class="' + (current >= totalPages ? 'disabled' : '') + '"><a href="#" data-page="' + (current + 1) + '">&raquo;</a></li>';
            pg.innerHTML = pages;
            $(pg).find('a[data-page]').on('click', function(e) {
                e.preventDefault();
                var page = parseInt($(this).data('page'));
                if (page < 1 || page > totalPages) return;
                state.current = page;
                loadData();
            });
        }

        function loadData() {
            var tbody = document.querySelector('#tbl_campaigns tbody');
            tbody.innerHTML = '<tr><td colspan="6" style="padding:24px;text-align:center;color:var(--text)">Loading…</td></tr>';
            $.ajax({
                type: 'POST', url: 'response.php',
                data: { current: state.current, rowCount: state.rowCount, searchPhrase: state.search },
                dataType: 'json',
                success: function(data) {
                    if (!data || !data.rows) {
                        tbody.innerHTML = '<tr><td colspan="6" style="padding:24px;text-align:center;">Error loading data.</td></tr>';
                        return;
                    }
                    state.rows = data.rows;
                    if (data.rows.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="6" style="padding:24px;text-align:center;color:var(--text)">No data available.</td></tr>';
                        document.getElementById('tbl-info').textContent = 'No entries';
                        document.getElementById('tbl-pagination').innerHTML = '';
                    } else {
                        tbody.innerHTML = data.rows.map(function(r, i) { return renderRow(r, i); }).join('');
                        bindRowActions();
                        renderPagination(data.total, data.current, data.rowCount);
                    }
                },
                error: function() {
                    tbody.innerHTML = '<tr><td colspan="6" style="padding:24px;text-align:center;color:var(--danger)">Failed to load data.</td></tr>';
                }
            });
        }

        var searchTimer;
        $('#tbl-search').on('input', function() {
            clearTimeout(searchTimer);
            var val = this.value;
            searchTimer = setTimeout(function() { state.search = val; state.current = 1; loadData(); }, 300);
        });

        $('#tbl-rowcount').on('change', function() {
            state.rowCount = parseInt(this.value); state.current = 1; loadData();
        });
        (function(){var btn=document.getElementById('ddt-rowcount-btn'),menu=document.getElementById('ddt-rowcount-menu'),inp=document.getElementById('tbl-rowcount');if(!btn||!menu||!inp)return;btn.addEventListener('click',function(e){e.stopPropagation();menu.classList.toggle('open');});menu.addEventListener('click',function(e){var a=e.target.closest?e.target.closest('a'):(e.target.tagName==='A'?e.target:null);if(!a)return;e.preventDefault();var v=a.getAttribute('data-val');menu.querySelectorAll('a').forEach(function(el){el.classList.remove('ddt-active');});a.classList.add('ddt-active');btn.querySelector('.ddt-label').textContent=a.textContent;inp.value=v;menu.classList.remove('open');$(inp).trigger('change');});document.addEventListener('click',function(){menu.classList.remove('open');});})();
        (function(){var btn=document.getElementById('ddt-c-net-btn'),menu=document.getElementById('ddt-c-net-menu'),inp=document.getElementById('c_net');if(!btn||!menu||!inp)return;btn.addEventListener('click',function(e){e.stopPropagation();menu.classList.toggle('open');});menu.addEventListener('click',function(e){var a=e.target.closest?e.target.closest('a'):(e.target.tagName==='A'?e.target:null);if(!a)return;e.preventDefault();var v=a.getAttribute('data-val');menu.querySelectorAll('a').forEach(function(el){el.classList.remove('ddt-active');});a.classList.add('ddt-active');btn.querySelector('.ddt-label').textContent=a.textContent.trim();inp.value=v;menu.classList.remove('open');$(inp).trigger('change');});document.addEventListener('click',function(){menu.classList.remove('open');});})();
        (function(){var btn=document.getElementById('ddt-edit-network-btn'),menu=document.getElementById('ddt-edit-network-menu'),inp=document.getElementById('edit_network_sel');if(!btn||!menu||!inp)return;btn.addEventListener('click',function(e){e.stopPropagation();menu.classList.toggle('open');});menu.addEventListener('click',function(e){var a=e.target.closest?e.target.closest('a'):(e.target.tagName==='A'?e.target:null);if(!a)return;e.preventDefault();var v=a.getAttribute('data-val');menu.querySelectorAll('a').forEach(function(el){el.classList.remove('ddt-active');});a.classList.add('ddt-active');btn.querySelector('.ddt-label').textContent=a.textContent.trim();inp.value=v;menu.classList.remove('open');$(inp).trigger('change');});document.addEventListener('click',function(){menu.classList.remove('open');});})();

        function ajaxAction(action) {
            $.ajax({
                type: 'POST', url: 'response.php',
                data: $('#frm_' + action).serializeArray(),
                dataType: 'json',
                success: function() { $('#' + action + '_model').modal('hide'); loadData(); }
            });
        }

        function showNetworkHint(net) {
            var h = (typeof _networkHints !== 'undefined') ? _networkHints[net] : null;
            if (!h) { $('#hint-smartlink').hide(); return; }
            $('#hint-sl-line').html(h.sl);
            $('#hint-pb-line').html(h.pb);
            $('#hint-smartlink').show();
        }

        $('#c_net').on('change', function() {
            var val = this.value;
            if (val === 'CUSTOM') {
                $('#custom_network').show().focus();
                $('#network').val('');
            } else {
                $('#custom_network').hide().val('');
                $('#network').val(val);
            }
            showNetworkHint(val);
        });

        $('#custom_network').on('input', function() {
            var v = $.trim($(this).val()).toUpperCase();
            $('#network').val(v);
        });

        $('#command-add').on('click', function() {
            $('#c_net').val('');
            var _cnetBtn=document.getElementById('ddt-c-net-btn');if(_cnetBtn){_cnetBtn.querySelector('.ddt-label').textContent='* Select Network';}
            var _cnetMenu=document.getElementById('ddt-c-net-menu');if(_cnetMenu){_cnetMenu.querySelectorAll('a').forEach(function(a){a.classList.remove('ddt-active');});}
            $('#custom_network').hide().val('');
            $('#country_code').val('global');
            $('#ua').val('global');
            $('#offer').val('');
            $('#network').val('');
            $('#hint-smartlink').hide();
            $('#add_model').modal('show');
        });

        $('#btn_add').on('click', function() {
            if (!$.trim($('#network').val()) || !$.trim($('#offer').val())) {
                Swal.fire({ allowOutsideClick: false, type: 'error', title: 'Oops...', text: 'Something went wrong! {Required all fields}' });
                return false;
            }
            ajaxAction('add');
            return true;
        });

        $('#edit_network_sel').on('change', function() {
            var val = this.value;
            if (val === 'CUSTOM') {
                $('#edit_custom_network').show().focus();
                $('#edit_network').val('');
            } else {
                $('#edit_custom_network').hide().val('');
                $('#edit_network').val(val);
            }
        });

        $('#edit_custom_network').on('input', function() {
            $('#edit_network').val($.trim($(this).val()).toUpperCase());
        });

        $('#btn_edit').on('click', function() { ajaxAction('edit'); });

        loadData();
    });
    document.addEventListener('click', function(e) {
        var target = e.target;
        var btn = target && typeof target.closest === 'function' ? target.closest('#btn-logout') : null;

        if (!btn) {
            return;
        }

        e.preventDefault();

        var href = btn.getAttribute('href') || btn.getAttribute('data-href') || '/logout';
        var toast = document.getElementById('logout-toast');

        if (toast) {
            toast.classList.add('show');
        }

        window.setTimeout(function() {
            window.location.href = href;
        }, 900);
    });
