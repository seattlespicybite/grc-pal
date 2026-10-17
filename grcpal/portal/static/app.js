// Progressive enhancement only: every page works without JavaScript.
(function () {
  // Drag and drop onto the upload area fills the file input.
  document.querySelectorAll('[data-drop]').forEach(function (zone) {
    var input = zone.querySelector('input[type=file]');
    var label = zone.querySelector('[data-file-label]');
    function show() { if (input.files.length && label) label.textContent = input.files[0].name; }
    input.addEventListener('change', show);
    ['dragenter', 'dragover'].forEach(function (e) {
      zone.addEventListener(e, function (ev) { ev.preventDefault(); zone.classList.add('over'); });
    });
    ['dragleave', 'drop'].forEach(function (e) {
      zone.addEventListener(e, function () { zone.classList.remove('over'); });
    });
    zone.addEventListener('drop', function (ev) {
      ev.preventDefault();
      if (ev.dataTransfer.files.length) { input.files = ev.dataTransfer.files; show(); }
    });
  });

  // Confirm destructive actions.
  document.querySelectorAll('form[data-confirm]').forEach(function (f) {
    f.addEventListener('submit', function (ev) {
      if (!window.confirm(f.getAttribute('data-confirm'))) ev.preventDefault();
    });
  });

  // Filter selects and checkboxes submit their form when changed.
  document.querySelectorAll('[data-autosubmit]').forEach(function (s) {
    s.addEventListener('change', function () { s.form.submit(); });
  });

  // Show fields only when another field has a matching value: data-show-when="KEY=a|b".
  document.querySelectorAll('[data-show-when]').forEach(function (el) {
    var rule = el.getAttribute('data-show-when').split('=');
    var form = el.closest('form');
    var ctrl = form && form.querySelector('[name="' + rule[0] + '"]');
    if (!ctrl) return;
    var allowed = rule[1].split('|');
    function current() {
      if (ctrl.type === 'checkbox') return ctrl.checked ? 'true' : 'false';
      return ctrl.value;
    }
    function apply() { el.hidden = allowed.indexOf(current()) === -1; }
    ctrl.addEventListener('change', apply);
    apply();
  });

  // Long-running submits (AI review): disable the button and say what is happening.
  document.querySelectorAll('form[data-busy]').forEach(function (f) {
    f.addEventListener('submit', function () {
      var b = f.querySelector('button[type=submit]');
      if (b) { b.disabled = true; b.textContent = f.getAttribute('data-busy'); }
    });
  });

  // Setup guide: build the deployment command from the fields.
  document.querySelectorAll('[data-cmd-builder]').forEach(function (box) {
    var out = box.parentNode.querySelector('[data-cmd-output]');
    function quote(v) { return /^[A-Za-z0-9@._\/:,-]+$/.test(v) ? v : "'" + v.replace(/'/g, "'\\''") + "'"; }
    function build() {
      var parts = ['./deploy/azure/deploy.sh'];
      box.querySelectorAll('[data-arg]').forEach(function (i) {
        if (i.value.trim()) parts.push(i.getAttribute('data-arg') + ' ' + quote(i.value.trim()));
      });
      out.textContent = parts.join(' ');
    }
    box.addEventListener('input', build);
    build();
  });

  // Filter a long checkbox list as you type: <input data-filter-list="ID">; items carry data-filter-text.
  // Ticked items always stay visible.
  document.querySelectorAll('[data-filter-list]').forEach(function (input) {
    var list = document.getElementById(input.getAttribute('data-filter-list'));
    if (!list) return;
    input.addEventListener('input', function () {
      var q = input.value.trim().toLowerCase();
      list.querySelectorAll('[data-filter-text]').forEach(function (item) {
        var box = item.querySelector('input');
        var match = !q || item.getAttribute('data-filter-text').toLowerCase().indexOf(q) >= 0;
        item.hidden = !(match || (box && box.checked));
      });
    });
  });

  // Calendar: drag a row within its group to reorder; the new order is posted with the group's hidden form.
  document.querySelectorAll('tbody[data-sortable]').forEach(function (body) {
    var kind = body.getAttribute('data-sortable');
    var form = document.querySelector('form[data-sort-form="' + kind + '"]');
    if (!form) return;
    var dragged = null;
    body.querySelectorAll('tr[data-id]').forEach(function (row) {
      row.setAttribute('draggable', 'true');
      row.addEventListener('dragstart', function (e) {
        dragged = row; row.classList.add('cal-dragging');
        e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', row.getAttribute('data-id'));
      });
      row.addEventListener('dragend', function () {
        row.classList.remove('cal-dragging');
        body.querySelectorAll('.cal-drop-target').forEach(function (r) { r.classList.remove('cal-drop-target'); });
      });
      row.addEventListener('dragover', function (e) {
        if (!dragged || dragged === row) return;
        e.preventDefault(); row.classList.add('cal-drop-target');
      });
      row.addEventListener('dragleave', function () { row.classList.remove('cal-drop-target'); });
      row.addEventListener('drop', function (e) {
        if (!dragged || dragged === row) return;
        e.preventDefault();
        var rows = Array.prototype.slice.call(body.querySelectorAll('tr[data-id]'));
        body.insertBefore(dragged, rows.indexOf(dragged) < rows.indexOf(row) ? row.nextSibling : row);
        form.querySelector('input[name="ids"]').value = Array.prototype.map.call(
          body.querySelectorAll('tr[data-id]'), function (r) { return r.getAttribute('data-id'); }).join(',');
        form.submit();
      });
    });
  });
})();
