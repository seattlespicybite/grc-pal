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

  // Control matrix report: print button (the browser's Print dialog also saves as PDF).
  document.querySelectorAll('[data-print]').forEach(function (b) {
    b.addEventListener('click', function () { window.print(); });
  });

  // Back button: same as the browser's Back, so the previous page opens where you left it (the browser
  // restores the scroll position). Shown only when the previous page was a page of this portal.
  var back = document.querySelector('[data-back]');
  if (back) {
    var fromHere = false;
    try { fromHere = !!document.referrer && new URL(document.referrer).origin === window.location.origin; } catch (e) {}
    if (fromHere && window.history.length > 1) {
      back.hidden = false;
      back.addEventListener('click', function () { window.history.back(); });
    }
  }

fix/backup-popup-vendor-reason-register
  // Job page: when a job (for example a backup) has just finished, pop up its result once per browser tab.
  // The same result is always shown as a banner on the page, so nothing depends on this popup.
  var jobDialog = document.querySelector('[data-job-dialog]');
  if (jobDialog && typeof jobDialog.showModal === 'function') {
    var seenKey = 'grcpal-job-seen-' + jobDialog.getAttribute('data-job-id');
    var seen = false;
    try { seen = window.sessionStorage.getItem(seenKey) === '1'; } catch (e) { seen = false; }
    jobDialog.addEventListener('click', function (ev) {
      if (ev.target === jobDialog || ev.target.closest('[data-pop-close]')) jobDialog.close();
    });
    if (!seen) {
      try { window.sessionStorage.setItem(seenKey, '1'); } catch (e) { /* storage blocked: popup may repeat */ }
      jobDialog.showModal();
      var ok = jobDialog.querySelector('[data-pop-close]');
      if (ok) ok.focus();
    }
  }
=======
  // Date fields: clicking anywhere in the field opens the browser's date picker, not only the small icon.
  // Delegated, so it also works in the calendar popup that is loaded later. Typing a date still works.
  document.addEventListener('click', function (ev) {
    var input = ev.target;
    if (!input || input.tagName !== 'INPUT' || input.type !== 'date' || input.disabled || input.readOnly) return;
    if (typeof input.showPicker === 'function') {
      try { input.showPicker(); } catch (e) { /* not allowed here (for example inside a cross-origin frame) */ }
    }
  });
main

  // Calendar: open a month (or the + of an unscheduled month) in a popup instead of a new page. Saving posts
  // the form as usual and the calendar reloads at the same row. Without JavaScript the links open the page.
  var calDialog = document.querySelector('[data-cal-dialog]');
  if (calDialog && typeof calDialog.showModal === 'function') {
    var calBody = calDialog.querySelector('[data-cal-dialog-body]');
    calDialog.addEventListener('click', function (ev) {
      if (ev.target === calDialog || ev.target.closest('[data-pop-close]')) calDialog.close();
    });
    document.querySelectorAll('[data-cal-popup] a.cal-cell, [data-cal-popup] a.cal-add').forEach(function (a) {
      a.addEventListener('click', function (ev) {
        if (ev.ctrlKey || ev.metaKey || ev.shiftKey || ev.button !== 0) return;  // new tab still works
        ev.preventDefault();
        var url = a.getAttribute('href') + '?popup=1';
        fetch(url, { credentials: 'same-origin', headers: { 'X-Requested-With': 'fetch' } })
          .then(function (r) { if (!r.ok) throw new Error(r.status); return r.text(); })
          .then(function (html) {
            calBody.innerHTML = html;  // our own server-rendered, escaped template
            calDialog.showModal();
            var first = calBody.querySelector('input:checked, input, button');
            if (first) first.focus();
          })
          .catch(function () { window.location.href = a.getAttribute('href'); });
      });
    });
  }

  // Password links: the token sits after "#" in the emailed link, so it never reaches the server's logs. Post it
  // once (it is swapped for a short-lived password form) and drop it from the address bar and history.
  var linkForm = document.querySelector('form[data-link-open]');
  if (linkForm && window.location.hash.length > 1) {
    linkForm.querySelector('input[name=token]').value = decodeURIComponent(window.location.hash.slice(1));
    window.history.replaceState(null, '', window.location.pathname);
    linkForm.submit();
  }

  // Confirm destructive actions.
  document.querySelectorAll('form[data-confirm]').forEach(function (f) {
    f.addEventListener('submit', function (ev) {
      if (!window.confirm(f.getAttribute('data-confirm'))) ev.preventDefault();
    });
  });

  // Filter selects and checkboxes submit their form when changed.
  // Buttons only needed without JavaScript (an upload that sends itself once a file is chosen).
  document.querySelectorAll('[data-nojs]').forEach(function (b) { b.hidden = true; });
  document.querySelectorAll('[data-autosubmit]').forEach(function (s) {
    s.addEventListener('change', function () { s.form.submit(); });
  });

  // "Select all" box: <input data-check-all="GROUP"> ticks or clears every <input data-check-group="GROUP">.
  document.querySelectorAll('[data-check-all]').forEach(function (all) {
    var group = all.getAttribute('data-check-all');
    all.addEventListener('change', function () {
      document.querySelectorAll('[data-check-group="' + group + '"]').forEach(function (box) { box.checked = all.checked; });
    });
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

  // Updates page: live progress while the host updater works (polls a small JSON endpoint, admins only).
  document.querySelectorAll('[data-update-progress]').forEach(function (card) {
    if (!card.hasAttribute('data-active')) return;
    var url = card.getAttribute('data-update-progress');
    var steps = Array.prototype.slice.call(card.querySelectorAll('[data-step]'));
    var keys = steps.map(function (li) { return li.getAttribute('data-step'); });
    function text(sel, value) { var el = card.querySelector(sel); if (el) el.textContent = value; }
    function paint(d) {
      var pct = d.percent === null ? 0 : d.percent;
      var bar = card.querySelector('[data-progress-bar]');
      if (bar) bar.value = pct;
      text('[data-progress-percent]', pct + '%');
      text('[data-progress-message]', d.pending ? 'Waiting for the updater to start (within a minute).' : d.message);
      text('[data-progress-state]', (d.pending ? 'waiting' : d.state || 'idle').replace(/_/g, ' '));
      var at = keys.indexOf(d.state);
      steps.forEach(function (li, i) {
        li.classList.toggle('done', at >= 0 && i < at);
        li.classList.toggle('current', i === at);
      });
    }
    function tick() {
      fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) {
          if (!d) { setTimeout(tick, 5000); return; }
          paint(d);
          if (d.active) setTimeout(tick, 2000); else window.location.reload();
        })
        .catch(function () { setTimeout(tick, 5000); });  // the portal restarts during the switch
    }
    setTimeout(tick, 2000);
  });
  // Access reviews: one click keeps every account that has no flag; flagged accounts are always decided one by one.
  document.querySelectorAll('[data-ar-keep-unflagged]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var form = btn.closest('form');
      if (!form) return;
      form.querySelectorAll('select[data-flagged="0"]').forEach(function (sel) { if (!sel.value) sel.value = 'keep'; });
    });
  });
})();
