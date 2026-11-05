// Progressive enhancement only: every page works without JavaScript.
(function () {
  // Form helpers that also run inside the control side panel, which is loaded after the page: enhance(root).
  function enhance(root) {
  // Drag and drop onto the upload area fills the file input.
  root.querySelectorAll('[data-drop]').forEach(function (zone) {
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
  root.querySelectorAll('form[data-confirm]').forEach(function (f) {
    f.addEventListener('submit', function (ev) {
      if (!window.confirm(f.getAttribute('data-confirm'))) ev.preventDefault();
    });
  });

  // Filter selects and checkboxes submit their form when changed.
  // Buttons only needed without JavaScript (an upload that sends itself once a file is chosen).
  root.querySelectorAll('[data-nojs]').forEach(function (b) { b.hidden = true; });
  root.querySelectorAll('[data-autosubmit]').forEach(function (s) {
    s.addEventListener('change', function () { s.form.submit(); });
  });

  // Show fields only when another field has a matching value: data-show-when="KEY=a|b".
  root.querySelectorAll('[data-show-when]').forEach(function (el) {
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
  root.querySelectorAll('form[data-busy]').forEach(function (f) {
    f.addEventListener('submit', function () {
      var b = f.querySelector('button[type=submit]');
      if (b) { b.disabled = true; b.textContent = f.getAttribute('data-busy'); }
    });
  });
  }
  enhance(document);

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

  // Date fields: clicking anywhere in the field opens the browser's date picker, not only the small icon.
  // Delegated, so it also works in the calendar popup that is loaded later. Typing a date still works.
  document.addEventListener('click', function (ev) {
    var input = ev.target;
    if (!input || input.tagName !== 'INPUT' || input.type !== 'date' || input.disabled || input.readOnly) return;
    if (typeof input.showPicker === 'function') {
      try { input.showPicker(); } catch (e) { /* not allowed here (for example inside a cross-origin frame) */ }
    }
  });

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

  // "Select all" box: <input data-check-all="GROUP"> ticks or clears every <input data-check-group="GROUP">.
  document.querySelectorAll('[data-check-all]').forEach(function (all) {
    var group = all.getAttribute('data-check-all');
    all.addEventListener('change', function () {
      document.querySelectorAll('[data-check-group="' + group + '"]').forEach(function (box) { box.checked = all.checked; });
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
  // Slim menu: the sidebar folds to icons. nav.js has already applied the remembered choice before the page was
  // drawn; this only handles the button. A per-browser convenience (localStorage), never needed.
  var navToggle = document.querySelector('[data-nav-toggle]');
  if (navToggle) {
    var NAV_KEY = 'grcpal-nav-slim';
    var navGroups = Array.prototype.slice.call(document.querySelectorAll('.nav-group'));
    var groupOpen = navGroups.map(function (g) { return g.open; });
    function setSlim(slim) {
      document.body.classList.toggle('nav-slim', slim);
      navToggle.setAttribute('aria-expanded', slim ? 'false' : 'true');
      navToggle.setAttribute('aria-label', slim ? 'Expand the menu' : 'Collapse the menu');
      navToggle.title = navToggle.getAttribute('aria-label');
      // Icons only: every item must be reachable, so groups open; their labels become tooltips.
      navGroups.forEach(function (g, i) { g.open = slim ? true : groupOpen[i]; });
      document.querySelectorAll('.nav a, .nav-group > summary').forEach(function (a) {
        var label = a.querySelector('.nav-item span');
        if (slim && label) a.title = label.textContent; else a.removeAttribute('title');
      });
    }
    navToggle.hidden = false;
    setSlim(document.body.classList.contains('nav-slim'));
    navToggle.addEventListener('click', function () {
      var slim = !document.body.classList.contains('nav-slim');
      if (slim) groupOpen = navGroups.map(function (g) { return g.open; });
      setSlim(slim);
      try { window.localStorage.setItem(NAV_KEY, slim ? '1' : '0'); } catch (e) { /* storage blocked: not remembered */ }
    });
  }

  // Unsaved changes. A form inside [data-unsaved-watch] (the control page and the control side panel) whose fields
  // differ from what the page was loaded with is "changed". Closing the panel, switching control or following a
  // link then asks first in an in-page dialog that names the section and the fields; the browser's own question
  // (beforeunload) covers reloading, typing an address and closing the tab. Submitting a form is not "unsaved".
  var unsavedDialog = document.querySelector('[data-unsaved-dialog]');
  var submitting = false, leaving = false, onDiscard = null, onKeep = null;
  function isChanged(el) {
    var t = (el.type || '').toLowerCase();
    if (!el.name || el.disabled || t === 'hidden' || t === 'submit' || t === 'button' || t === 'reset') return false;
    if (t === 'checkbox' || t === 'radio') return el.checked !== el.defaultChecked;
    if (t === 'file') return !!(el.files && el.files.length);
    if (el.tagName === 'SELECT') {
      var opts = Array.prototype.slice.call(el.options);
      if (el.multiple) return opts.some(function (o) { return o.selected !== o.defaultSelected; });
      var dflt = opts.findIndex(function (o) { return o.defaultSelected; });
      return el.selectedIndex !== (dflt < 0 ? 0 : dflt);
    }
    return typeof el.value === 'string' && el.value !== el.defaultValue;
  }
  function textOf(node) { return (node && node.textContent || '').replace(/\s+/g, ' ').trim(); }
  function fieldLabel(el) {
    if (el.id) {
      var l = document.querySelector('label[for="' + (window.CSS && CSS.escape ? CSS.escape(el.id) : el.id) + '"]');
      if (l) return textOf(l);
    }
    var wrap = el.closest('label');
    if (wrap) {
      var own = Array.prototype.filter.call(wrap.childNodes, function (n) {
        return n.nodeType === 3 || (n.nodeType === 1 && !n.matches('input, select, textarea'));
      }).map(textOf).join(' ').trim();
      if (own) return own;
    }
    return el.getAttribute('aria-label') || el.name;
  }
  function sectionName(el) {
    var box = el.closest('section, details.card, .card');
    var head = box && box.querySelector('h2, summary');
    return textOf(head) || 'This control';
  }
  function changes(scope) {
    var out = [], seen = {};
    scope.querySelectorAll('[data-unsaved-watch] form').forEach(function (f) {
      if ((f.getAttribute('method') || '').toLowerCase() !== 'post') return;
      Array.prototype.forEach.call(f.elements, function (el) {
        if (!isChanged(el)) return;
        var item = sectionName(el) + ': ' + fieldLabel(el);
        if (!seen[item]) { seen[item] = true; out.push(item); }
      });
    });
    return out;
  }
  function confirmDiscard(list, discard, keep) {
    if (!list.length || !unsavedDialog || typeof unsavedDialog.showModal !== 'function') {
      if (!list.length || window.confirm('Changes are not saved:\n' + list.join('\n') + '\n\nClose without saving?')) discard();
      else if (keep) keep();
      return;
    }
    var ul = unsavedDialog.querySelector('[data-unsaved-list]');
    ul.innerHTML = '';
    list.forEach(function (item) { var li = document.createElement('li'); li.textContent = item; ul.appendChild(li); });
    onDiscard = discard; onKeep = keep || null;
    unsavedDialog.showModal();
    unsavedDialog.querySelector('[data-unsaved-keep]').focus();
  }
  if (unsavedDialog) {
    // Decide at once on the click (the dialog's own "close" event comes later and could act on a newer question).
    var finish = function (discard) {
      var go = discard ? onDiscard : onKeep;
      onDiscard = onKeep = null;
      if (unsavedDialog.open) unsavedDialog.close();
      if (go) go();
    };
    unsavedDialog.querySelector('[data-unsaved-keep]').addEventListener('click', function () { finish(false); });
    unsavedDialog.querySelector('[data-unsaved-discard]').addEventListener('click', function () { finish(true); });
    unsavedDialog.addEventListener('cancel', function (ev) { ev.preventDefault(); finish(false); });  // Escape = keep
  }
  document.addEventListener('submit', function (ev) { if (!ev.defaultPrevented) submitting = true; });
  window.addEventListener('pageshow', function () { submitting = false; leaving = false; });  // back from the cache
  window.addEventListener('beforeunload', function (ev) {
    if (submitting || leaving || !changes(document).length) return;
    ev.preventDefault();
    ev.returnValue = '';
  });

  // Control side panel: a control in a list (a whole row, or its link) opens beside the list, over a dimmed
  // backdrop, with every section of the full page (_control_body.html). Escape, the backdrop, Close and the
  // browser's Back close it; the list keeps its filters and scroll. Ctrl/Cmd-click, middle-click and no JavaScript
  // open the full page. The address bar keeps #control=ID so the panel can be shared or reloaded.
  var drawer = document.querySelector('[data-drawer]');
  var drawerBody = drawer && drawer.querySelector('[data-drawer-body]');
  var backdrop = document.querySelector('[data-drawer-backdrop]');
  var ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
  var SCROLL_KEY = 'grcpal-list-scroll';
  var opener = null, currentId = null, pushed = false, closingByBack = false;
  function listUrl() {  // this list page without a one-time message
    var q = new URLSearchParams(window.location.search);
    q.delete('msg'); q.delete('err');
    var s = q.toString();
    return window.location.pathname + (s ? '?' + s : '');
  }
  function hideDrawer() {
    if (!drawer || drawer.hidden) return;
    drawer.hidden = true;
    if (backdrop) backdrop.hidden = true;
    document.body.classList.remove('drawer-open');
    drawerBody.innerHTML = '';
    currentId = null;
    document.querySelectorAll('[data-panel-row].selected').forEach(function (r) { r.classList.remove('selected'); });
    if (opener && document.body.contains(opener)) opener.focus();
  }
  function requestClose() {  // Close button, backdrop, Escape
    confirmDiscard(changes(drawerBody), function () {
      if (pushed) { pushed = false; closingByBack = true; window.history.back(); }  // popstate hides it
      else { window.history.replaceState(null, '', listUrl()); hideDrawer(); }
    });
  }
  function wirePanel(id) {
    enhance(drawerBody);
    // A save made here comes back to this list with the same panel open (see panel_return in app.py).
    drawerBody.querySelectorAll('form').forEach(function (f) {
      if ((f.getAttribute('method') || '').toLowerCase() !== 'post') return;
      var u = new URL(f.getAttribute('action') || window.location.href, window.location.href);
      u.searchParams.set('panel', listUrl());
      f.setAttribute('action', u.pathname + u.search);
      f.addEventListener('submit', function (ev) {
        if (ev.defaultPrevented) return;
        try { window.sessionStorage.setItem(SCROLL_KEY, JSON.stringify({ u: listUrl(), y: window.scrollY })); } catch (e) { /* not kept */ }
      });
    });
    // Section links scroll inside the panel instead of changing the address.
    drawerBody.querySelectorAll('.section-nav a[href^="#"]').forEach(function (a) {
      a.addEventListener('click', function (ev) {
        ev.preventDefault();
        var target = drawerBody.querySelector('[id="' + a.getAttribute('href').slice(1) + '"]');
        if (target) { target.scrollIntoView({ block: 'start' }); if (target.tagName === 'DETAILS') target.open = true; }
      });
    });
    document.querySelectorAll('[data-panel-row]').forEach(function (r) {
      r.classList.toggle('selected', r.getAttribute('data-panel-row') === id);
    });
  }
  function loadPanel(id, link, how) {
    fetch('/controls/' + encodeURIComponent(id) + '/panel', { credentials: 'same-origin', headers: { 'X-Requested-With': 'fetch' } })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.text(); })
      .then(function (html) {
        var wasOpen = !drawer.hidden;
        if (link) opener = link;
        drawerBody.innerHTML = html;  // our own server-rendered, escaped template
        currentId = id;
        wirePanel(id);
        drawer.hidden = false;
        if (backdrop) backdrop.hidden = false;
        document.body.classList.add('drawer-open');
        drawer.scrollTop = 0;
        var url = listUrl() + '#control=' + id;
        if (how === 'push' && !wasOpen) { window.history.pushState(null, '', url); pushed = true; }
        else if (how !== 'none') window.history.replaceState(null, '', url);
        var title = drawerBody.querySelector('#drawer-title');
        if (title) title.focus();
      })
      .catch(function () { if (link) window.location.href = link.getAttribute('href'); });
  }
  function openPanel(id, link, how) {
    if (!drawer || !ID_RE.test(id)) return;
    if (!drawer.hidden && id === currentId) return;
    if (drawer.hidden) { loadPanel(id, link, how); return; }
    var was = currentId;
    confirmDiscard(changes(drawerBody), function () { loadPanel(id, link, how); }, function () {
      if (how === 'none') window.history.replaceState(null, '', listUrl() + '#control=' + was);  // undo a hash change
    });
  }
  function syncFromUrl() {
    var m = /^#control=([A-Za-z0-9._-]+)$/.exec(window.location.hash);
    if (m) { if (document.querySelector('a[data-panel]')) openPanel(m[1], document.querySelector('a[data-panel="' + m[1] + '"]'), 'none'); return; }
    if (!drawer || drawer.hidden) return;
    if (closingByBack) { closingByBack = false; hideDrawer(); return; }
    var list = changes(drawerBody);  // the browser's Back while the panel is open
    if (!list.length) { pushed = false; hideDrawer(); return; }
    window.history.pushState(null, '', listUrl() + '#control=' + currentId);
    pushed = true;
    confirmDiscard(list, function () { pushed = false; closingByBack = true; window.history.back(); });
  }

  document.addEventListener('click', function (ev) {
    if (ev.defaultPrevented) return;
    if (drawer && ev.target.closest('[data-drawer-close]')) { requestClose(); return; }
    if (backdrop && ev.target === backdrop) { requestClose(); return; }
    var plain = !(ev.ctrlKey || ev.metaKey || ev.shiftKey || ev.altKey) && ev.button === 0;
    var a = ev.target.closest('a[href]');
    if (a && a.hasAttribute('data-panel') && drawer) {
      if (!plain) return;
      ev.preventDefault();
      openPanel(a.getAttribute('data-panel'), a, 'push');
      return;
    }
    // The whole row of a list opens the panel; real links stay underneath for keyboard and new-tab use.
    var row = !a && drawer && ev.target.closest('tr[data-panel-row]');
    if (row && !ev.target.closest('button, input, select, textarea, label, summary')) {
      var link = row.querySelector('a[data-panel]');
      if (!link || String(window.getSelection ? window.getSelection() : '').length) return;  // selecting text
      if (ev.ctrlKey || ev.metaKey) { window.open(link.href, '_blank', 'noopener'); return; }
      if (plain) openPanel(row.getAttribute('data-panel-row'), link, 'push');
      return;
    }
    // Any other link that leaves this page while a form has changes: ask in the page first.
    if (!a || !plain || a.target === '_blank' || a.hasAttribute('download')) return;
    var href = a.getAttribute('href');
    if (href.charAt(0) === '#') return;
    var url;
    try { url = new URL(a.href); } catch (e) { return; }
    if (url.origin === window.location.origin && url.pathname === window.location.pathname &&
        url.search === window.location.search && url.hash) return;
    var list = changes(document);
    if (!list.length) return;
    ev.preventDefault();
    confirmDiscard(list, function () { leaving = true; window.location.href = a.href; });
  });
  document.addEventListener('keydown', function (ev) {
    if (!drawer || drawer.hidden || (unsavedDialog && unsavedDialog.open)) return;
    if (ev.key === 'Escape') { ev.preventDefault(); requestClose(); return; }
    if (ev.key !== 'Tab') return;
    // Keep keyboard focus inside the panel while it is open (it is shown as a dialog over the list).
    var items = Array.prototype.filter.call(drawer.querySelectorAll(
      'a[href], button:not([disabled]), input:not([type=hidden]):not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex="0"]'),
      function (el) { return el.getClientRects().length > 0; });
    if (!items.length) return;
    var first = items[0], last = items[items.length - 1], active = document.activeElement;
    if (!drawer.contains(active) || (ev.shiftKey && active === first) || (!ev.shiftKey && active === last)) {
      ev.preventDefault();
      (ev.shiftKey ? last : first).focus();
    }
  });
  if (drawer) {
    window.addEventListener('popstate', syncFromUrl);
    syncFromUrl();
    // After saving from the panel the list reloads; put it back where it was scrolled.
    try {
      var keep = JSON.parse(window.sessionStorage.getItem(SCROLL_KEY) || 'null');
      window.sessionStorage.removeItem(SCROLL_KEY);
      if (keep && keep.u === listUrl() && keep.y > 0) window.scrollTo(0, keep.y);
    } catch (e) { /* storage blocked: the list opens at the top */ }
  }

  // Access reviews: one click keeps every account that has no flag; flagged accounts are always decided one by one.
  document.querySelectorAll('[data-ar-keep-unflagged]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var form = btn.closest('form');
      if (!form) return;
      form.querySelectorAll('select[data-flagged="0"]').forEach(function (sel) { if (!sel.value) sel.value = 'keep'; });
    });
  });
})();
