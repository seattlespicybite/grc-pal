// Menu state, restored before the page is drawn: base.html loads this file right after the menu (not at the end
// of the page), so the menu never jumps. Remembered per browser in localStorage: which groups are open, the slim
// menu and how far the menu is scrolled. A convenience only: with storage blocked the server's menu shows as is.
// The group of the current page (opened by the server) always stays open.
(function () {
  var KEY_SLIM = 'grcpal-nav-slim', KEY_GROUPS = 'grcpal-nav-groups', KEY_SCROLL = 'grcpal-nav-scroll';
  function get(k) { try { return window.localStorage.getItem(k); } catch (e) { return null; } }
  function set(k, v) { try { window.localStorage.setItem(k, v); } catch (e) { /* storage blocked: not remembered */ } }

  var saved = {};
  try { saved = JSON.parse(get(KEY_GROUPS) || '{}') || {}; } catch (e) { saved = {}; }
  if (typeof saved !== 'object' || Array.isArray(saved)) saved = {};
  document.querySelectorAll('.nav-group[data-nav-group]').forEach(function (g) {
    var id = g.getAttribute('data-nav-group');
    var current = g.hasAttribute('open');  // the server opens the group of the page you are on
    if (!current && saved[id] === true) g.open = true;
    var summary = g.querySelector('summary');
    if (summary) summary.addEventListener('click', function () {
      if (document.body.classList.contains('nav-slim')) return;  // slim menu shows every group; not a choice
      saved[id] = !g.open;  // the click toggles it right after this handler
      set(KEY_GROUPS, JSON.stringify(saved));
    });
  });

  var slimSaved = get(KEY_SLIM);
  var slim = slimSaved === null ? window.innerWidth < 1180 && window.innerWidth > 960 : slimSaved === '1';
  if (slim) document.body.classList.add('nav-slim');
  var toggle = document.querySelector('[data-nav-toggle]');
  if (toggle) toggle.hidden = false;

  var side = document.querySelector('.side');
  if (side) {
    var y = parseInt(get(KEY_SCROLL) || '0', 10);
    if (y > 0) side.scrollTop = y;
    var timer = null;
    side.addEventListener('scroll', function () {
      clearTimeout(timer);
      timer = setTimeout(function () { set(KEY_SCROLL, String(Math.round(side.scrollTop))); }, 150);
    }, { passive: true });
    window.addEventListener('pagehide', function () { set(KEY_SCROLL, String(Math.round(side.scrollTop))); });
  }
})();
