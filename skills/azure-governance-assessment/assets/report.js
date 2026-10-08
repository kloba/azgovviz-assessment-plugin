/* Azure Governance Assessment report - progressive enhancement (the report is complete without JS). */
(function () {
  "use strict";
  var doc = document.documentElement;

  // ---------- theme ----------
  var THEME_KEY = "azgov-report-theme";
  try { var saved = localStorage.getItem(THEME_KEY); if (saved) doc.setAttribute("data-theme", saved); } catch (e) { }
  var themeBtn = document.getElementById("themeToggle");
  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var dark = doc.getAttribute("data-theme") === "dark" ||
        (!doc.getAttribute("data-theme") && window.matchMedia("(prefers-color-scheme: dark)").matches);
      var next = dark ? "light" : "dark";
      doc.setAttribute("data-theme", next);
      try { localStorage.setItem(THEME_KEY, next); } catch (e) { }
    });
  }
  var printBtn = document.getElementById("printBtn");
  if (printBtn) printBtn.addEventListener("click", function () { window.print(); });

  // ---------- table of contents highlight ----------
  var links = Array.prototype.slice.call(document.querySelectorAll("nav.toc a[href^='#']"));
  if ("IntersectionObserver" in window && links.length) {
    var map = {};
    links.forEach(function (a) { map[a.getAttribute("href").slice(1)] = a; });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting && map[en.target.id]) {
          links.forEach(function (a) { a.classList.remove("active"); });
          map[en.target.id].classList.add("active");
        }
      });
    }, { rootMargin: "-80px 0px -70% 0px" });
    Object.keys(map).forEach(function (id) { var el = document.getElementById(id); if (el) io.observe(el); });
  }

  // ---------- tooltip (values are always also visible or in a table; tooltips only enhance) ----------
  var tip = document.getElementById("tip");
  function showTip(el, x, y) {
    var t = el.getAttribute("data-tip");
    if (!t || !tip) return;
    tip.textContent = "";
    var parts = t.split("|");
    var strong = document.createElement("b");
    strong.textContent = parts[0];
    tip.appendChild(strong);
    if (parts[1]) { tip.appendChild(document.createElement("br")); tip.appendChild(document.createTextNode(parts.slice(1).join(" · "))); }
    var w = tip.offsetWidth, h = tip.offsetHeight;
    tip.style.left = Math.min(window.innerWidth - w - 8, x + 12) + "px";
    tip.style.top = Math.max(8, y - h - 12) + "px";
    tip.classList.add("on");
  }
  document.addEventListener("pointermove", function (ev) {
    var el = ev.target.closest ? ev.target.closest("[data-tip]") : null;
    if (el) showTip(el, ev.clientX, ev.clientY); else if (tip) tip.classList.remove("on");
  });
  document.addEventListener("focusin", function (ev) {
    var el = ev.target.closest ? ev.target.closest("[data-tip]") : null;
    if (el) { var r = el.getBoundingClientRect(); showTip(el, r.left + r.width / 2, r.top); }
  });
  document.addEventListener("focusout", function () { if (tip) tip.classList.remove("on"); });

  // ---------- generic filter engine ----------
  var filters = [];
  function setupFilter(root) {
    var targetSel = root.getAttribute("data-target");
    var items = Array.prototype.slice.call(document.querySelectorAll(targetSel));
    var search = root.querySelector("input[type='search']");
    var selects = Array.prototype.slice.call(root.querySelectorAll("select[data-key]"));
    var segs = Array.prototype.slice.call(root.querySelectorAll(".seg[data-key]"));
    var counter = root.querySelector(".result-count");
    var pageSize = parseInt(root.getAttribute("data-page") || "0", 10);
    var moreBtn = root.getAttribute("data-more") ? document.getElementById(root.getAttribute("data-more")) : null;
    var limit = pageSize;

    function activeSeg(seg) {
      var on = Array.prototype.slice.call(seg.querySelectorAll("button[aria-pressed='true']"));
      return on.map(function (b) { return b.getAttribute("data-value"); });
    }
    function apply() {
      var q = search ? search.value.trim().toLowerCase() : "";
      var shown = 0, matched = 0;
      items.forEach(function (el) {
        var ok = true;
        if (q && (el.getAttribute("data-text") || el.textContent).toLowerCase().indexOf(q) === -1) ok = false;
        selects.forEach(function (s) { if (ok && s.value && el.getAttribute("data-" + s.getAttribute("data-key")) !== s.value) ok = false; });
        segs.forEach(function (seg) {
          var vals = activeSeg(seg);
          if (ok && vals.length && vals.indexOf(el.getAttribute("data-" + seg.getAttribute("data-key"))) === -1) ok = false;
        });
        if (ok) matched++;
        var visible = ok && (!limit || shown < limit);
        if (visible) shown++;
        el.hidden = !visible;
        var detail = el.nextElementSibling;
        if (detail && detail.classList.contains("detail-row") && !visible) detail.hidden = true;
      });
      var groupSel = root.getAttribute("data-groups");
      if (groupSel) {
        document.querySelectorAll(groupSel).forEach(function (g) {
          g.hidden = !g.querySelector(targetSel + ":not([hidden])");
        });
      }
      if (counter) counter.textContent = matched === items.length ? matched + " shown" : matched + " of " + items.length;
      if (moreBtn) {
        moreBtn.hidden = !(limit && matched > shown);
        moreBtn.textContent = "Show " + Math.min(pageSize, matched - shown) + " more (" + (matched - shown) + " hidden)";
      }
    }
    if (search) search.addEventListener("input", function () { limit = pageSize; apply(); });
    selects.forEach(function (s) { s.addEventListener("change", function () { limit = pageSize; apply(); }); });
    segs.forEach(function (seg) {
      seg.addEventListener("click", function (ev) {
        var b = ev.target.closest("button"); if (!b) return;
        b.setAttribute("aria-pressed", b.getAttribute("aria-pressed") === "true" ? "false" : "true");
        limit = pageSize; apply();
      });
    });
    if (moreBtn) moreBtn.addEventListener("click", function () { limit += pageSize; apply(); });
    apply();

    // Print / PDF: no paging; filters marked data-print-all are cleared so nothing is dropped silently.
    var saved = null;
    filters.push({
      print: function () {
        saved = { q: search ? search.value : "", sel: selects.map(function (s) { return s.value; }),
          seg: segs.map(function (seg) { return activeSeg(seg); }), limit: limit };
        if (root.hasAttribute("data-print-all")) {
          if (search) search.value = "";
          selects.forEach(function (s) { s.value = ""; });
          segs.forEach(function (seg) { seg.querySelectorAll("button").forEach(function (b) { b.setAttribute("aria-pressed", "false"); }); });
        }
        limit = 0; apply();
        var note = root.getAttribute("data-print-note") ? document.getElementById(root.getAttribute("data-print-note")) : null;
        if (note) {
          var shown = items.filter(function (el) { return !el.hidden; }).length;
          note.textContent = shown === items.length ? "" :
            "This printout lists " + shown + " of " + items.length + " items (the filter that was active in the report). " +
            "The full list is in the HTML report and checklists/results.json.";
        }
      },
      restore: function () {
        if (!saved) return;
        if (search) search.value = saved.q;
        selects.forEach(function (s, i) { s.value = saved.sel[i]; });
        segs.forEach(function (seg, i) {
          seg.querySelectorAll("button").forEach(function (b) {
            b.setAttribute("aria-pressed", saved.seg[i].indexOf(b.getAttribute("data-value")) === -1 ? "false" : "true");
          });
        });
        limit = saved.limit; saved = null; apply();
      }
    });
  }
  document.querySelectorAll(".filters[data-target]").forEach(setupFilter);

  // ---------- print ----------
  function enterPrint() {
    filters.forEach(function (f) { f.print(); });
    document.querySelectorAll("details.finding").forEach(function (d) { d.dataset.wasOpen = d.open ? "1" : ""; d.open = true; });
  }
  window.addEventListener("beforeprint", enterPrint);
  window.addEventListener("afterprint", function () {
    filters.forEach(function (f) { f.restore(); });
    document.querySelectorAll("details.finding").forEach(function (d) { d.open = d.dataset.wasOpen === "1"; });
  });
  if (location.hash === "#print") {  // headless PDF export (azgov-assess report --pdf)
    enterPrint();
    document.querySelectorAll("details").forEach(function (d) { d.open = true; });
  }

  // ---------- checklist item rows expand ----------
  // the recommendation text is a <button> (keyboard + screen readers); a click anywhere on the row also toggles
  document.querySelectorAll("tr.item-row").forEach(function (row) {
    var btn = row.querySelector(".row-toggle");
    row.addEventListener("click", function (ev) {
      if (ev.target.closest("a")) return;
      var d = row.nextElementSibling;
      if (!d || !d.classList.contains("detail-row")) return;
      d.hidden = !d.hidden;
      if (btn) btn.setAttribute("aria-expanded", d.hidden ? "false" : "true");
    });
  });

  // ---------- jump-to-finding / design-area links reveal what the filters hid ----------
  document.addEventListener("click", function (ev) {
    var area = ev.target.closest ? ev.target.closest("a[href^='#dom-']") : null;
    if (area) {
      var g = document.getElementById(area.getAttribute("href").slice(1));
      if (g) { g.hidden = false; g.querySelectorAll("details.finding").forEach(function (d) { d.hidden = false; }); }
      return;
    }
    var a = ev.target.closest ? ev.target.closest("a[href^='#F-']") : null;
    if (!a) return;
    var el = document.getElementById(a.getAttribute("href").slice(1));
    if (el && el.tagName === "DETAILS") {
      el.hidden = false; el.open = true;
      var group = el.closest(".domain-group");  // the filter hides whole design-area groups too
      if (group) group.hidden = false;
    }
  });

  // ---------- expand / collapse all findings ----------
  var exp = document.getElementById("expandAll");
  if (exp) exp.addEventListener("click", function () {
    var open = exp.getAttribute("aria-pressed") !== "true";
    exp.setAttribute("aria-pressed", open ? "true" : "false");
    exp.textContent = open ? "Collapse all" : "Expand all";
    document.querySelectorAll("details.finding:not([hidden])").forEach(function (d) { d.open = open; });
  });
})();
