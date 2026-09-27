// grd-sgr web UI. No framework, no external resource. Everything that comes
// from the EMS or the server is inserted as text (textContent), never as HTML.
// The interface strings live in i18n.js; an element keeps its key and params
// in data-i18n* attributes, so that a change of language re-translates it.
"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const VERDICT_CLASS = { PASS: "pass", FAIL: "fail", ERROR: "fail", INCONCLUSIVE: "warn",
  HARDWARE_REQUIRED: "warn", "N/A": "muted", SKIPPED: "muted" };
const LANG_KEY = "grd-sgr.lang";

const state = { info: null, target: null, jobs: {}, polls: {}, consoleTimer: null, lastSeq: 0, lang: "en" };

// -- languages ---------------------------------------------------------------------------------

const I18N = window.GRD_I18N || { languages: { en: "English" }, default: "en", strings: { en: {} } };

function known(key) {
  return Object.prototype.hasOwnProperty.call(I18N.strings.en, key);
}

// The text of `key` in the current language, English if missing there. A
// param is either plain text or {$t: key, params} to translate in turn.
function t(key, params) {
  const table = I18N.strings[state.lang] || {};
  const text = table[key] !== undefined ? table[key] : I18N.strings.en[key];
  if (text === undefined) return key;
  return text.replace(/\{(\w+)\}/g, (whole, name) => {
    const value = params ? params[name] : undefined;
    if (value === undefined || value === null) return whole;
    if (typeof value === "object" && value.$t) return known(value.$t) ? t(value.$t, value.params) : (value.fallback || value.$t);
    return String(value);
  });
}

// Text with `backquoted` parts shown as code, built without HTML.
function fill(node, text) {
  const parts = String(text).split("`");
  node.replaceChildren(...parts.map((part, i) => (i % 2 ? el("code", { text: part }) : document.createTextNode(part))));
}

// Show a translated message in `node`, and keep what it needs to follow a change of language.
function msg(node, key, params) {
  node.dataset.i18n = key;
  if (params) node.dataset.i18nParams = JSON.stringify(params);
  else delete node.dataset.i18nParams;
  fill(node, t(key, params));
}

// Show text that is not translated (it comes from the EMS or the server).
function plain(node, text) {
  delete node.dataset.i18n;
  delete node.dataset.i18nParams;
  node.textContent = text;
}

function attrMessages(node) {
  const spec = node.dataset.i18nAttr || "";
  if (spec.startsWith("{")) return JSON.parse(spec);
  const out = {};
  for (const pair of spec.split(";")) {
    const [attr, key] = pair.split(":").map((s) => s.trim());
    if (attr && key) out[attr] = [key, null];
  }
  return out;
}

function applyI18n(root) {
  for (const node of root.querySelectorAll("[data-i18n]")) {
    const params = node.dataset.i18nParams ? JSON.parse(node.dataset.i18nParams) : null;
    fill(node, t(node.dataset.i18n, params));
  }
  for (const node of root.querySelectorAll("[data-i18n-attr]")) {
    for (const [attr, [key, params]] of Object.entries(attrMessages(node))) node.setAttribute(attr, t(key, params));
  }
}

function pickLanguage() {
  const supported = Object.keys(I18N.strings);
  const fromQuery = new URLSearchParams(window.location.search).get("lang");
  if (fromQuery && supported.includes(fromQuery.toLowerCase())) return fromQuery.toLowerCase();
  let stored = null;
  try { stored = window.localStorage.getItem(LANG_KEY); } catch (_) { stored = null; }
  if (stored && supported.includes(stored)) return stored;
  for (const tag of navigator.languages || [navigator.language || ""]) {
    const base = String(tag).toLowerCase().split("-")[0];
    if (supported.includes(base)) return base;
  }
  return I18N.default || "en";
}

function setLanguage(lang, remember) {
  state.lang = I18N.strings[lang] ? lang : "en";
  document.documentElement.lang = state.lang;
  for (const button of $$("#langs button")) button.setAttribute("aria-pressed", String(button.dataset.lang === state.lang));
  if (remember) {
    try { window.localStorage.setItem(LANG_KEY, state.lang); } catch (_) { /* a convenience only */ }
    const url = new URL(window.location.href);
    if (url.searchParams.has("lang")) {
      url.searchParams.set("lang", state.lang);
      window.history.replaceState(null, "", url);
    }
  }
  applyI18n(document);
}

// -- elements ------------------------------------------------------------------------------------

// `i18n` (a key) and `params` give the text; `i18nAttr` maps attributes to [key, params].
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  const { i18n, params, i18nAttr, ...rest } = attrs || {};
  for (const [key, value] of Object.entries(rest)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  if (i18nAttr) {
    node.dataset.i18nAttr = JSON.stringify(i18nAttr);
    for (const [attr, [key, attrParams]] of Object.entries(i18nAttr)) node.setAttribute(attr, t(key, attrParams));
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  if (i18n) msg(node, i18n, params);
  return node;
}

function pill(verdict) {
  return el("span", { class: `pill v-${VERDICT_CLASS[verdict] || "muted"}`, text: verdict });
}

function testTitle(id) {
  const test = state.info && state.info.tests.find((x) => x.id === id);
  return { $t: `test.${id}`, fallback: test ? test.title : "" };
}

// -- errors ----------------------------------------------------------------------------------------

class ApiError extends Error {
  constructor(message, status, code, params) {
    super(message);
    this.status = status;
    this.code = code;
    this.params = params || {};
  }
}

// The translated message of a refusal: from its code, or null for the server's own text.
function errorMessage(error) {
  if (error instanceof ApiError && error.code && known(`err.${error.code}`)) {
    const params = { ...error.params };
    if (params.subject) params.subject = { $t: `subject.${params.subject}`, fallback: params.subject };
    return [`err.${error.code}`, params];
  }
  if (error instanceof ApiError && !error.message) return ["err.http", { status: error.status }];
  return null;
}

function showError(node, error) {
  const found = errorMessage(error);
  if (found) msg(node, found[0], found[1]);
  else plain(node, error.message);
}

function flash(error) {
  const box = $("#flash");
  if (!error) { box.hidden = true; plain(box, ""); return; }
  showError(box, error);
  box.hidden = false;
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function flashKey(key, params) {
  const box = $("#flash");
  msg(box, key, params);
  box.hidden = false;
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function api(path, options = {}) {
  const init = { method: options.method || "GET", credentials: "same-origin", headers: {} };
  if (options.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  if (init.method !== "GET") init.headers["X-Requested-With"] = "grd-sgr";
  const response = await fetch(path, init);
  let data = null;
  try { data = await response.json(); } catch (_) { data = null; }
  if (!response.ok) {
    throw new ApiError((data && data.error) || "", response.status, data && data.code, data && data.params);
  }
  return data;
}

// -- tabs --------------------------------------------------------------------------------------

function showTab(name) {
  for (const button of $$(".tabs button")) button.setAttribute("aria-selected", String(button.dataset.tab === name));
  for (const panel of $$(".tab")) panel.hidden = panel.id !== `tab-${name}`;
}

// -- target (EMS, evidence, meter) ---------------------------------------------------------------

function configForm(container, summary) {
  container.replaceChildren();
  for (const item of summary.configuration) {
    let placeholder;
    if (item.secret) placeholder = [item.set ? "cfg.set_keep" : "cfg.required", null];
    else if (item.default !== null && item.default !== undefined) placeholder = ["cfg.default", { value: item.default }];
    else placeholder = ["cfg.required", null];
    const input = el("input", {
      name: item.name, autocomplete: "off", type: item.secret ? "password" : "text", i18nAttr: { placeholder },
    });
    if (!item.secret && item.value !== undefined) input.value = item.value;
    const missing = summary.missing.includes(item.name);
    const label = missing ? el("span", { i18n: "cfg.missing", params: { name: item.name } })
      : el("span", { class: "muted", text: item.name });
    container.append(el("label", {}, label, input));
  }
}

function collect(container) {
  const out = {};
  for (const input of container.querySelectorAll("input[name]")) out[input.name] = input.value;
  return out;
}

function summaryBlock(container, summary) {
  container.replaceChildren(
    el("p", {}, el("strong", { text: summary.device_name }), " — ", summary.manufacturer,
      el("span", { class: "kv" }, "  ·  ",
        el("span", { i18n: "ems.interface", params: { file: summary.file, interface: summary.interface || "?" } }))),
    el("ul", {}, ...summary.profiles.map((fp) => el("li", {}, el("span", { class: "mono", text: fp.name }), ` ${fp.key}`))),
  );
}

function renderTarget() {
  const target = state.target;
  if (!target) { msg($("#target-status"), "status.no_ems"); return; }
  summaryBlock($("#eid-summary"), target.ems);
  configForm($("#config-form"), target.ems);
  if (target.evidence) {
    $("#ev-url").value = target.evidence.url || "";
    $("#ev-hname").value = (target.evidence.headers || [])[0] || "";
    const hvalue = $("#ev-hvalue");
    if (target.evidence.headers.length) {
      hvalue.dataset.i18nAttr = JSON.stringify({ placeholder: ["cfg.set_keep", null] });
      hvalue.placeholder = t("cfg.set_keep");
    } else {
      delete hvalue.dataset.i18nAttr;
      hvalue.placeholder = "Bearer …";
    }
    $("#evidence-card").open = true;
  }
  const meter = target.meter;
  $("#meter-same").checked = Boolean(meter && meter.same_as_ems);
  $("#meter-file-label").hidden = $("#meter-same").checked;
  const select = $("#meter-point");
  select.replaceChildren(el("option", { value: "", i18n: "meter.none" }));
  if (meter) {
    $("#meter-card").open = true;
    if (!meter.same_as_ems) { summaryBlock($("#meter-summary"), meter); configForm($("#meter-form"), meter); }
    else { $("#meter-summary").replaceChildren(); $("#meter-form").replaceChildren(); }
    for (const fp of meter.profiles) {
      for (const dp of fp.data_points) {
        if (!dp.readable) continue;
        const value = `${fp.name}.${dp.name}`;
        const option = el("option", { value, selected: meter.point === value, i18n: "meter.option",
          params: { point: value, unit: dp.unit || { $t: "meter.no_unit" } } });
        select.append(option);
      }
    }
  }
  const missing = target.ems.missing.concat(meter && !meter.same_as_ems ? meter.missing : []);
  if (target.ready) msg($("#target-status"), "status.ready", { name: target.ems.device_name });
  else msg($("#target-status"), "status.missing", { names: missing.join(", ") });
  renderWritables();
}

async function saveTarget(extra = {}) {
  flash(null);
  const body = { props: collect($("#config-form")), ...extra };
  const url = $("#ev-url").value.trim();
  if (url) body.evidence = { url, header_name: $("#ev-hname").value.trim(), header_value: $("#ev-hvalue").value };
  if ($("#meter-same").checked) body.meter = { same_as_ems: true, point: $("#meter-point").value };
  else if (state.target && state.target.meter || extra.meter) {
    body.meter = { ...(extra.meter || {}), props: collect($("#meter-form")), point: $("#meter-point").value };
  }
  try {
    const data = await api("/api/target", { method: "POST", body });
    state.target = data.target;
    $("#ev-hvalue").value = "";
    renderTarget();
  } catch (error) { flash(error); }
}

async function readFile(input) {
  const file = input.files && input.files[0];
  if (!file) return null;
  return { name: file.name, xml: await file.text() };
}

// -- runs (compliance and tariffs) ---------------------------------------------------------------

function testsSelected() {
  const families = new Set($$(".family").filter((x) => x.checked).map((x) => x.value));
  const writes = $("#allow-write").checked;
  const functional = $("#functional").checked;
  const ids = [];
  for (const test of state.info.tests) {
    if (test.family === "S" && families.has("S")) ids.push(test.id);
    else if (test.family === "P" && families.has("P") && (!test.needs_write || writes)) ids.push(test.id);
    else if (test.family === "P" && writes) ids.push(test.id);
    else if (test.family === "F" && functional) ids.push(test.id);
    else if (test.family === "E" && families.has("E")) ids.push(test.id);
  }
  return Array.from(new Set(ids));
}

function reportLinks(job) {
  const base = `/api/jobs/${encodeURIComponent(job.id)}/reports/`;
  const links = el("div", { class: "actions" });
  if (job.reports.includes("report.html")) {
    links.append(el("a", { class: "button primary", href: base + "report.html", target: "_blank", rel: "noopener", i18n: "rep.open" }));
    links.append(el("a", { href: base + "report.html?download=1", text: "HTML" }));
  }
  for (const [name, label] of [["report.json", { i18n: "rep.json" }], ["report.md", { text: "Markdown" }],
    ["report.junit.xml", { text: "JUnit" }]]) {
    if (job.reports.includes(name)) links.append(el("a", { href: base + name, ...label }));
  }
  return el("div", {}, links, el("p", { class: "muted", i18n: "rep.note" }));
}

function renderJob(container, job) {
  container.replaceChildren();
  const card = el("div", { class: "card" });
  if (job.notice) card.append(noticeOf(job));
  const progress = el("ol", { class: "progress" });
  const done = new Map();
  for (const step of job.progress) {
    if (step.event === "scenario") progress.append(el("li", { i18n: "job.serving", params: { scenario: step.scenario } }));
    else if (step.event === "done") done.set(step.test_id, step.verdicts || []);
    else if (step.event === "start" && !done.has(step.test_id)) done.set(step.test_id, null);
  }
  for (const [id, verdicts] of done) {
    const item = el("li", { i18nAttr: { title: ["job.test_label", { id, title: testTitle(id) }] } }, id, " ");
    if (verdicts === null) item.append(el("span", { class: "muted", i18n: "job.running" }));
    else for (const v of verdicts) item.append(pill(v), " ");
    progress.append(item);
  }
  card.append(progress);
  if (job.status === "failed") card.append(el("p", { class: "flash", i18n: "job.failed", params: { error: job.error } }));
  if (job.status === "cancelled") card.append(el("p", { class: "notice", i18n: "job.cancelled" }));
  if (job.overall) {
    card.append(el("p", {}, el("span", { i18n: "job.overall" }), " ", pill(job.overall), " ",
      el("span", { class: "muted", text: Object.entries(job.summary).map(([k, v]) => `${k} ${v}`).join(" · ") })));
    if (job.effect_note) card.append(el("p", { class: "notice", i18n: "job.note", params: { note: job.effect_note } }));
    card.append(reportLinks(job));
  }
  if (job.results && job.results.length) {
    const body = el("tbody");
    for (const r of job.results) {
      const shown = r.findings.filter((f) => f.severity !== "info");
      const findings = (shown.length ? shown : r.findings.slice(0, 2)).map((f) => f.message).join(" · ");
      body.append(el("tr", {}, el("td", { text: r.test_id, i18nAttr: { title: ["job.test_label", { id: r.test_id, title: testTitle(r.test_id) }] } }),
        el("td", { text: r.subject }), el("td", {}, pill(r.verdict)), el("td", { text: findings })));
    }
    card.append(el("div", { class: "table-wrap" }, el("table", { class: "results" },
      el("thead", {}, el("tr", {}, el("th", { i18n: "th.id" }), el("th", { i18n: "th.subject" }), el("th", { i18n: "th.verdict" }),
        el("th", { i18n: "th.findings" }))),
      body)));
  }
  container.append(card);
}

function noticeOf(job) {
  const node = el("p", { class: "notice" });
  if (job.notice_code && known(`notice.${job.notice_code}`)) msg(node, `notice.${job.notice_code}`, job.notice_params);
  else plain(node, job.notice);
  return node;
}

function watch(job, container, statusEl, cancelButton, runButton) {
  state.jobs[job.id] = job;
  const tick = async () => {
    try {
      const data = await api(`/api/jobs/${encodeURIComponent(job.id)}`);
      const current = data.job;
      state.jobs[current.id] = current;
      renderJob(container, current);
      msg(statusEl, `run.${current.status}`);
      if (current.status === "running") { state.polls[job.id] = setTimeout(tick, 1000); return; }
      cancelButton.hidden = true;
      runButton.disabled = false;
      loadHistory();
    } catch (error) { showError(statusEl, error); runButton.disabled = false; cancelButton.hidden = true; }
  };
  cancelButton.hidden = false;
  cancelButton.onclick = async () => {
    try { await api(`/api/jobs/${encodeURIComponent(job.id)}/cancel`, { method: "POST", body: {} }); }
    catch (error) { flash(error); }
  };
  runButton.disabled = true;
  tick();
}

async function runCompliance() {
  flash(null);
  const tests = testsSelected();
  const writes = $("#allow-write").checked || $("#functional").checked;
  const body = {
    kind: "compliance", tests, allow_write: writes, confirm_writes: $("#confirm-writes").checked,
    functional: $("#functional").checked, hold_s: Number($("#hold").value || 60),
  };
  if ($("#reaction").value) body.reaction_time_s = Number($("#reaction").value);
  try {
    const data = await api("/api/jobs", { method: "POST", body });
    watch(data.job, $("#compliance-result"), $("#run-status"), $("#cancel"), $("#run"));
  } catch (error) { flash(error); }
}

async function runTariffs() {
  flash(null);
  const scenarios = $$("#scenarios input").filter((x) => x.checked).map((x) => x.value);
  try {
    const data = await api("/api/jobs", { method: "POST", body: { kind: "tariffs", scenarios, dwell_s: Number($("#dwell").value || 600) } });
    const notice = $("#tariff-notice");
    notice.replaceWith(Object.assign(data.job.notice ? noticeOf(data.job) : el("p", { class: "notice" }),
      { id: "tariff-notice", hidden: !data.job.notice }));
    watch(data.job, $("#tariff-result"), $("#tariff-status"), $("#cancel-tariffs"), $("#run-tariffs"));
  } catch (error) { flash(error); }
}

async function loadHistory() {
  try {
    const data = await api("/api/jobs");
    const list = $("#history");
    list.replaceChildren();
    for (const job of data.jobs) {
      const item = el("li", {}, `${job.started_utc.replace("T", " ").slice(0, 19)} UTC — `,
        el("span", { i18n: `kind.${job.kind}` }), " — ",
        job.overall ? pill(job.overall) : el("span", { class: "muted", i18n: `st.${job.status}` }), " ");
      if (job.reports.includes("report.html")) {
        item.append(el("a", { href: `/api/jobs/${encodeURIComponent(job.id)}/reports/report.html`, target: "_blank", rel: "noopener", i18n: "hist.report" }));
      }
      list.append(item);
    }
  } catch (_) { /* the history is a convenience */ }
}

// -- console ---------------------------------------------------------------------------------------

function showValue(value) {
  if (value === null || value === undefined) return "—";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

function renderPoints(points) {
  const body = $("#points");
  body.replaceChildren();
  for (const p of points) {
    const value = p.error ? el("td", { class: "mono", i18n: "k.point_error", params: { detail: p.error } })
      : el("td", { class: "mono", text: showValue(p.value) });
    body.append(el("tr", {}, el("td", { class: "mono", text: p.fp }), el("td", { class: "mono", text: p.dp }),
      value, el("td", { text: p.unit || "" })));
  }
}

function renderLog(log) {
  const list = $("#console-log");
  list.replaceChildren();
  for (const entry of log || []) {
    list.append(el("li", {}, el("span", { class: "muted", text: `${entry.ts} ` }), el("span", { class: "mono", text: `${entry.fp}.${entry.dp} ← ${showValue(entry.value)} ` }),
      entry.ok ? pill("PASS") : el("span", {}, pill("FAIL"), ` ${entry.error || ""}`)));
  }
}

const TEMPLATES = {
  RestrictPower: { RestrictionActive: true, Restriction: { MinimumPowerKw: -1000, MaximumPowerKw: 2, DurationInMinutes: 15 } },
};

function renderWritables() {
  const box = $("#writables");
  box.replaceChildren();
  if (!state.target) return;
  for (const fp of state.target.ems.profiles) {
    for (const dp of fp.data_points) {
      if (!dp.writable) continue;
      let input;
      if (dp.literals.length) {
        input = el("select", {}, ...dp.literals.map((lit) => el("option", { value: lit, text: lit })));
      } else if (dp.type === "json" || TEMPLATES[dp.name]) {
        input = el("textarea", { spellcheck: "false" });
        input.value = JSON.stringify(TEMPLATES[dp.name] || {}, null, 1);
      } else {
        input = el("input", { type: /int|float/.test(dp.type) ? "number" : "text", step: "any" });
      }
      const send = el("button", { type: "button", class: "primary", i18n: "k.send" });
      send.addEventListener("click", () => writePoint(fp.name, dp, input));
      box.append(el("div", { class: "writable" },
        el("p", {}, el("strong", { class: "mono", text: `${fp.name}.${dp.name}` }), el("span", { class: "muted", text: `  ${dp.type}${dp.unit ? ", " + dp.unit : ""}` })),
        el("div", { class: "row" }, input, send)));
    }
  }
  if (!box.children.length) box.append(el("p", { class: "muted", i18n: "k.no_writable" }));
}

async function writePoint(fpName, dp, input) {
  flash(null);
  let value = input.value;
  if (input.tagName === "TEXTAREA") {
    try { value = JSON.parse(input.value); } catch (_) { flashKey("k.bad_json"); return; }
  } else if (input.type === "number") value = Number(input.value);
  try {
    await api("/api/console/write", { method: "POST", body: { fp: fpName, dp: dp.name, value, confirm: $("#confirm-console").checked } });
    await refreshConsole();
  } catch (error) { flash(error); }
}

async function refreshConsole() {
  try {
    const data = await api("/api/console/points");
    renderPoints(data.points);
    renderLog(data.log);
    await refreshJournal();
  } catch (error) { showError($("#console-status"), error); }
}

async function refreshJournal() {
  try {
    const data = await api(`/api/console/evidence?after_seq=${state.lastSeq}`);
    if (!data.available) { msg($("#journal-note"), "k.no_evidence"); return; }
    const body = $("#journal");
    for (const e of data.events) {
      state.lastSeq = Math.max(state.lastSeq, e.seq || 0);
      const subject = [e.fp && e.dp ? `${e.fp}.${e.dp}` : e.fp || e.device || "", e.value !== undefined && e.value !== null ? `= ${showValue(e.value)}` : ""].join(" ");
      body.prepend(el("tr", {}, el("td", { text: e.seq }), el("td", { class: "mono", text: e.ts }), el("td", { text: e.kind }),
        el("td", { class: "mono", text: subject }), el("td", { text: [e.result, e.reason].filter(Boolean).join(" — ") })));
    }
    while (body.children.length > 200) body.lastChild.remove();
    plain($("#journal-note"), "");
  } catch (error) { showError($("#journal-note"), error); }
}

async function connectConsole() {
  flash(null);
  msg($("#console-status"), "k.connecting");
  try {
    const data = await api("/api/console/connect", { method: "POST", body: {} });
    renderPoints(data.points);
    state.lastSeq = 0;
    $("#journal").replaceChildren();
    if (data.warnings.length) msg($("#console-status"), "k.connected_warn", { warnings: data.warnings.join(" · ") });
    else msg($("#console-status"), "k.connected");
    await refreshJournal();
  } catch (error) { plain($("#console-status"), ""); flash(error); }
}

// -- start -------------------------------------------------------------------------------------------

async function start() {
  setLanguage(pickLanguage(), false);
  for (const button of $$("#langs button")) button.addEventListener("click", () => setLanguage(button.dataset.lang, true));
  for (const button of $$(".tabs button")) button.addEventListener("click", () => showTab(button.dataset.tab));
  try {
    state.info = await api("/api/info");
  } catch (error) { flash(error); return; }
  msg($("#version"), "version", { version: state.info.tool_version, commit: state.info.spec_commit.slice(0, 7),
    date: state.info.spec_date });
  const chips = $("#scenarios");
  for (const name of state.info.scenarios) {
    chips.append(el("label", { class: "check" }, el("input", { type: "checkbox", value: name, checked: ["normal", "dst_spring", "http_500"].includes(name) }), name));
  }
  if (!state.info.tariffs_available) {
    $("#run-tariffs").disabled = true;
    msg($("#tariff-status"), "t.hosted");
  }
  $("#hold").max = String(state.info.max_hold_s);
  $("#dwell").max = String(state.info.max_dwell_s);

  $("#eid-file").addEventListener("change", async (event) => {
    const eid = await readFile(event.target);
    if (eid) await saveTarget({ eid });
  });
  $("#meter-file").addEventListener("change", async (event) => {
    const eid = await readFile(event.target);
    if (eid) await saveTarget({ meter: { eid } });
  });
  $("#meter-same").addEventListener("change", () => { $("#meter-file-label").hidden = $("#meter-same").checked; saveTarget(); });
  $("#save-target").addEventListener("click", () => saveTarget());
  $("#run").addEventListener("click", runCompliance);
  $("#run-tariffs").addEventListener("click", runTariffs);
  $("#connect").addEventListener("click", connectConsole);
  $("#refresh").addEventListener("click", refreshConsole);
  $("#disconnect").addEventListener("click", async () => {
    try { await api("/api/console/disconnect", { method: "POST", body: {} }); msg($("#console-status"), "k.disconnected"); }
    catch (error) { flash(error); }
  });
  $("#auto").addEventListener("change", (event) => {
    clearInterval(state.consoleTimer);
    if (event.target.checked) state.consoleTimer = setInterval(refreshConsole, 5000);
  });

  try {
    const data = await api("/api/target");
    state.target = data.target;
    renderTarget();
  } catch (error) { flash(error); }
  loadHistory();
}

document.addEventListener("DOMContentLoaded", start);
