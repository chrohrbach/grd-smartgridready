// grd-sgr web UI. No framework, no external resource. Everything that comes
// from the EMS or the server is inserted as text (textContent), never as HTML.
"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const VERDICT_CLASS = { PASS: "pass", FAIL: "fail", ERROR: "fail", INCONCLUSIVE: "warn",
  HARDWARE_REQUIRED: "warn", "N/A": "muted", SKIPPED: "muted" };

const state = { info: null, target: null, jobs: {}, polls: {}, consoleTimer: null, lastSeq: 0 };

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function pill(verdict) {
  return el("span", { class: `pill v-${VERDICT_CLASS[verdict] || "muted"}`, text: verdict });
}

function flash(message) {
  const box = $("#flash");
  if (!message) { box.hidden = true; box.textContent = ""; return; }
  box.textContent = message;
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
  if (!response.ok) throw new Error((data && data.error) || `HTTP ${response.status}`);
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
    const input = el("input", {
      name: item.name, autocomplete: "off",
      type: item.secret ? "password" : "text",
      placeholder: item.secret ? (item.set ? "set — leave blank to keep" : "required")
        : (item.default !== null && item.default !== undefined ? `default: ${item.default}` : "required"),
    });
    if (!item.secret && item.value !== undefined) input.value = item.value;
    const missing = summary.missing.includes(item.name);
    container.append(el("label", {}, el("span", { class: missing ? "" : "muted", text: item.name + (missing ? " (missing)" : "") }), input));
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
      el("span", { class: "kv", text: `  ·  ${summary.file} · ${summary.interface || "?"} interface` })),
    el("ul", {}, ...summary.profiles.map((fp) => el("li", {}, el("span", { class: "mono", text: fp.name }), ` ${fp.key}`))),
  );
}

function renderTarget() {
  const target = state.target;
  if (!target) { $("#target-status").textContent = "No EMS yet: load its EID."; return; }
  summaryBlock($("#eid-summary"), target.ems);
  configForm($("#config-form"), target.ems);
  if (target.evidence) {
    $("#ev-url").value = target.evidence.url || "";
    $("#ev-hname").value = (target.evidence.headers || [])[0] || "";
    $("#ev-hvalue").placeholder = target.evidence.headers.length ? "set — leave blank to keep" : "Bearer …";
    $("#evidence-card").open = true;
  }
  const meter = target.meter;
  $("#meter-same").checked = Boolean(meter && meter.same_as_ems);
  $("#meter-file-label").hidden = $("#meter-same").checked;
  const select = $("#meter-point");
  select.replaceChildren(el("option", { value: "", text: "— none —" }));
  if (meter) {
    $("#meter-card").open = true;
    if (!meter.same_as_ems) { summaryBlock($("#meter-summary"), meter); configForm($("#meter-form"), meter); }
    else { $("#meter-summary").replaceChildren(); $("#meter-form").replaceChildren(); }
    for (const fp of meter.profiles) {
      for (const dp of fp.data_points) {
        if (!dp.readable) continue;
        const value = `${fp.name}.${dp.name}`;
        select.append(el("option", { value, text: `${value} (${dp.unit || "no unit"})`, selected: meter.point === value }));
      }
    }
  }
  const missing = target.ems.missing.concat(meter && !meter.same_as_ems ? meter.missing : []);
  $("#target-status").textContent = target.ready
    ? `Ready: ${target.ems.device_name}.` : `Missing: ${missing.join(", ")}.`;
  renderWritables();
}

async function saveTarget(extra = {}) {
  flash("");
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
  } catch (error) { flash(error.message); }
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
    links.append(el("a", { class: "button primary", href: base + "report.html", target: "_blank", rel: "noopener", text: "Open the audit report" }));
    links.append(el("a", { href: base + "report.html?download=1", text: "HTML" }));
  }
  for (const [name, label] of [["report.json", "JSON evidence"], ["report.md", "Markdown"], ["report.junit.xml", "JUnit"]]) {
    if (job.reports.includes(name)) links.append(el("a", { href: base + name, text: label }));
  }
  return links;
}

function titleOf(id) {
  const test = state.info.tests.find((t) => t.id === id);
  return test ? `${id} ${test.title}` : id;
}

function renderJob(container, job) {
  container.replaceChildren();
  const card = el("div", { class: "card" });
  if (job.notice) card.append(el("p", { class: "notice", text: job.notice }));
  const progress = el("ol", { class: "progress" });
  const done = new Map();
  for (const step of job.progress) {
    if (step.event === "scenario") progress.append(el("li", { text: `serving ${step.scenario}` }));
    else if (step.event === "done") done.set(step.test_id, step.verdicts || []);
    else if (step.event === "start" && !done.has(step.test_id)) done.set(step.test_id, null);
  }
  for (const [id, verdicts] of done) {
    const item = el("li", { title: titleOf(id) }, id, " ");
    if (verdicts === null) item.append(el("span", { class: "muted", text: "running…" }));
    else for (const v of verdicts) item.append(pill(v), " ");
    progress.append(item);
  }
  card.append(progress);
  if (job.status === "failed") card.append(el("p", { class: "flash", text: `The run could not go on: ${job.error}` }));
  if (job.status === "cancelled") card.append(el("p", { class: "notice", text: "Cancelled. Each test that commanded the EMS wrote the released state on its way out." }));
  if (job.overall) {
    card.append(el("p", {}, "Overall ", pill(job.overall), " ",
      el("span", { class: "muted", text: Object.entries(job.summary).map(([k, v]) => `${k} ${v}`).join(" · ") })));
    if (job.effect_note) card.append(el("p", { class: "notice", text: `Note: ${job.effect_note}.` }));
    card.append(reportLinks(job));
  }
  if (job.results && job.results.length) {
    const body = el("tbody");
    for (const r of job.results) {
      const shown = r.findings.filter((f) => f.severity !== "info");
      const findings = (shown.length ? shown : r.findings.slice(0, 2)).map((f) => f.message).join(" · ");
      body.append(el("tr", {}, el("td", { text: r.test_id }), el("td", { text: r.subject }),
        el("td", {}, pill(r.verdict)), el("td", { text: findings })));
    }
    card.append(el("div", { class: "table-wrap" }, el("table", { class: "results" },
      el("thead", {}, el("tr", {}, el("th", { text: "ID" }), el("th", { text: "Subject" }), el("th", { text: "Verdict" }), el("th", { text: "Findings" }))),
      body)));
  }
  container.append(card);
}

function watch(job, container, statusEl, cancelButton, runButton) {
  state.jobs[job.id] = job;
  const tick = async () => {
    try {
      const data = await api(`/api/jobs/${encodeURIComponent(job.id)}`);
      const current = data.job;
      state.jobs[current.id] = current;
      renderJob(container, current);
      statusEl.textContent = current.status === "running" ? "Running…" : `Run ${current.status}.`;
      if (current.status === "running") { state.polls[job.id] = setTimeout(tick, 1000); return; }
      cancelButton.hidden = true;
      runButton.disabled = false;
      loadHistory();
    } catch (error) { statusEl.textContent = error.message; runButton.disabled = false; cancelButton.hidden = true; }
  };
  cancelButton.hidden = false;
  cancelButton.onclick = async () => {
    try { await api(`/api/jobs/${encodeURIComponent(job.id)}/cancel`, { method: "POST", body: {} }); }
    catch (error) { flash(error.message); }
  };
  runButton.disabled = true;
  tick();
}

async function runCompliance() {
  flash("");
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
  } catch (error) { flash(error.message); }
}

async function runTariffs() {
  flash("");
  const scenarios = $$("#scenarios input").filter((x) => x.checked).map((x) => x.value);
  try {
    const data = await api("/api/jobs", { method: "POST", body: { kind: "tariffs", scenarios, dwell_s: Number($("#dwell").value || 600) } });
    const notice = $("#tariff-notice");
    notice.textContent = data.job.notice || "";
    notice.hidden = !data.job.notice;
    watch(data.job, $("#tariff-result"), $("#tariff-status"), $("#cancel-tariffs"), $("#run-tariffs"));
  } catch (error) { flash(error.message); }
}

async function loadHistory() {
  try {
    const data = await api("/api/jobs");
    const list = $("#history");
    list.replaceChildren();
    for (const job of data.jobs) {
      const item = el("li", {}, `${job.started_utc.replace("T", " ").slice(0, 19)} UTC — ${job.kind} — `,
        job.overall ? pill(job.overall) : el("span", { class: "muted", text: job.status }), " ");
      if (job.reports.includes("report.html")) {
        item.append(el("a", { href: `/api/jobs/${encodeURIComponent(job.id)}/reports/report.html`, target: "_blank", rel: "noopener", text: "audit report" }));
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
    body.append(el("tr", {}, el("td", { class: "mono", text: p.fp }), el("td", { class: "mono", text: p.dp }),
      el("td", { class: "mono", text: p.error ? `error: ${p.error}` : showValue(p.value) }), el("td", { text: p.unit || "" })));
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
      const send = el("button", { type: "button", class: "primary", text: "Send" });
      send.addEventListener("click", () => writePoint(fp.name, dp, input));
      box.append(el("div", { class: "writable" },
        el("p", {}, el("strong", { class: "mono", text: `${fp.name}.${dp.name}` }), el("span", { class: "muted", text: `  ${dp.type}${dp.unit ? ", " + dp.unit : ""}` })),
        el("div", { class: "row" }, input, send)));
    }
  }
  if (!box.children.length) box.append(el("p", { class: "muted", text: "This EID declares no writable data point." }));
}

async function writePoint(fpName, dp, input) {
  flash("");
  let value = input.value;
  if (input.tagName === "TEXTAREA") {
    try { value = JSON.parse(input.value); } catch (_) { flash("The value is not valid JSON."); return; }
  } else if (input.type === "number") value = Number(input.value);
  try {
    await api("/api/console/write", { method: "POST", body: { fp: fpName, dp: dp.name, value, confirm: $("#confirm-console").checked } });
    await refreshConsole();
  } catch (error) { flash(error.message); }
}

async function refreshConsole() {
  try {
    const data = await api("/api/console/points");
    renderPoints(data.points);
    renderLog(data.log);
    await refreshJournal();
  } catch (error) { $("#console-status").textContent = error.message; }
}

async function refreshJournal() {
  try {
    const data = await api(`/api/console/evidence?after_seq=${state.lastSeq}`);
    if (!data.available) { $("#journal-note").textContent = "No evidence API configured for this EMS."; return; }
    const body = $("#journal");
    for (const e of data.events) {
      state.lastSeq = Math.max(state.lastSeq, e.seq || 0);
      const subject = [e.fp && e.dp ? `${e.fp}.${e.dp}` : e.fp || e.device || "", e.value !== undefined && e.value !== null ? `= ${showValue(e.value)}` : ""].join(" ");
      body.prepend(el("tr", {}, el("td", { text: e.seq }), el("td", { class: "mono", text: e.ts }), el("td", { text: e.kind }),
        el("td", { class: "mono", text: subject }), el("td", { text: [e.result, e.reason].filter(Boolean).join(" — ") })));
    }
    while (body.children.length > 200) body.lastChild.remove();
    $("#journal-note").textContent = "";
  } catch (error) { $("#journal-note").textContent = error.message; }
}

async function connectConsole() {
  flash("");
  $("#console-status").textContent = "Connecting…";
  try {
    const data = await api("/api/console/connect", { method: "POST", body: {} });
    renderPoints(data.points);
    state.lastSeq = 0;
    $("#journal").replaceChildren();
    $("#console-status").textContent = data.warnings.length ? `Connected, with warnings: ${data.warnings.join(" · ")}` : "Connected.";
    await refreshJournal();
  } catch (error) { $("#console-status").textContent = ""; flash(error.message); }
}

// -- start -------------------------------------------------------------------------------------------

async function start() {
  for (const button of $$(".tabs button")) button.addEventListener("click", () => showTab(button.dataset.tab));
  try {
    state.info = await api("/api/info");
  } catch (error) { flash(error.message); return; }
  $("#version").textContent = `${state.info.tool_version} · SGr specification ${state.info.spec_commit.slice(0, 7)} (${state.info.spec_date})`;
  const chips = $("#scenarios");
  for (const name of state.info.scenarios) {
    chips.append(el("label", { class: "check" }, el("input", { type: "checkbox", value: name, checked: ["normal", "dst_spring", "http_500"].includes(name) }), name));
  }
  if (!state.info.tariffs_available) {
    $("#run-tariffs").disabled = true;
    $("#tariff-status").textContent = "Not available on a hosted instance: run grd-sgr ui locally for the tariff tests.";
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
    try { await api("/api/console/disconnect", { method: "POST", body: {} }); $("#console-status").textContent = "Disconnected."; }
    catch (error) { flash(error.message); }
  });
  $("#auto").addEventListener("change", (event) => {
    clearInterval(state.consoleTimer);
    if (event.target.checked) state.consoleTimer = setInterval(refreshConsole, 5000);
  });

  try {
    const data = await api("/api/target");
    state.target = data.target;
    renderTarget();
  } catch (error) { flash(error.message); }
  loadHistory();
}

document.addEventListener("DOMContentLoaded", start);
