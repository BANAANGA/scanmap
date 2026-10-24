/* scanmap front-end: plain DOM, no build step. */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const state = {
  scanner: "nmap",
  jobId: null,
  offset: 0,
  timer: null,
  job: null,
  lines: [],
  hosts: new Set(),
  resultFields: null,
  copyStatusTimer: null,
  busy: false,
};

const TERMINAL = new Set(["finished", "failed", "cancelled"]);

/* ------------------------------------------------------------------ http */

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (response.status === 204) return null;
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const message = (payload && payload.error) || `HTTP ${response.status}`;
    throw new Error(message);
  }
  return payload;
}

/* ----------------------------------------------------------------- tools */

async function loadTools(refresh = false) {
  const el = $("#tools");
  try {
    const data = await api(`/api/tools${refresh ? "?refresh=1" : ""}`);
    el.innerHTML = "";
    data.tools.forEach((tool) => {
      const pill = document.createElement("span");
      pill.className = "pill";
      const dot = document.createElement("span");
      dot.className = `dot${tool.available ? " ok" : ""}`;
      const name = document.createElement("strong");
      name.textContent = tool.name;
      const ver = document.createElement("span");
      ver.className = "ver";
      ver.textContent = tool.available ? tool.version || "available" : "not installed";
      pill.append(dot, name, ver);
      el.append(pill);
      const tab = $(`.tab[data-scanner="${tool.name}"]`);
      if (tab) {
        tab.disabled = !tool.available;
        tab.title = tool.available ? "" : `${tool.name} is not installed in this container`;
      }
    });
    checkScannerAvailability();
  } catch (error) {
    el.textContent = `could not read tool status: ${error.message}`;
  }
}

function scannerAvailable(scanner) {
  const tab = $(`.tab[data-scanner="${scanner}"]`);
  return tab ? !tab.disabled : true;
}

function checkScannerAvailability() {
  const hint = $("#tab-hint");
  if (!scannerAvailable(state.scanner)) {
    hint.textContent = `${state.scanner} is not available in this container`;
  } else {
    hint.textContent = "";
  }
  $$('button.primary').forEach((button) => {
    button.disabled = !scannerAvailable(state.scanner);
  });
}

/* ------------------------------------------------------------------ tabs */

function selectScanner(scanner) {
  state.scanner = scanner;
  $$(".tab").forEach((tab) => {
    const active = tab.dataset.scanner === scanner;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  $("#nmap-form").classList.toggle("hidden", scanner !== "nmap");
  $("#zmap-form").classList.toggle("hidden", scanner !== "zmap");
  checkScannerAvailability();
  updatePreview();
}

$$(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    if (tab.disabled) return;
    selectScanner(tab.dataset.scanner);
  });
});

/* ----------------------------------------------------------------- forms */

function readForm(form) {
  const data = new FormData(form);
  const params = {};
  for (const [key, value] of data.entries()) {
    params[key] = typeof value === "string" ? value.trim() : value;
  }
  $$('input[type="checkbox"]', form).forEach((input) => {
    params[input.name] = input.checked;
  });
  return params;
}

let previewTimer = null;
function updatePreview() {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(async () => {
    const form = state.scanner === "nmap" ? $("#nmap-form") : $("#zmap-form");
    const target = $(`#${state.scanner}-preview`);
    const targetValue = (form.elements.namedItem("target")?.value || "").trim();
    if (!targetValue) {
      target.textContent = "enter a target to preview the command";
      target.style.color = "";
      return;
    }
    try {
      const data = await api("/api/preview", {
        method: "POST",
        body: JSON.stringify({ scanner: state.scanner, params: readForm(form) }),
      });
      target.textContent = data.argv.map(shellQuote).join(" ");
      target.style.color = "";
    } catch (error) {
      target.textContent = error.message;
      target.style.color = "#ffb454";
    }
  }, 180);
}

function shellQuote(value) {
  return /^[A-Za-z0-9_./:=@%+,-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`;
}

["nmap-form", "zmap-form"].forEach((id) => {
  const form = $(`#${id}`);
  form.addEventListener("input", updatePreview);
  form.addEventListener("change", updatePreview);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    await startScan(form.dataset.scanner, readForm(form));
  });
});

async function startScan(scanner, params) {
  if (state.busy) return;
  state.busy = true;
  try {
    const job = await api("/api/jobs", {
      method: "POST",
      body: JSON.stringify({ scanner, params }),
    });
    await refreshJobs();
    selectJob(job.id);
  } catch (error) {
    appendConsole(`error: ${error.message}`, true);
  } finally {
    state.busy = false;
  }
}

/* ------------------------------------------------------------------- jobs */

async function refreshJobs() {
  try {
    const data = await api("/api/jobs");
    renderJobs(data.jobs);
    return data.jobs;
  } catch (error) {
    $("#job-list").innerHTML = "";
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = `could not load jobs: ${error.message}`;
    $("#job-list").append(li);
    return [];
  }
}

function renderJobs(jobs) {
  const list = $("#job-list");
  list.innerHTML = "";
  if (!jobs.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No scans yet.";
    list.append(li);
    return;
  }
  jobs.forEach((job) => {
    const li = document.createElement("li");
    li.className = `job${job.id === state.jobId ? " is-active" : ""}`;
    li.dataset.id = job.id;

    const top = document.createElement("div");
    top.className = "job-top";
    const name = document.createElement("span");
    name.className = "job-name";
    name.textContent = `${job.scanner} → ${targetOf(job.argv)}`;
    const badge = document.createElement("span");
    badge.className = `badge ${job.status}`;
    badge.textContent = job.status;
    top.append(name, badge);

    const meta = document.createElement("div");
    meta.className = "job-meta";
    const id = document.createElement("span");
    id.textContent = job.id;
    const when = document.createElement("span");
    when.textContent = formatDuration(job);
    meta.append(id, when);

    li.append(top, meta);
    li.addEventListener("click", () => selectJob(job.id));
    list.append(li);
  });
}

function targetOf(argv) {
  return argv.length ? argv[argv.length - 1] : "";
}

function formatDuration(job) {
  if (job.duration === null || job.duration === undefined) return "queued";
  const total = Math.round(job.duration);
  if (total < 60) return `${total}s`;
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return `${minutes}m ${seconds}s`;
}

/* ---------------------------------------------------------------- polling */

function selectJob(jobId) {
  if (!jobId) return;
  state.jobId = jobId;
  state.offset = 0;
  state.lines = [];
  state.hosts = new Set();
  state.resultFields = null;
  state.job = null;
  $("#console").textContent = "";
  $("#results-wrap").classList.add("hidden");
  $("#results-table thead").textContent = "";
  $("#results-table tbody").textContent = "";
  $("#copy-status").textContent = "";
  $("#job-ref").textContent = jobId;
  $("#cancel-job").disabled = false;
  $("#clear-job").disabled = false;
  $("#download-log").disabled = false;
  $("#host-counter").textContent = "";
  poll();
  if (state.timer) clearInterval(state.timer);
  state.timer = setInterval(poll, 900);
  refreshJobs();
}

async function poll() {
  if (!state.jobId) return;
  try {
    const job = await api(`/api/jobs/${state.jobId}?since=${state.offset}`);
    state.job = job;
    if (job.scanner === "zmap" && !state.resultFields) {
      const fieldsIndex = job.argv.indexOf("-f");
      if (fieldsIndex >= 0 && job.argv[fieldsIndex + 1]) {
        state.resultFields = job.argv[fieldsIndex + 1].split(",");
      }
    }
    if (job.output && job.output.length) {
      job.output.forEach((line) => appendConsole(line));
      state.offset = job.next;
    }
    updateJobUi(job);
    if (TERMINAL.has(job.status) && state.timer) {
      clearInterval(state.timer);
      state.timer = null;
      refreshJobs();
    } else if (job.status === "running" || job.status === "queued") {
      refreshJobs();
    }
  } catch (error) {
    appendConsole(`error: ${error.message}`, true);
    if (state.timer) clearInterval(state.timer);
    state.timer = null;
  }
}

function updateJobUi(job) {
  const running = job.status === "running" || job.status === "queued";
  $("#cancel-job").disabled = !running;
  $("#job-ref").textContent = `${job.id} · ${job.status}`;
  if (job.error) {
    if (!state.lines.includes(job.error)) appendConsole(job.error, true);
  }
  const hosts = state.hosts.size;
  $("#host-counter").textContent = job.scanner === "zmap" && hosts ? `${hosts} hosts` : "";
}

/* ---------------------------------------------------------------- console */

function appendConsole(line, isError = false) {
  const consoleEl = $("#console");
  const atBottom = consoleEl.scrollHeight - consoleEl.scrollTop - consoleEl.clientHeight < 40;
  state.lines.push(line);
  if (!isError && state.job?.scanner === "zmap" && appendZmapResult(line)) {
    if (state.lines.length === 1 && consoleEl.textContent.startsWith("Select a job")) {
      consoleEl.textContent = "";
    }
    return;
  }
  if (state.lines.length === 1 && consoleEl.textContent.startsWith("Select a job")) {
    consoleEl.textContent = "";
  }
  const node = document.createElement("span");
  node.className = isError ? "log-error" : "";
  node.textContent = `${line}\n`;
  consoleEl.append(node);
  if (atBottom) consoleEl.scrollTop = consoleEl.scrollHeight;
}

function parseCsvLine(line) {
  const values = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (char === '"' && quoted && line[index + 1] === '"') {
      value += '"';
      index += 1;
    } else if (char === '"') {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      values.push(value);
      value = "";
    } else {
      value += char;
    }
  }
  if (quoted) return null;
  values.push(value);
  return values;
}

function appendZmapResult(line) {
  const values = parseCsvLine(line);
  const fields = state.resultFields;
  if (!values || !fields || values.length !== fields.length) return false;

  const normalized = values.map((value) => value.trim().toLowerCase());
  if (normalized.every((value, index) => value === fields[index].toLowerCase())) {
    renderResultHeaders(fields);
    return true;
  }

  const addressIndex = fields.findIndex((field) => field === "saddr" || field === "saddr-raw");
  if (addressIndex >= 0) {
    const addressPattern = fields[addressIndex] === "saddr-raw"
      ? /^(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]+|[0-9]+)$/
      : /^(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]+)$/;
    if (!addressPattern.test(values[addressIndex])) return false;
  }
  if (values.some((value) => !value.trim())) return false;

  renderResultHeaders(fields);
  const row = document.createElement("tr");
  values.forEach((value) => {
    const cell = document.createElement("td");
    const copyButton = document.createElement("button");
    copyButton.type = "button";
    copyButton.className = "copy-value";
    copyButton.textContent = value;
    copyButton.title = "Click to copy";
    copyButton.setAttribute("aria-label", `Copy ${value}`);
    copyButton.addEventListener("click", () => copyResultValue(value));
    cell.append(copyButton);
    row.append(cell);
  });
  $("#results-table tbody").append(row);

  if (addressIndex >= 0) state.hosts.add(values[addressIndex]);
  $("#host-counter").textContent = state.hosts.size ? `${state.hosts.size} hosts` : "";
  return true;
}

function renderResultHeaders(fields) {
  const table = $("#results-table");
  if (table.tHead.rows.length) return;
  const row = table.tHead.insertRow();
  fields.forEach((field) => {
    const header = document.createElement("th");
    header.scope = "col";
    header.textContent = field;
    row.append(header);
  });
  $("#results-wrap").classList.remove("hidden");
}

async function copyResultValue(value) {
  const status = $("#copy-status");
  let copied = false;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      copied = true;
    }
  } catch {
    copied = false;
  }
  if (!copied) copied = copyWithSelection(value);
  status.textContent = copied ? `Copied “${value}”` : "Could not copy value";
  clearTimeout(state.copyStatusTimer);
  state.copyStatusTimer = setTimeout(() => {
    status.textContent = "";
  }, 1800);
}

function copyWithSelection(value) {
  const input = document.createElement("textarea");
  input.value = value;
  input.setAttribute("readonly", "");
  input.style.position = "fixed";
  input.style.opacity = "0";
  document.body.append(input);
  input.select();
  const copied = document.execCommand("copy");
  input.remove();
  return copied;
}

$("#cancel-job").addEventListener("click", async () => {
  if (!state.jobId) return;
  try {
    await api(`/api/jobs/${state.jobId}/cancel`, { method: "POST" });
  } catch (error) {
    appendConsole(`error: ${error.message}`, true);
  }
});

$("#clear-job").addEventListener("click", () => {
  state.lines = [];
  state.hosts = new Set();
  state.offset = state.job ? state.job.next : state.offset;
  $("#console").textContent = "";
  $("#results-wrap").classList.add("hidden");
  $("#results-table thead").textContent = "";
  $("#results-table tbody").textContent = "";
  $("#host-counter").textContent = "";
});

$("#download-log").addEventListener("click", () => {
  if (!state.lines.length) return;
  const blob = new Blob([state.lines.join("\n") + "\n"], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `scanmap-${state.job ? state.job.scanner : "scan"}-${state.jobId}.log`;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
});

$("#refresh-jobs").addEventListener("click", () => refreshJobs());

/* ------------------------------------------------------------------- boot */

(async function boot() {
  await loadTools();
  selectScanner("nmap");
  const jobs = await refreshJobs();
  const running = jobs.find((job) => job.status === "running" || job.status === "queued");
  if (running) selectJob(running.id);
})();
