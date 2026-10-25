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
  resultRows: [],
  selectedResultAddresses: new Set(),
  currentNmapHost: null,
  nmapPortSection: false,
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

      async function loadAccountMenu() {
        const menu = $("#account-menu");
        try {
          const response = await fetch("/api/auth/me");
          if (!response.ok) return;
          const data = await response.json();
          if (data.auth !== "session" || !data.user) return;

          const identity = document.createElement("span");
          identity.className = "account-name";
          identity.textContent = data.user.username;
          menu.append(identity);
          if (data.user.is_admin) {
            const admin = document.createElement("a");
            admin.className = "button-link";
            admin.href = "/admin";
            admin.textContent = "Users";
            menu.append(admin);
          }
          const logout = document.createElement("button");
          logout.type = "button";
          logout.className = "button-link";
          logout.textContent = "Sign out";
          logout.addEventListener("click", async () => {
            await fetch("/api/auth/logout", { method: "POST" });
            location.href = "/login";
          });
          menu.append(logout);
          menu.classList.remove("hidden");
        } catch (error) {
          menu.textContent = `account status unavailable: ${error.message}`;
          menu.classList.remove("hidden");
        }
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
  state.resultRows = [];
  state.selectedResultAddresses = new Set();
  state.currentNmapHost = null;
  state.nmapPortSection = false;
  state.job = null;
  $("#console").textContent = "";
  $("#results-wrap").classList.add("hidden");
  $("#results-table thead").textContent = "";
  $("#results-table tbody").textContent = "";
  $("#copy-status").textContent = "";
  updateNmapSelectionAction();
  $("#copy-all-results").disabled = true;
  $("#save-results-csv").disabled = true;
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
    if (job.scanner === "nmap" && TERMINAL.has(job.status)) {
      finishNmapHost();
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
  $("#host-counter").textContent = hosts ? `${hosts} hosts` : "";
}

/* ---------------------------------------------------------------- console */

function appendConsole(line, isError = false) {
  const consoleEl = $("#console");
  const atBottom = consoleEl.scrollHeight - consoleEl.scrollTop - consoleEl.clientHeight < 40;
  state.lines.push(line);
  if (!isError && state.job?.scanner === "nmap" && appendNmapResult(line)) {
    if (state.lines.length === 1 && consoleEl.textContent.startsWith("Select a job")) {
      consoleEl.textContent = "";
    }
    return;
  }
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

function appendNmapResult(line) {
  const report = line.match(/^Nmap scan report for (.+)$/);
  if (report) {
    finishNmapHost();
    const label = report[1];
    const address = label.match(/\(([^()]+)\)$/)?.[1];
    const name = address ? label.slice(0, -(address.length + 3)) : label;
    state.currentNmapHost = {
      name,
      address: address || label,
      display: address ? `${name} (${address})` : name,
      up: false,
      portCount: 0,
    };
    state.nmapPortSection = false;
    return true;
  }

  if (!state.currentNmapHost) return false;
  if (/^Host is up(?:\s|$)/.test(line)) {
    state.currentNmapHost.up = true;
    return true;
  }
  if (/^Host seems down(?:\s|$)/.test(line)) {
    state.currentNmapHost.up = false;
    state.currentNmapHost.down = true;
    return true;
  }
  if (/^PORT\s+STATE\s+SERVICE(?:\s|$)/.test(line)) {
    state.nmapPortSection = true;
    return true;
  }

  if (state.nmapPortSection) {
    const port = line.match(/^(\d+\/(?:tcp|udp|sctp))\s+(\S+)\s+(\S+)(?:\s+(.*))?$/);
    if (port) {
      const host = state.currentNmapHost;
      host.portCount += 1;
      state.hosts.add(host.address);
      addResultRow([host.display, port[1], port[2], port[3], port[4] || ""]);
      $("#host-counter").textContent = `${state.hosts.size} hosts`;
      return true;
    }
  }
  return false;
}

function finishNmapHost() {
  const host = state.currentNmapHost;
  if (host?.up && host.portCount === 0) {
    addResultRow([host.display, "", "up", "host", ""]);
  } else if (host?.down) {
    addResultRow([host.display, "", "down", "host", ""]);
  }
  if (host && (host.up || host.down || host.portCount > 0)) {
    state.hosts.add(host.address);
    $("#host-counter").textContent = `${state.hosts.size} hosts`;
  }
  state.currentNmapHost = null;
  state.nmapPortSection = false;
}

function addResultRow(values) {
  const fields = ["Host", "Port", "State", "Service", "Version"];
  if (!state.resultFields) state.resultFields = fields;
  renderResultHeaders(state.resultFields);
  const row = document.createElement("tr");
  values.forEach((value) => {
    const cell = document.createElement("td");
    const copyButton = document.createElement("button");
    copyButton.type = "button";
    copyButton.className = "copy-value";
    copyButton.textContent = value;
    copyButton.title = "Click to copy";
    copyButton.setAttribute("aria-label", `Copy ${value}`);
    copyButton.disabled = value === "";
    copyButton.addEventListener("click", () => copyResultValue(value));
    cell.append(copyButton);
    row.append(cell);
  });
  $("#results-table tbody").append(row);
  state.resultRows.push(values);
  $("#copy-all-results").disabled = false;
  $("#save-results-csv").disabled = false;
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
  const selectableAddress = fields.includes("saddr") ? values[fields.indexOf("saddr")] : null;
  if (selectableAddress) {
    const selectCell = document.createElement("td");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.className = "result-select";
    checkbox.value = selectableAddress;
    checkbox.checked = state.selectedResultAddresses.has(selectableAddress);
    checkbox.setAttribute("aria-label", `Select ${selectableAddress} for nmap`);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) {
        state.selectedResultAddresses.add(selectableAddress);
      } else {
        state.selectedResultAddresses.delete(selectableAddress);
      }
      updateNmapSelectionAction();
      $$(".result-select").forEach((item) => {
        if (item.value === selectableAddress) item.checked = checkbox.checked;
      });
    });
    selectCell.append(checkbox);
    row.append(selectCell);
  }
  addResultRow(values);

  if (addressIndex >= 0) state.hosts.add(values[addressIndex]);
  $("#host-counter").textContent = state.hosts.size ? `${state.hosts.size} hosts` : "";
  return true;
}

function renderResultHeaders(fields) {
  const table = $("#results-table");
  if (table.tHead.rows.length) return;
  const row = table.tHead.insertRow();
  if (fields.includes("saddr")) {
    const selectHeader = document.createElement("th");
    selectHeader.scope = "col";
    selectHeader.textContent = "Select";
    row.append(selectHeader);
  }
  fields.forEach((field) => {
    const header = document.createElement("th");
    header.scope = "col";
    header.textContent = field;
    row.append(header);
  });
  $("#results-wrap").classList.remove("hidden");
}

async function copyResultValue(value) {
  const copied = await copyText(value);
  showCopyStatus(copied ? `Copied “${value}”` : "Could not copy value");
}

async function copyText(value) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch {
    // Try the selection-based fallback for browsers without clipboard permission.
  }
  return copyWithSelection(value);
}

function showCopyStatus(message) {
  const status = $("#copy-status");
  status.textContent = message;
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

function updateNmapSelectionAction() {
  const button = $("#add-selected-to-nmap");
  const count = state.selectedResultAddresses.size;
  button.disabled = count === 0;
  button.textContent = count ? `add ${count} selected to nmap` : "add selected to nmap";
}

$("#add-selected-to-nmap").addEventListener("click", () => {
  const selected = [...state.selectedResultAddresses];
  if (!selected.length) return;

  const target = $('#nmap-form [name="target"]');
  const current = target.value.trim();
  const existing = new Set(
    current.split(/[,\s]+/).filter(Boolean).map((value) => value.toLowerCase())
  );
  const additions = selected.filter((address) => !existing.has(address.toLowerCase()));
  if (additions.length) {
    target.value = current ? `${current}, ${additions.join(", ")}` : additions.join(", ");
    target.dispatchEvent(new Event("input", { bubbles: true }));
  }

  state.selectedResultAddresses.clear();
  $$(".result-select").forEach((checkbox) => {
    checkbox.checked = false;
  });
  updateNmapSelectionAction();
  selectScanner("nmap");
  target.focus();
  target.scrollIntoView({ behavior: "smooth", block: "center" });
  showCopyStatus(`Added ${additions.length} address${additions.length === 1 ? "" : "es"} to nmap targets`);
});

$("#copy-all-results").addEventListener("click", async () => {
  if (!state.resultFields || !state.resultRows.length) return;
  const values = [state.resultFields, ...state.resultRows]
    .map((row) => row.join("\t"))
    .join("\n");
  const copied = await copyText(values);
  showCopyStatus(copied ? `Copied ${state.resultRows.length} results` : "Could not copy results");
});

function csvValue(value) {
  return `"${String(value).replace(/"/g, '""')}"`;
}

$("#save-results-csv").addEventListener("click", () => {
  if (!state.resultFields || !state.resultRows.length) return;
  const rows = [state.resultFields, ...state.resultRows];
  const csv = rows.map((row) => row.map(csvValue).join(",")).join("\r\n") + "\r\n";
  const blob = new Blob([`\uFEFF${csv}`], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `scanmap-${state.job?.scanner || "scan"}-${state.jobId}.csv`;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  showCopyStatus("CSV saved");
});

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
  state.resultRows = [];
  state.selectedResultAddresses.clear();
  state.offset = state.job ? state.job.next : state.offset;
  $("#console").textContent = "";
  $("#results-wrap").classList.add("hidden");
  $("#results-table thead").textContent = "";
  $("#results-table tbody").textContent = "";
  updateNmapSelectionAction();
  $("#copy-all-results").disabled = true;
  $("#save-results-csv").disabled = true;
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
  await loadAccountMenu();
  await loadTools();
  selectScanner("nmap");
  const jobs = await refreshJobs();
  const running = jobs.find((job) => job.status === "running" || job.status === "queued");
  if (running) selectJob(running.id);
})();
