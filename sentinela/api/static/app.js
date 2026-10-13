// Dashboard executivo do Sentinela — JavaScript puro, sem build.
// Todo texto vindo da API passa por esc() antes de ir para o HTML: o
// dashboard exibe trechos de código vulnerável e não pode ser ele mesmo
// vulnerável a XSS.

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", info: "Info" };
const STATUS_LABEL = {
  open: "Aberto", confirmed: "Confirmado", false_positive: "Falso positivo",
  accepted_risk: "Risco aceito", fixed: "Corrigido",
};
const AI_LABEL = { true_positive: "IA: real", false_positive: "IA: falso positivo", uncertain: "IA: incerto" };
const GATE_LABEL = { passed: "Aprovado", warned: "Com avisos", failed: "Bloqueado" };
const charts = [];
let state = { project: localStorage.getItem("sentinela.project") || "" };

const $ = (sel) => document.querySelector(sel);
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
function fmtDate(iso) { return iso ? new Date(iso).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" }) : "—"; }
function gateBadge(status) {
  const cls = status || "pending";
  return `<span class="gate ${cls}">${esc(GATE_LABEL[status] || "Em andamento")}</span>`;
}
function sevBadge(sev) { return `<span class="sev ${esc(sev)}">${esc(SEV_LABEL[sev] || sev)}</span>`; }
function aiBadge(ai) { return ai ? `<span class="ai ${esc(ai.verdict)}" title="${esc(ai.rationale)}">${esc(AI_LABEL[ai.verdict] || ai.verdict)}</span>` : ""; }

async function api(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let detail = response.statusText;
    try { detail = (await response.json()).detail || detail; } catch { /* corpo não-JSON */ }
    throw new Error(detail);
  }
  return response.json();
}

function destroyCharts() { while (charts.length) charts.pop().destroy(); }

// ---------------------------------------------------------------- roteador
async function route() {
  destroyCharts();
  const hash = location.hash || "#/";
  document.querySelectorAll(".topbar nav a").forEach((a) => a.classList.toggle("active", a.getAttribute("href") === hash));
  const view = $("#view");
  try {
    if (hash.startsWith("#/scan/")) return await renderScan(view, decodeURIComponent(hash.slice(7)));
    if (hash === "#/scans") return await renderScans(view);
    if (hash === "#/regras") return await renderRules(view);
    return await renderOverview(view);
  } catch (error) {
    view.innerHTML = `<div class="card empty"><p class="error">Não foi possível carregar: ${esc(error.message)}</p></div>`;
  }
}

async function loadProjects() {
  const projects = await api("/api/projects");
  const select = $("#project");
  if (!projects.length) {
    select.innerHTML = `<option value="">Nenhum projeto</option>`;
    state.project = "";
    return;
  }
  if (!projects.some((p) => p.name === state.project)) state.project = projects[0].name;
  select.innerHTML = projects.map((p) => `<option ${p.name === state.project ? "selected" : ""}>${esc(p.name)}</option>`).join("");
}

// --------------------------------------------------------------- visão geral
async function renderOverview(view) {
  if (!state.project) {
    view.innerHTML = `<div class="card empty">
      <h1>Nenhum scan ainda</h1>
      <p>Clique em <b>Novo scan</b> para enviar um .zip, ou rode no seu repositório:</p>
      <p><code>sentinela scan . --api ${esc(location.origin)} --project minha-api</code></p></div>`;
    return;
  }
  const m = await api(`/api/projects/${encodeURIComponent(state.project)}/metrics`);
  const latest = m.latest_scan;
  view.innerHTML = `
    <h1>${esc(m.project)}</h1>
    <p class="subtitle">Último scan: ${latest ? `${fmtDate(latest.created_at)} · commit <code>${esc((latest.commit_sha || "—").slice(0, 7))}</code> · ${gateBadge(latest.gate.status)} · <a href="#/scan/${esc(latest.id)}">ver achados</a>` : "—"}</p>
    <section class="grid kpis">
      ${kpi("Abertos", m.totals.open)}
      ${kpi("Críticos", m.totals.critical, "critical")}
      ${kpi("Altos", m.totals.high, "high")}
      ${kpi("Scans", m.totals.scans)}
      ${kpi("Gates bloqueados", m.totals.gate_failed)}
      ${kpi("Revisados", m.totals.reviewed)}
    </section>
    <section class="grid charts">
      <div class="card span-4"><h2>Severidade (abertos)</h2><div class="chart-box"><canvas id="c-sev"></canvas></div></div>
      <div class="card span-8"><h2>Tendência de falhas por scan</h2><div class="chart-box"><canvas id="c-trend"></canvas></div></div>
      <div class="card span-5"><h2>Top 5 arquivos críticos</h2>${topFiles(m.top_files)}</div>
      <div class="card span-7"><h2>OWASP Top 10</h2><div class="chart-box"><canvas id="c-owasp"></canvas></div></div>
      <div class="card span-4"><h2>Triagem por IA (último scan)</h2><div class="chart-box"><canvas id="c-ai"></canvas></div></div>
      <div class="card span-8"><h2>Fraquezas mais frequentes (CWE)</h2>${cweTable(m.cwe)}</div>
    </section>`;
  drawOverviewCharts(m);
}

function kpi(label, value, cls = "") {
  return `<div class="card kpi ${cls}"><div class="value">${esc(value)}</div><div class="label">${esc(label)}</div></div>`;
}

function topFiles(files) {
  if (!files.length) return `<p class="muted">Nenhum arquivo com achados abertos. 🎉</p>`;
  const max = Math.max(...files.map((f) => f.total));
  return `<ul class="bar-list">${files.map((f) => `
    <li><div class="row"><code>${esc(f.file)}</code><span>${f.critical_high ? `<b style="color:var(--critical)">${esc(f.critical_high)} crít./alto</b> · ` : ""}${esc(f.total)} falha(s)</span></div>
    <div class="bar"><span style="width:${(100 * f.total) / max}%"></span></div></li>`).join("")}</ul>`;
}

function cweTable(rows) {
  if (!rows.length) return `<p class="muted">Sem dados.</p>`;
  return `<table><thead><tr><th>CWE</th><th>Ocorrências</th></tr></thead><tbody>${rows.map((r) => `
    <tr><td><a href="https://cwe.mitre.org/data/definitions/${esc(r.cwe.split("-")[1])}.html" target="_blank" rel="noopener">${esc(r.cwe)}</a></td><td>${esc(r.count)}</td></tr>`).join("")}</tbody></table>`;
}

function drawOverviewCharts(m) {
  if (!window.Chart) return;
  Chart.defaults.color = cssVar("--muted");
  Chart.defaults.borderColor = cssVar("--border");
  const colors = SEVERITIES.map((s) => cssVar(`--${s}`));

  charts.push(new Chart($("#c-sev"), {
    type: "doughnut",
    data: { labels: SEVERITIES.map((s) => SEV_LABEL[s]), datasets: [{ data: SEVERITIES.map((s) => m.severity[s]), backgroundColor: colors, borderWidth: 0 }] },
    options: { maintainAspectRatio: false, cutout: "62%", plugins: { legend: { position: "right" } } },
  }));

  charts.push(new Chart($("#c-trend"), {
    type: "line",
    data: {
      labels: m.trend.map((t) => `${new Date(t.date).toLocaleDateString("pt-BR")} ${t.commit || ""}`),
      datasets: SEVERITIES.slice(0, 4).map((s, i) => ({
        label: SEV_LABEL[s], data: m.trend.map((t) => t[s]), borderColor: colors[i],
        backgroundColor: colors[i] + "33", fill: true, tension: 0.35, pointRadius: 3,
      })),
    },
    options: { maintainAspectRatio: false, scales: { y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } }, interaction: { mode: "index", intersect: false } },
  }));

  charts.push(new Chart($("#c-owasp"), {
    type: "bar",
    data: { labels: m.owasp.map((o) => o.category.split(" - ")[1] || o.category), datasets: [{ data: m.owasp.map((o) => o.count), backgroundColor: cssVar("--accent"), maxBarThickness: 26, borderRadius: 4 }] },
    options: { indexAxis: "y", maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } } } },
  }));

  const aiKeys = ["true_positive", "false_positive", "uncertain", "sem_ia"];
  charts.push(new Chart($("#c-ai"), {
    type: "doughnut",
    data: {
      labels: ["Real", "Falso positivo", "Incerto", "Sem IA"],
      datasets: [{ data: aiKeys.map((k) => m.ai[k] || 0), backgroundColor: [cssVar("--critical"), cssVar("--ok"), cssVar("--muted"), cssVar("--border")], borderWidth: 0 }],
    },
    options: { maintainAspectRatio: false, cutout: "62%", plugins: { legend: { position: "right" } } },
  }));
}

// ------------------------------------------------------------------- scans
async function renderScans(view) {
  const scans = await api(`/api/scans?limit=50${state.project ? `&project=${encodeURIComponent(state.project)}` : ""}`);
  view.innerHTML = `<h1>Scans</h1><p class="subtitle">Cada análise enviada pela CLI, pelo pipeline ou por upload.</p>
    <div class="card table-wrap"><table><thead><tr><th>Data</th><th>Projeto</th><th>Origem</th><th>Commit / PR</th><th>Arquivos</th><th>Achados</th><th>Gate</th><th>Status</th></tr></thead>
    <tbody>${scans.map((s) => `<tr class="clickable" data-href="#/scan/${esc(s.id)}">
      <td>${fmtDate(s.created_at)}</td><td>${esc(s.project)}</td><td>${esc(s.trigger)}</td>
      <td><code>${esc((s.commit_sha || "—").slice(0, 7))}</code>${s.pr_number ? ` · PR #${esc(s.pr_number)}` : ""}</td>
      <td>${esc(s.files_scanned)}</td>
      <td>${SEVERITIES.filter((x) => s.counts[x]).map((x) => `${sevBadge(x)} ${esc(s.counts[x])}`).join(" ") || "0"}</td>
      <td>${gateBadge(s.gate.status)}</td><td>${esc(s.status)}</td></tr>`).join("") || `<tr><td colspan="8" class="muted">Nenhum scan.</td></tr>`}</tbody></table></div>`;
  view.querySelectorAll("tr[data-href]").forEach((tr) => tr.addEventListener("click", () => { location.hash = tr.dataset.href; }));
}

async function renderScan(view, id) {
  const scan = await api(`/api/scans/${encodeURIComponent(id)}`);
  if (!["completed", "failed"].includes(scan.status)) {
    view.innerHTML = `<div class="card empty"><h1>Analisando…</h1><p>Status: <b>${esc(scan.status)}</b>. A página atualiza sozinha.</p></div>`;
    setTimeout(() => { if (location.hash === `#/scan/${id}`) route(); }, 2500);
    return;
  }
  const findings = await api(`/api/scans/${encodeURIComponent(id)}/findings`);
  view.innerHTML = `
    <h1>Scan ${esc(scan.id.slice(0, 8))} ${gateBadge(scan.gate.status)}</h1>
    <p class="subtitle">${esc(scan.project)} · ${fmtDate(scan.created_at)} · ${esc(scan.files_scanned)} arquivo(s) · ${esc(Object.entries(scan.languages).map(([k, v]) => `${k}: ${v}`).join(", "))} · ${esc(scan.duration_ms)} ms
      · <a href="/api/scans/${esc(scan.id)}/sarif" download="sentinela-${esc(scan.id.slice(0, 8))}.sarif">SARIF</a>
      · <a href="/api/scans/${esc(scan.id)}/report.md" target="_blank" rel="noopener">Relatório Markdown</a></p>
    ${scan.error ? `<p class="error">${esc(scan.error)}</p>` : ""}
    <div class="card" style="margin-bottom:16px"><h2>Security Gate</h2>${gateReasons(scan.gate.reasons || [])}</div>
    <div class="card">
      <div class="filters">
        <select id="f-sev"><option value="">Todas as severidades</option>${SEVERITIES.map((s) => `<option value="${s}">${SEV_LABEL[s]}</option>`).join("")}</select>
        <select id="f-status"><option value="">Todos os status</option>${Object.entries(STATUS_LABEL).map(([k, v]) => `<option value="${k}">${v}</option>`).join("")}</select>
        <select id="f-ai"><option value="">Qualquer veredito da IA</option>${Object.entries(AI_LABEL).map(([k, v]) => `<option value="${k}">${v}</option>`).join("")}</select>
        <span class="muted" id="f-count"></span>
      </div>
      <div class="table-wrap"><table><thead><tr><th>Severidade</th><th>Vulnerabilidade</th><th>Local</th><th>Evidência</th><th>Status</th></tr></thead><tbody id="rows"></tbody></table></div>
    </div>`;
  const draw = () => {
    const sev = $("#f-sev").value, st = $("#f-status").value, ai = $("#f-ai").value;
    const visible = findings.filter((f) => (!sev || f.severity === sev) && (!st || f.status === st) && (!ai || (f.ai && f.ai.verdict === ai)));
    $("#f-count").textContent = `${visible.length} de ${findings.length} achado(s)`;
    $("#rows").innerHTML = visible.map(findingRow).join("") || `<tr><td colspan="5" class="muted">Nenhum achado com esses filtros.</td></tr>`;
    $("#rows").querySelectorAll("tr.clickable").forEach((tr) => tr.addEventListener("click", () => toggleDetail(tr, findings.find((f) => f.id === tr.dataset.id))));
  };
  ["#f-sev", "#f-status", "#f-ai"].forEach((sel) => $(sel).addEventListener("change", draw));
  draw();
}

function gateReasons(reasons) {
  const items = (list) => list.map((r) => `<li>${esc(r)}</li>`).join("");
  if (reasons.length <= 6) return `<ul>${items(reasons)}</ul>`;
  return `<ul>${items(reasons.slice(0, 6))}</ul><details><summary class="muted">mais ${reasons.length - 6} motivo(s)</summary><ul>${items(reasons.slice(6))}</ul></details>`;
}

function findingRow(f) {
  return `<tr class="clickable" data-id="${esc(f.id)}">
    <td>${sevBadge(f.severity)}</td>
    <td><b>${esc(f.title)}</b><br><span class="tag">${esc(f.cwe)}</span><span class="tag">${esc(f.language)}</span>${aiBadge(f.ai)}</td>
    <td><code>${esc(f.file_path)}:${esc(f.line)}</code></td>
    <td>${f.engines.map((e) => `<span class="tag">${esc(e)}</span>`).join("")}<br><span class="muted">confiança ${esc(f.confidence)}</span></td>
    <td>${esc(STATUS_LABEL[f.status] || f.status)}</td></tr>`;
}

function toggleDetail(tr, f) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains("detail-row")) { next.remove(); return; }
  const row = document.createElement("tr");
  row.className = "detail-row";
  row.innerHTML = `<td colspan="5">${findingDetail(f)}</td>`;
  tr.after(row);
  row.querySelectorAll("button[data-status]").forEach((btn) => btn.addEventListener("click", () => review(f, btn.dataset.status, row)));
}

function findingDetail(f) {
  const path = f.taint_path.length ? `<h3>Caminho do dado (taint)</h3><ol class="path-steps">${f.taint_path.map((s) => `
    <li class="${esc(s.kind)}"><span class="muted">linha ${esc(s.line)} · ${esc(s.kind)}</span><br><code>${esc(s.code)}</code></li>`).join("")}</ol>` : "";
  const ai = f.ai ? `<h3>Análise da IA (${esc(f.ai.model)})</h3>
      <p>${aiBadge(f.ai)} confiança ${esc(f.ai.confidence)}${f.ai.suggested_severity ? ` · severidade sugerida: ${sevBadge(f.ai.suggested_severity)}` : ""}</p>
      <p>${esc(f.ai.rationale)}</p>
      ${f.ai.fix_explanation ? `<p><b>Correção sugerida:</b> ${esc(f.ai.fix_explanation)}</p>` : ""}
      ${f.ai.fix_code ? `<pre>${esc(f.ai.fix_code)}</pre>` : ""}` : `<h3>Análise da IA</h3><p class="muted">Não disponível (Ollama desligado ou sem resposta).</p>`;
  return `<div class="detail">
    <p>${esc(f.message)}</p>
    <h3>Código</h3><pre>${esc(f.snippet)}</pre>
    ${path}
    ${ai}
    <h3>Como corrigir</h3><p>${esc(f.remediation)}</p>${f.safe_example ? `<pre>${esc(f.safe_example)}</pre>` : ""}
    <p class="muted">Regra <code>${esc(f.rule_id)}</code> · ${esc(f.owasp)} · ${f.references.map((r) => `<a href="${esc(r)}" target="_blank" rel="noopener">referência</a>`).join(" ")}</p>
    <h3>Revisão</h3>
    <div class="review">${Object.entries(STATUS_LABEL).map(([k, v]) => `<button type="button" class="btn small" data-status="${k}" ${k === f.status ? "disabled" : ""}>${v}</button>`).join("")}
      <input type="text" class="note" placeholder="Justificativa (opcional)" size="36" value="${esc(f.review_note || "")}"></div>
  </div>`;
}

async function review(f, status, row) {
  const note = row.querySelector(".note").value;
  try {
    const updated = await api(`/api/findings/${encodeURIComponent(f.id)}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, note, actor: "dashboard" }),
    });
    Object.assign(f, updated);
    const tr = row.previousElementSibling;
    tr.outerHTML = findingRow(f);
    row.remove();
    route();
  } catch (error) {
    alert(`Não foi possível salvar: ${error.message}`);
  }
}

// ------------------------------------------------------------------ regras
async function renderRules(view) {
  const rules = await api("/api/rules");
  view.innerHTML = `<h1>Catálogo de regras</h1><p class="subtitle">${rules.length} regras em Python, JavaScript e Java — padrões, taint analysis e segredos.</p>
    <div class="card table-wrap"><table><thead><tr><th>Severidade</th><th>Regra</th><th>Linguagem</th><th>Tipo</th><th>CWE</th><th>OWASP</th></tr></thead>
    <tbody>${rules.map((r) => `<tr><td>${sevBadge(r.severity)}</td><td><b>${esc(r.title)}</b><br><code class="muted">${esc(r.id)}</code></td>
      <td>${esc(r.language)}</td><td>${esc(r.kind)}</td><td>${esc(r.cwe)}</td><td>${esc(r.owasp)}</td></tr>`).join("")}</tbody></table></div>`;
}

// --------------------------------------------------------------- novo scan
function setupScanDialog() {
  const dialog = $("#scan-dialog");
  $("#new-scan").addEventListener("click", () => {
    dialog.querySelector("[name=project]").value = state.project || "";
    $("#scan-error").hidden = true;
    dialog.showModal();
  });
  $("#scan-cancel").addEventListener("click", () => dialog.close());
  $("#scan-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    const button = $("#scan-submit");
    button.disabled = true;
    button.textContent = "Enviando…";
    try {
      const scan = await api("/api/scans/upload", { method: "POST", body: form });
      state.project = scan.project;
      localStorage.setItem("sentinela.project", state.project);
      dialog.close();
      await loadProjects();
      location.hash = `#/scan/${scan.id}`;
    } catch (error) {
      $("#scan-error").textContent = error.message;
      $("#scan-error").hidden = false;
    } finally {
      button.disabled = false;
      button.textContent = "Analisar";
    }
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  setupScanDialog();
  $("#project").addEventListener("change", (e) => {
    state.project = e.target.value;
    localStorage.setItem("sentinela.project", state.project);
    route();
  });
  window.addEventListener("hashchange", route);
  try { await loadProjects(); } catch { /* API fora do ar: a rota mostra o erro */ }
  route();
});
