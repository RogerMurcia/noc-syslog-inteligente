/*
 * NOC Syslog Inteligente - interfaz web (una sola página con pestañas).
 *
 * SEGURIDAD: todo texto que viene de la base de datos (en especial de los logs)
 * se inserta con textContent, NUNCA con innerHTML. Si un log trae
 * "<script>...</script>" se muestra como texto y no se ejecuta (prevención de XSS).
 */
const SEV = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"];
const $ = (sel) => document.querySelector(sel);
let devices = [];

// ---------------------------------------------------------------- utilidades
function el(tag, text = "", cls = "") {
  const n = document.createElement(tag);
  if (text !== null && text !== undefined) n.textContent = String(text);
  if (cls) n.className = cls;
  return n;
}
function row(cells, onClick) {
  const tr = document.createElement("tr");
  for (const c of cells) {
    const td = document.createElement("td");
    if (c instanceof Node) td.appendChild(c); else td.textContent = c ?? "—";
    tr.appendChild(td);
  }
  if (onClick) { tr.className = "clickable"; tr.onclick = onClick; }
  return tr;
}
function fill(tbody, rows, cols) {
  const t = $(tbody);
  t.replaceChildren(...rows);
  if (!rows.length) { const tr = row(["Sin datos"]); tr.firstChild.colSpan = cols; tr.firstChild.className = "muted"; t.appendChild(tr); }
}
const sevBadge = (s) => el("span", `${s} ${SEV[s]}`, `sev sev-${s}`);
const stBadge = (s) => el("span", s, `st st-${s}`);
function fmt(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString("es-CO", { dateStyle: "short", timeStyle: "medium" });
}
function flagsCell(flags, simulated) {
  const span = el("span");
  if (simulated) span.appendChild(el("span", "SIM", "tag sim"));
  for (const f of (flags || "").split(",").filter(Boolean)) {
    span.append(" ", el("span", f, f.includes("autorizada") || f.includes("injection") ? "tag bad" : "tag info"));
  }
  return span;
}
function toast(msg, err = false) {
  const t = $("#toast");
  t.textContent = msg; t.className = `toast show${err ? " err" : ""}`;
  clearTimeout(toast.t); toast.t = setTimeout(() => (t.className = "toast"), 4000);
}
function operador() { return $("#operador").value.trim(); }
async function api(url, method = "GET", data) {
  const opts = { method };
  if (data instanceof FormData) { data.append("operador", operador()); opts.body = data; }
  else if (data) { opts.headers = { "Content-Type": "application/json" }; opts.body = JSON.stringify({ ...data, operador: operador() }); }
  const res = await fetch(url, opts);
  let body = null;
  try { body = await res.json(); } catch (_) { /* sin JSON */ }
  if (!res.ok && !(body && "allowed" in body)) {
    throw new Error(((body && (body.errors || [body.error])) || [`Error HTTP ${res.status}`]).join("\n"));
  }
  return body;
}
const safe = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };

// Operador recordado en este navegador (preferencia local, opcional)
try { const saved = localStorage.getItem("noc_operador"); if (saved) $("#operador").value = saved; } catch (_) {}
$("#operador").addEventListener("change", () => { try { localStorage.setItem("noc_operador", operador()); } catch (_) {} });

// ---------------------------------------------------------------- pestañas
const loaders = {};
document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll("section.view").forEach((s) => s.classList.toggle("active", s.id === `view-${b.dataset.view}`));
  (loaders[b.dataset.view] || (() => {}))();
}));

// Listas desplegables de severidad y de equipos
document.querySelectorAll(".sel-sev").forEach((s) => SEV.forEach((n, i) => s.appendChild(new Option(`${i} ${n}`, i))));
$("#frm-config [name=severity]").value = 6;
async function loadDevices() {
  devices = await api("/api/devices");
  document.querySelectorAll(".sel-device").forEach((s) => {
    const keep = s.value;
    [...s.options].forEach((o) => { if (o.value) o.remove(); });
    devices.forEach((d) => s.appendChild(new Option(`${d.name} (${d.ip})`, d.id)));
    s.value = keep;
  });
}

// ---------------------------------------------------------------- dashboard
loaders.dashboard = safe(async () => {
  const d = await api("/api/dashboard");
  $("#k-devices").textContent = d.devices.length;
  $("#k-events").textContent = d.events_24h;
  $("#k-critical").textContent = d.critical_24h;
  $("#k-incidents").textContent = d.incidents_open;
  fill("#dash-devices", d.devices.map((x) => row([
    x.is_simulated ? `${x.name} (SIM)` : x.name, x.ip, x.vendor, stBadge(x.status), x.eventos_24h, fmt(x.ultimo_evento)])), 6);
  const max = Math.max(1, ...d.by_severity);
  $("#dash-sev").replaceChildren(...d.by_severity.map((n, i) => {
    const r = el("div", "", "bar-row"), track = el("div", "", "bar-track"), fillDiv = el("div", "", `bar-fill bg-${i}`);
    fillDiv.style.width = `${(n / max) * 100}%`; track.appendChild(fillDiv);
    r.append(el("span", `${i} ${SEV[i]}`, "muted"), track, el("span", n));
    return r;
  }));
  fill("#dash-critical", d.critical_events.map((e) => row([fmt(e.received_at), sevBadge(e.severity), e.device_name || e.source_ip, e.message])), 4);
  fill("#dash-incidents", d.open_incidents.map((i) => row([i.id, sevBadge(i.severity), i.title, stBadge(i.status), i.assigned_to], () => openIncident(i.id))), 5);
  fill("#dash-recent", d.recent_events.map((e) => row([fmt(e.received_at), sevBadge(e.severity), e.device_name || e.source_ip, e.vendor, e.message,
    flagsCell(e.flags, false)])), 6);
});
$("#dash-refresh").onclick = loaders.dashboard;
setInterval(() => { if ($("#view-dashboard").classList.contains("active")) loaders.dashboard(); }, 15000);

// ---------------------------------------------------------------- inventario
let editingId = null;
loaders.inventario = safe(async () => {
  await loadDevices();
  fill("#dev-table", devices.map((d) => {
    const actions = el("span");
    const edit = el("button", "Editar", "btn sm"); edit.onclick = () => openDevice(d);
    const del = el("button", "Eliminar", "btn sm danger"); del.onclick = safe(async () => {
      if (!confirm(`¿Eliminar ${d.name}? Sus eventos se conservan.`)) return;
      await api(`/api/devices/${d.id}?operador=${encodeURIComponent(operador())}`, "DELETE");
      toast("Equipo eliminado"); loaders.inventario();
    });
    actions.append(edit, " ", del);
    const name = el("span", d.name); if (d.is_simulated) name.append(" ", el("span", "SIM", "tag sim"));
    return row([name, d.ip, d.vendor, d.model, d.version, d.location, stBadge(d.status),
      el("span", d.authorized ? "sí" : "no", d.authorized ? "tag ok" : "tag bad"), fmt(d.updated_at), actions]);
  }), 10);
});
function openDevice(d) {
  editingId = d ? d.id : null;
  const f = $("#frm-device"); f.reset();
  $("#dev-title").textContent = d ? `Editar ${d.name}` : "Nuevo equipo";
  if (d) {
    for (const k of ["name", "ip", "vendor", "model", "version", "location", "status"]) f[k].value = d[k] ?? "";
    f.authorized.checked = !!d.authorized; f.is_simulated.checked = !!d.is_simulated;
  }
  $("#dlg-device").showModal();
}
$("#dev-new").onclick = () => openDevice(null);
$("#frm-device").addEventListener("submit", safe(async (e) => {
  if (e.submitter && e.submitter.value === "cancel") return;
  e.preventDefault();
  const f = e.target, data = Object.fromEntries(new FormData(f));
  data.authorized = f.authorized.checked; data.is_simulated = f.is_simulated.checked;
  if (editingId) await api(`/api/devices/${editingId}`, "PUT", data); else await api("/api/devices", "POST", data);
  $("#dlg-device").close(); toast("Equipo guardado"); loaders.inventario();
}));

// ---------------------------------------------------------------- eventos
loaders.eventos = safe(async () => {
  await loadDevices();
  const params = new URLSearchParams([...new FormData($("#frm-filter"))].filter(([, v]) => v !== ""));
  const evs = await api(`/api/events?${params}`);
  fill("#ev-table", evs.map((e) => row([e.id, fmt(e.received_at), e.device_name || e.source_ip, e.vendor, e.facility,
    sevBadge(e.severity), e.mnemonic, `${e.message}${e.dup_count > 1 ? `  (x${e.dup_count})` : ""}`,
    flagsCell(e.flags, e.is_simulated)])), 9);
  $("#ev-count").textContent = `${evs.length} evento(s) mostrados (máx. 200).`;
});
$("#frm-filter").addEventListener("submit", (e) => { e.preventDefault(); loaders.eventos(); });
$("#frm-filter").addEventListener("reset", () => setTimeout(loaders.eventos, 0));
$("#frm-import").addEventListener("submit", safe(async (e) => {
  e.preventDefault();
  const s = await api("/api/events/import", "POST", new FormData(e.target));
  toast(`Importación: ${s.leidas} leídas, ${s.nuevas} nuevas, ${s.duplicadas} duplicadas, ${s.incidentes_nuevos} incidentes nuevos`);
  e.target.reset(); loaders.eventos();
}));

// ---------------------------------------------------------------- incidentes
let currentInc = null;
loaders.incidentes = safe(async () => {
  await loadDevices();
  const list = await api(`/api/incidents?estado=${$("#inc-filter").value}`);
  fill("#inc-table", list.map((i) => row([i.id, sevBadge(i.severity), i.title, i.device_name, stBadge(i.status),
    i.assigned_to, i.event_count, fmt(i.created_at)], () => openIncident(i.id))), 8);
});
$("#inc-filter").onchange = loaders.incidentes;
$("#inc-new").onclick = () => { $("#frm-new-inc").reset(); $("#dlg-new-inc").showModal(); };
$("#frm-new-inc").addEventListener("submit", safe(async (e) => {
  if (e.submitter && e.submitter.value === "cancel") return;
  e.preventDefault();
  await api("/api/incidents", "POST", Object.fromEntries(new FormData(e.target)));
  $("#dlg-new-inc").close(); toast("Incidente creado"); loaders.incidentes();
}));

const openIncident = safe(async (id) => {
  currentInc = id;
  const { incident: i, notes, actions, event } = await api(`/api/incidents/${id}`);
  $("#inc-title").textContent = `#${i.id} ${i.title}`;
  const meta = $("#inc-meta"); meta.replaceChildren(sevBadge(i.severity), " ", stBadge(i.status),
    ` Equipo: ${i.device_name || "—"} · Responsable: ${i.assigned_to || "sin asignar"} · Eventos: ${i.event_count} · Creado por ${i.created_by}`);
  if (i.is_simulated) meta.append(" ", el("span", "SIM", "tag sim"));
  if (i.resolution) meta.append(el("div", `Resolución: ${i.resolution}`, "muted"));
  const ev = $("#inc-event");
  ev.hidden = !event;
  if (event) ev.textContent = `Evento origen #${event.id} (dato NO confiable, solo lectura):\n${event.raw}`;
  $("#inc-notes").replaceChildren(...notes.map((n) => el("li", `${fmt(n.created_at)} · ${n.author}: ${n.note}`)));
  const box = $("#inc-actions"); box.replaceChildren();
  for (const a of actions) {
    const card = el("div", "", "card"); card.style.padding = "10px"; card.style.margin = "8px 0";
    card.append(el("code", a.command), " ", stBadge(a.status),
      el("div", `Propuesta por ${a.proposed_by}${a.justification ? " · " + a.justification : ""}`, "muted small"));
    if (a.reviewed_by) card.append(el("div", `Revisada por ${a.reviewed_by}`, "muted small"));
    if (a.result) card.append(el("div", a.result, "small"));
    const btns = el("div");
    const mk = (label, url, payload) => { const b = el("button", label, "btn sm"); b.onclick = safe(async () => {
      await api(url, "POST", payload); toast(`Acción ${label.toLowerCase()}`); openIncident(id); }); btns.append(b, " "); };
    if (a.status === "pendiente") { mk("Aprobar", `/api/actions/${a.id}/review`, { decision: "aprobar" }); mk("Rechazar", `/api/actions/${a.id}/review`, { decision: "rechazar" }); }
    if (a.status === "aprobada") mk("Ejecutar (simulado)", `/api/actions/${a.id}/execute`, {});
    card.append(btns); box.appendChild(card);
  }
  if (!$("#dlg-inc").open) $("#dlg-inc").showModal();
});
$("#inc-close").onclick = () => { $("#dlg-inc").close(); loaders.incidentes(); };
const incForm = (sel, path, after) => $(sel).addEventListener("submit", safe(async (e) => {
  e.preventDefault();
  await api(`/api/incidents/${currentInc}/${path}`, "POST", Object.fromEntries(new FormData(e.target)));
  e.target.reset(); toast(after); openIncident(currentInc);
}));
incForm("#frm-assign", "assign", "Incidente asignado");
incForm("#frm-status", "status", "Estado actualizado");
incForm("#frm-note", "notes", "Nota agregada");
incForm("#frm-action", "actions", "Acción propuesta: pendiente de aprobación humana");

// ---------------------------------------------------------------- configuraciones
loaders.configuraciones = safe(loadDevices);
$("#frm-config").addEventListener("submit", safe(async (e) => {
  e.preventDefault();
  const p = new URLSearchParams(new FormData(e.target)); p.append("operador", operador());
  $("#cfg-out").textContent = (await api(`/api/config?${p}`)).config;
}));
$("#frm-config [name=device_id]").onchange = (e) => {
  const d = devices.find((x) => String(x.id) === e.target.value);
  if (d && d.vendor !== "Otro") $("#frm-config [name=vendor]").value = d.vendor;
};
$("#cfg-copy").onclick = () => navigator.clipboard.writeText($("#cfg-out").textContent).then(() => toast("Copiado"));

// ---------------------------------------------------------------- consola
function termLine(text, cls = "") { const t = $("#terminal"); t.appendChild(el("div", text, cls)); t.scrollTop = t.scrollHeight; }
const loadAllowed = safe(async () => {
  const d = devices.find((x) => String(x.id) === $("#con-device").value);
  const list = (await api(`/api/console?vendor=${d ? d.vendor : "Cisco"}`)).allowed;
  $("#allow-list").replaceChildren(...list.map((c) => {
    const li = el("li"), code = el("code", c.command); code.onclick = () => { $("#cmd").value = c.command; $("#cmd").focus(); };
    li.append(code, el("div", c.description, "muted small")); return li;
  }));
  if (!list.length) $("#allow-list").appendChild(el("li", "Sin comandos permitidos para esta marca", "muted"));
});
loaders.consola = safe(async () => {
  await loadDevices();
  const s = $("#con-device"); if (!s.value && devices.length) s.value = devices[0].id;
  if (!$("#terminal").childElementCount) termLine("[CONSOLA SIMULADA] Seleccione un equipo y escriba un comando de solo lectura.", "t-info");
  loadAllowed();
});
$("#con-device").onchange = loadAllowed;
$("#frm-cmd").addEventListener("submit", safe(async (e) => {
  e.preventDefault();
  const command = $("#cmd").value; if (!command.trim()) return;
  const d = devices.find((x) => String(x.id) === $("#con-device").value);
  const actor = $("#con-actor").value;
  termLine(`${actor === "asistente_ia" ? "[IA] " : ""}${d ? d.name : "?"}# ${command}`, "t-cmd");
  const r = await api("/api/console", "POST", { device_id: $("#con-device").value, command, actor });
  if (r.allowed) termLine(r.output); else termLine(`BLOQUEADO: ${r.reason}`, "t-block");
  $("#cmd").value = "";
}));

// ---------------------------------------------------------------- política y auditoría
loaders.politica = safe(async () => {
  const p = await api("/api/policy");
  const labels = { fuentes_autorizadas: "Fuentes autorizadas", eventos_no_autorizados: "Eventos de fuentes no autorizadas",
    posibles_prompt_injection: "Posibles prompt injection", mensajes_deduplicados: "Mensajes deduplicados",
    comandos_bloqueados: "Comandos bloqueados", acciones_pendientes: "Acciones pendientes de aprobación", bloqueos_ia: "Intentos de la IA bloqueados" };
  $("#pol-kpis").replaceChildren(...Object.entries(labels).map(([k, label]) => {
    const div = el("div", "", "kpi"); div.append(el("b", p[k]), el("span", label)); return div;
  }));
});
loaders.auditoria = safe(async () => {
  const rows = await api("/api/audit");
  fill("#aud-table", rows.map((a) => row([a.id, fmt(a.ts), a.actor, a.action, a.entity ? `${a.entity} #${a.entity_id ?? ""}` : "—",
    a.detail, el("span", a.result, a.result === "ok" ? "tag ok" : "tag bad")])), 7);
});
$("#aud-refresh").onclick = loaders.auditoria;

loadDevices().then(loaders.dashboard).catch((e) => toast(e.message, true));
