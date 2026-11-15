"""
Bot de Telegram del NOC - consulta de alertas, incidentes, análisis y mejoras.

Uso:  python bot_telegram.py        (terminal 4; se detiene con Ctrl+C)

Comandos:
    /start, /ayuda        Ayuda
    /id                   Muestra el chat_id (para autorizarlo en el .env)
    /estado               Resumen del NOC (equipos, eventos 24 h, decisiones, incidentes)
    /alertas              Últimas decisiones REVIEW y BLOCK del motor de políticas
    /eventos              Últimos 10 eventos
    /incidentes           Incidentes abiertos
    /incidente N          Detalle de un incidente + análisis + soluciones
    /analizar N           Análisis del evento N (asistente de solo lectura)
    /mejoras              Mejoras recomendadas para la red
    /politicas            Políticas P01-P06 vigentes
    /equipos              Inventario y estado
    /salud                Observabilidad: estado, salud, disponibilidad y causa raíz

Seguridad:
  * Solo responden con datos los chats listados en TELEGRAM_CHAT_IDS (lista permitida).
    Un chat no autorizado solo recibe su chat_id y el intento queda en la auditoría.
  * El bot es de SOLO LECTURA (P03): no ejecuta comandos, no aprueba acciones y no
    cambia nada en los equipos. Las aprobaciones se hacen en la web (P04).
  * El texto que escribe el usuario se trata como dato: solo se reconocen comandos fijos.
"""
from __future__ import annotations

import re
import time

import asistente_ia
import noc
import telegram_noc as tg
from security import policy_engine

esc = tg.esc
SEV = tg.SEV_NAMES
ICON = tg.DECISION_ICON
STATUS_ICON = {"activo": "🟢", "alerta": "🟠", "caido": "🔴", "mantenimiento": "🛠", "desconocido": "⚪"}


def local(ts: str | None) -> str:
    """'2026-11-12T21:05:00Z' -> '12/11 16:05' (hora Colombia)."""
    if not ts:
        return "-"
    from datetime import datetime, timedelta
    try:
        d = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ") + timedelta(hours=noc.LOCAL_UTC_OFFSET)
        return d.strftime("%d/%m %H:%M")
    except ValueError:
        return ts


HELP = (
    "🛰 <b>NOC Syslog Inteligente · Bot</b>\n"
    "La IA asesora; las políticas y el humano conservan el control.\n\n"
    "/estado – resumen del NOC\n"
    "/alertas – últimas alertas (REVIEW / BLOCK)\n"
    "/eventos – últimos eventos\n"
    "/incidentes – incidentes abiertos\n"
    "/incidente N – detalle y soluciones de un incidente\n"
    "/analizar N – análisis del evento N\n"
    "/mejoras – mejoras recomendadas para la red\n"
    "/equipos – inventario y estado\n"
    "/salud – salud de los equipos y causa raíz\n"
    "/politicas – políticas P01–P06\n"
    "/id – ver el chat_id de este chat\n\n"
    "<i>Bot de solo lectura: no ejecuta comandos ni aprueba acciones (P03/P04).</i>"
)


def cmd_estado(conn) -> str:
    q = lambda sql, *a: conn.execute(sql, a).fetchone()[0]
    since = noc.iso_ago(24 * 3600)
    dec = {r["decision"]: r["n"] for r in conn.execute(
        "SELECT decision, COUNT(*) n FROM policy_decisions WHERE created_at >= ? GROUP BY decision", (since,))}
    by_status = {r["status"]: r["n"] for r in conn.execute("SELECT status, COUNT(*) n FROM devices GROUP BY status")}
    lines = [
        "📊 <b>Estado del NOC</b> (últimas 24 h)",
        "",
        f"🖥 Equipos: {q('SELECT COUNT(*) FROM devices')}  "
        + "  ".join(f"{STATUS_ICON.get(k, '')}{v}" for k, v in sorted(by_status.items())),
        f"📨 Eventos: {q('SELECT COUNT(*) FROM events WHERE received_at >= ?', since)}  ·  "
        f"críticos (0-3): {q('SELECT COUNT(*) FROM events WHERE received_at >= ? AND severity <= 3', since)}",
        f"🛡 Decisiones: 🟢 {dec.get('ALLOW', 0)}  🟠 {dec.get('REVIEW', 0)}  🔴 {dec.get('BLOCK', 0)}",
        f"🎫 Incidentes abiertos: {q('SELECT COUNT(*) FROM incidents WHERE status != ?', 'cerrado')}",
        f"✋ Acciones pendientes de aprobación: {q('SELECT COUNT(*) FROM actions WHERE status = ?', 'pendiente')}",
    ]
    return "\n".join(lines)


def cmd_alertas(conn) -> str:
    rows = conn.execute(
        "SELECT pd.decision, pd.created_at, pd.policies, e.id, e.severity, e.message, d.name AS device "
        "FROM policy_decisions pd JOIN events e ON e.id = pd.event_id LEFT JOIN devices d ON d.id = e.device_id "
        "WHERE pd.decision != 'ALLOW' ORDER BY pd.id DESC LIMIT 10").fetchall()
    if not rows:
        return "✅ Sin alertas REVIEW/BLOCK registradas."
    out = ["🚨 <b>Últimas alertas</b>", ""]
    for r in rows:
        msg = "contenido bloqueado (no se muestra)" if r["decision"] == "BLOCK" else r["message"][:80]
        out.append(f"{ICON[r['decision']]} <b>#{r['id']}</b> {local(r['created_at'])} · "
                   f"{esc(r['device'] or '-')} · sev {r['severity']}\n   {esc(msg)}")
    out += ["", "<i>Use /analizar N para ver causas y soluciones.</i>"]
    return "\n".join(out)


def cmd_eventos(conn) -> str:
    rows = conn.execute(
        "SELECT e.id, e.received_at, e.severity, e.message, d.name AS device, pd.decision "
        "FROM events e LEFT JOIN devices d ON d.id = e.device_id "
        "LEFT JOIN policy_decisions pd ON pd.event_id = e.id ORDER BY e.id DESC LIMIT 10").fetchall()
    if not rows:
        return "Sin eventos todavía."
    out = ["📨 <b>Últimos eventos</b>", ""]
    for r in rows:
        msg = "contenido bloqueado" if r["decision"] == "BLOCK" else r["message"][:70]
        out.append(f"{ICON.get(r['decision'], '⚪')} #{r['id']} {local(r['received_at'])} "
                   f"sev{r['severity']} {esc(r['device'] or '-')}: {esc(msg)}")
    return "\n".join(out)


def cmd_incidentes(conn) -> str:
    rows = conn.execute(
        "SELECT i.id, i.title, i.severity, i.status, i.assigned_to, i.event_count FROM incidents i "
        "WHERE i.status != 'cerrado' ORDER BY i.severity, i.id DESC LIMIT 15").fetchall()
    if not rows:
        return "✅ No hay incidentes abiertos."
    out = ["🎫 <b>Incidentes abiertos</b>", ""]
    for r in rows:
        out.append(f"• <b>#{r['id']}</b> [sev {r['severity']}] {esc(r['title'])}\n"
                   f"   {esc(r['status'])} · {esc(r['assigned_to'] or 'sin asignar')} · {r['event_count']} evento(s)")
    out += ["", "<i>/incidente N para ver detalle y soluciones.</i>"]
    return "\n".join(out)


def cmd_analizar(conn, arg: str) -> str:
    if not arg.isdigit():
        return "Uso: /analizar N  (N = número de evento, ver /eventos)"
    ev, decision, a = asistente_ia.analysis_for_event(conn, int(arg))
    if ev is None:
        return f"No existe el evento #{esc(arg)}."
    return tg.format_alert(ev, decision, a)


def cmd_incidente(conn, arg: str) -> str:
    if not arg.isdigit():
        return "Uso: /incidente N  (ver /incidentes)"
    i = conn.execute("SELECT i.*, d.name AS device FROM incidents i LEFT JOIN devices d ON d.id = i.device_id "
                     "WHERE i.id = ?", (int(arg),)).fetchone()
    if i is None:
        return f"No existe el incidente #{esc(arg)}."
    out = [f"🎫 <b>Incidente #{i['id']}</b> · sev {i['severity']} {SEV[i['severity']]}",
           f"<b>{esc(i['title'])}</b>",
           f"Estado: {esc(i['status'])} · Responsable: {esc(i['assigned_to'] or 'sin asignar')}",
           f"Equipo: {esc(i['device'] or '-')} · Eventos: {i['event_count']} · Creado: {local(i['created_at'])}"]
    if i["resolution"]:
        out.append(f"Resolución: {esc(i['resolution'])}")
    notes = conn.execute("SELECT author, note, created_at FROM incident_notes WHERE incident_id = ? "
                         "ORDER BY id DESC LIMIT 4", (i["id"],)).fetchall()
    if notes:
        out += ["", "<b>Bitácora:</b>"] + [f"• {local(n['created_at'])} {esc(n['author'])}: {esc(n['note'][:120])}"
                                           for n in notes]
    actions = conn.execute("SELECT id, command, status, proposed_by FROM actions WHERE incident_id = ? "
                           "ORDER BY id", (i["id"],)).fetchall()
    if actions:
        out += ["", "<b>Acciones:</b>"] + [f"• #{a['id']} <code>{esc(a['command'])}</code> — {esc(a['status'])} "
                                           f"(propuso {esc(a['proposed_by'])})" for a in actions]
    if i["event_id"]:
        ev, decision, a = asistente_ia.analysis_for_event(conn, i["event_id"])
        if a:
            out += ["", f"🛡 Decisión del evento #{ev['id']}: {ICON.get(decision['decision'], '')} "
                        f"{decision['decision']}"]
            if a.get("que_paso"):
                out += [f"<b>¿Qué pasó?</b> {esc(a['que_paso'])}"]
            if a.get("causas"):
                out += ["", "<b>Posibles causas:</b>"] + [f"• {esc(c)}" for c in a["causas"][:4]]
            if a.get("soluciones"):
                out += ["", "<b>🔧 Posibles soluciones:</b>"] + [f"{n}. {esc(s)}" for n, s in
                                                                 enumerate(a["soluciones"][:6], 1)]
            if a.get("verificacion"):
                out += ["", "<b>🔍 Verificar:</b> " + ", ".join(f"<code>{esc(c)}</code>" for c in a["verificacion"])]
    out += ["", "<i>Asignar, aprobar acciones o cerrar: desde la web del NOC (aprobación humana).</i>"]
    return "\n".join(out)


def cmd_mejoras(conn) -> str:
    items = asistente_ia.improvements(conn)
    icon = {"ALTA": "🔴", "MEDIA": "🟠", "BAJA": "🟢"}
    out = ["💡 <b>Mejoras recomendadas</b>", ""]
    for n, m in enumerate(items, 1):
        out.append(f"{icon[m['prioridad']]} <b>{n}. {esc(m['titulo'])}</b> ({m['prioridad']})\n"
                   f"   {esc(m['detalle'])}\n   ➜ {esc(m['accion'])}")
    return "\n".join(out)


def cmd_politicas(_conn) -> str:
    out = ["🛡 <b>Políticas activas (antes de la IA)</b>", ""]
    for p in policy_engine.POLICIES:
        out.append(f"<b>{p['id']} · {esc(p['name'])}</b>\n   {esc(p['action'])}")
    out += ["", "🟢 ALLOW: análisis de solo lectura · 🟠 REVIEW: pausa para un humano · "
                "🔴 BLOCK: la IA no se invoca"]
    return "\n".join(out)


def cmd_equipos(conn) -> str:
    rows = conn.execute("SELECT name, ip, vendor, status, authorized FROM devices ORDER BY name").fetchall()
    out = ["🖥 <b>Inventario</b>", ""]
    for r in rows:
        out.append(f"{STATUS_ICON.get(r['status'], '⚪')} {esc(r['name'])} · {esc(r['ip'])} · {esc(r['vendor'])}"
                   + ("" if r["authorized"] else " · ⛔ no autorizado"))
    return "\n".join(out)


def cmd_salud(conn) -> str:
    import observabilidad
    topo = observabilidad.topology(conn)
    icon = {"operativo": "🟢", "degradado": "🟡", "caido": "🔴", "afectado": "🟠", "mantenimiento": "🔧",
            "desconocido": "⚪"}
    s = topo["summary"]
    out = ["🩺 <b>Salud de la red</b>",
           f"🟢 {s['operativo']} · 🟡 {s['degradado']} · 🔴 {s['caido']} · 🟠 {s['afectado']}"
           + (f" · disponibilidad media {s['availability_avg']} %" if s["availability_avg"] is not None else ""), ""]
    for n in sorted(topo["nodes"], key=lambda n: (n["health"] is None, n["health"] if n["health"] is not None else 0)):
        line = f"{icon[n['state']]} <b>{esc(n['name'])}</b> · {esc(n['state_name'])}"
        if n["health"] is not None:
            line += f" · salud {n['health']}"
        if n["root_cause"]:
            line += f" · causa raíz: {esc(', '.join(n['root_cause']))}"
        out.append(line)
    if s["root_causes"]:
        out += ["", f"⚠️ Revisar primero: <b>{esc(', '.join(s['root_causes']))}</b>"]
    return "\n".join(out)


COMMANDS = {"/salud": cmd_salud, "/estado": cmd_estado, "/alertas": cmd_alertas, "/eventos": cmd_eventos,
            "/incidentes": cmd_incidentes, "/mejoras": cmd_mejoras, "/politicas": cmd_politicas,
            "/equipos": cmd_equipos}
COMMANDS_ARG = {"/analizar": cmd_analizar, "/incidente": cmd_incidente}
RE_CMD = re.compile(r"^(/[a-z_]+)(?:@\w+)?(?:\s+(\S+))?", re.I)


def handle(conn, text: str, chat_id: str, authorized: bool) -> str:
    """Responde a UN mensaje. Función pura (sin red) para poder probarla."""
    m = RE_CMD.match((text or "").strip())
    cmd = m.group(1).lower() if m else ""
    arg = (m.group(2) or "") if m else ""
    if cmd == "/id":
        return f"🆔 El chat_id de este chat es <code>{esc(chat_id)}</code>"
    if not authorized:
        noc.audit(conn, f"telegram:{chat_id}"[:32], "telegram.no_autorizado", detail=f"cmd={cmd or '-'}",
                  result="bloqueado")
        return (f"⛔ Este chat no está autorizado.\nSu chat_id es <code>{esc(chat_id)}</code>: "
                "agréguelo a TELEGRAM_CHAT_IDS en el archivo .env del NOC y reinicie el bot.")
    if cmd in ("/start", "/ayuda", "/help"):
        return HELP
    if cmd in COMMANDS:
        return COMMANDS[cmd](conn)
    if cmd in COMMANDS_ARG:
        return COMMANDS_ARG[cmd](conn, arg)
    if cmd in ("/aprobar", "/ejecutar", "/rechazar", "/cerrar"):
        return ("✋ Por política P03/P04 el bot no aprueba ni ejecuta acciones.\n"
                "Hágalo en la web del NOC: <code>http://127.0.0.1:5000</code> (pestaña Incidentes).")
    return "No reconozco ese comando.\n\n" + HELP


def main():
    if not tg.CONFIG.token:
        print("[BOT] Falta TELEGRAM_BOT_TOKEN en el archivo .env. Vea el README (sección Telegram).")
        return
    conn = noc.connect()
    noc.init_db(conn)
    try:
        me = tg.api_call("getMe", {})["result"]
    except RuntimeError as e:
        print(f"[BOT] No se pudo conectar con Telegram: {e}")
        return
    try:      # menú de comandos visible en la app
        tg.api_call("setMyCommands", {"commands": [
            {"command": c.strip("/"), "description": d} for c, d in (
                ("/estado", "Resumen del NOC"), ("/alertas", "Últimas alertas REVIEW/BLOCK"),
                ("/eventos", "Últimos eventos"), ("/incidentes", "Incidentes abiertos"),
                ("/incidente", "Detalle de un incidente: /incidente N"),
                ("/analizar", "Análisis de un evento: /analizar N"), ("/mejoras", "Mejoras recomendadas"),
                ("/equipos", "Inventario"), ("/politicas", "Políticas P01-P06"), ("/id", "Ver chat_id"),
                ("/ayuda", "Ayuda"))]})
    except RuntimeError:
        pass
    allowed = set(tg.CONFIG.chat_ids)
    noc.audit(conn, "sistema", "telegram.bot.start", detail=f"@{me.get('username')} chats={len(allowed)}")
    print(f"[BOT] @{me.get('username')} escuchando. Chats autorizados: {', '.join(allowed) or 'ninguno'}"
          "  (Ctrl+C para detener)")
    offset = 0
    try:
        while True:
            try:
                updates = tg.api_call("getUpdates", {"offset": offset, "timeout": 25,
                                                     "allowed_updates": ["message"]}, timeout=35)["result"]
            except RuntimeError as e:
                print(f"[BOT] {e}; reintento en 5 s")
                time.sleep(5)
                continue
            for u in updates:
                offset = u["update_id"] + 1
                msg = u.get("message") or {}
                chat_id = str((msg.get("chat") or {}).get("id", ""))
                text = msg.get("text") or ""
                if not chat_id or not text:
                    continue
                try:
                    reply = handle(conn, text, chat_id, chat_id in allowed)
                except Exception as e:      # el bot nunca se cae por una consulta
                    reply = f"⚠ Error procesando la consulta ({type(e).__name__})."
                ok, detail = tg.send_text(reply, chat_id=chat_id)
                print(f"[BOT] chat {chat_id}: {text[:40]!r} -> {'ok' if ok else detail}")
    except KeyboardInterrupt:
        print("\n[BOT] Detenido.")
    finally:
        noc.audit(conn, "sistema", "telegram.bot.stop")
        conn.close()


if __name__ == "__main__":
    main()
