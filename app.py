"""
NOC Syslog Inteligente v0.2.0 (MVP) - aplicación web Flask.

Uso:  python app.py   ->  http://127.0.0.1:5000
Solo escucha en 127.0.0.1 (este PC); no queda expuesta a la red.

API REST (la página web la consume con JavaScript):
    GET/POST          /api/devices                 Inventario (listar / crear)
    PUT/DELETE        /api/devices/<id>            Editar / eliminar
    GET               /api/events                  Eventos con filtros (fecha, marca, equipo, severidad)
    POST              /api/events/import           Importar archivo de log o texto pegado
    GET               /api/dashboard               Resumen del estado de la red
    GET/POST          /api/incidents               Incidentes (listar / crear)
    GET               /api/incidents/<id>          Detalle + notas + acciones propuestas
    POST              /api/incidents/<id>/assign   Asignar responsable
    POST              /api/incidents/<id>/status   Cambiar estado (cerrar exige resolución)
    POST              /api/incidents/<id>/notes    Nota de seguimiento
    POST              /api/incidents/<id>/actions  Proponer comando (humano o asistente IA)
    POST              /api/actions/<id>/review     Aprobar / rechazar (solo humanos)
    POST              /api/actions/<id>/execute    Ejecutar (SIMULADO) una acción aprobada
    GET               /api/config                  Generar configuración Syslog
    GET/POST          /api/console                 Comandos permitidos / ejecutar (simulado)
    GET               /api/policy                  Indicadores de la política de defensa IA
    GET               /api/audit                   Registro de auditoría

SEGURIDAD: todas las consultas SQL usan parámetros "?" (sin inyección SQL),
toda entrada se valida y toda acción queda en la auditoría.
"""
import ipaddress
import re
import sqlite3

from flask import Flask, g, jsonify, render_template, request

import noc
import plantillas

VERSION = "0.2.0"
VENDORS = ("Cisco", "Fortinet", "Huawei", "Otro")
DEVICE_STATUSES = ("activo", "alerta", "caido", "mantenimiento", "desconocido")
RE_NAME = re.compile(r"^[A-Za-z0-9._-]{2,64}$")
RE_OPERATOR = re.compile(r"^[A-Za-z0-9._-]{2,32}$")
# Ciclo de vida de un incidente (máquina de estados)
TRANSITIONS = {"abierto": {"asignado", "en_progreso", "cerrado"},
               "asignado": {"en_progreso", "cerrado"},
               "en_progreso": {"cerrado"},
               "cerrado": set()}
AI_ACTOR = "asistente_ia"


def create_app(db_path=None):
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = db_path or noc.DB_PATH
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024   # archivos de máx. 2 MB

    conn = noc.connect(app.config["DATABASE_PATH"])
    noc.init_db(conn)
    conn.close()

    # ----------------------------------------------------------------- utilidades
    def db():
        if "db" not in g:
            g.db = noc.connect(app.config["DATABASE_PATH"])
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    def body() -> dict:
        return request.get_json(silent=True) or {}

    def operator(data=None) -> str:
        """Operador responsable (MVP sin login: se toma del formulario o del .env).
        Ningún humano puede hacerse pasar por 'asistente_ia' ni por 'sistema'."""
        name = str((data or {}).get("operador") or "").strip()
        if RE_OPERATOR.match(name) and name not in (AI_ACTOR, "sistema"):
            return name
        return noc.DEFAULT_OPERATOR

    def to_int(value, lo=None, hi=None):
        try:
            n = int(value)
        except (TypeError, ValueError):
            return None
        if (lo is not None and n < lo) or (hi is not None and n > hi):
            return None
        return n

    def error(msg, code=400):
        return jsonify(errors=[msg] if isinstance(msg, str) else msg), code

    def local_day_to_utc(day: str, end=False):
        """'2026-10-14' (hora Colombia) -> límite en UTC para comparar con received_at."""
        from datetime import datetime, timedelta
        try:
            d = datetime.strptime(day, "%Y-%m-%d")
        except ValueError:
            return None
        if end:
            d += timedelta(days=1, seconds=-1)
        return (d - timedelta(hours=noc.LOCAL_UTC_OFFSET)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ----------------------------------------------------------------- páginas
    @app.get("/")
    def index():
        return render_template("index.html", version=VERSION, operator=noc.DEFAULT_OPERATOR)

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", version=VERSION)

    # ----------------------------------------------------------------- inventario
    def validate_device(data, partial=False):
        clean, errors = {}, []
        has = lambda f: data.get(f) not in (None, "")
        if not partial:
            errors += [f"El campo '{f}' es obligatorio" for f in ("name", "ip", "vendor") if not has(f)]
        if has("name"):
            clean["name"] = str(data["name"]).strip()
            if not RE_NAME.match(clean["name"]):
                errors.append("Nombre inválido: 2-64 caracteres, solo letras, números, '.', '_' o '-'")
        if has("ip"):
            try:
                clean["ip"] = str(ipaddress.ip_address(str(data["ip"]).strip()))
            except ValueError:
                errors.append(f"IP inválida: {data['ip']}")
        if has("vendor"):
            if data["vendor"] not in VENDORS:
                errors.append("Marca inválida (Cisco, Fortinet, Huawei, Otro)")
            clean["vendor"] = data["vendor"]
        if has("status"):
            if data["status"] not in DEVICE_STATUSES:
                errors.append("Estado inválido")
            clean["status"] = data["status"]
        for f in ("model", "version", "location"):
            if f in data and data[f] is not None:
                clean[f] = str(data[f]).strip()[:100]
        for f in ("authorized", "is_simulated"):
            if f in data:
                clean[f] = 1 if data[f] in (True, 1, "1", "true", "on") else 0
        return clean, errors

    def get_device_row(device_id):
        return db().execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()

    @app.get("/api/devices")
    def list_devices():
        return jsonify([dict(r) for r in db().execute("SELECT * FROM devices ORDER BY name")])

    @app.post("/api/devices")
    def create_device():
        raw = body()
        data, errors = validate_device(raw)
        if errors:
            return error(errors)
        data.setdefault("status", "desconocido")
        data.setdefault("authorized", 1)
        data.setdefault("is_simulated", 1)      # en el MVP todo equipo registrado es de prueba
        data["created_at"] = data["updated_at"] = noc.now_iso()
        try:
            cur = db().execute(f"INSERT INTO devices ({', '.join(data)}) VALUES ({', '.join('?' * len(data))})",
                               tuple(data.values()))
            db().commit()
        except sqlite3.IntegrityError:
            return error("Ya existe un equipo con ese nombre o esa IP", 409)
        noc.audit(db(), operator(raw), "device.create", "devices", cur.lastrowid,
                  f"{data['name']} {data['ip']} {data['vendor']}")
        return jsonify(dict(get_device_row(cur.lastrowid))), 201

    @app.put("/api/devices/<int:device_id>")
    def update_device(device_id):
        if get_device_row(device_id) is None:
            return error("Equipo no encontrado", 404)
        raw = body()
        data, errors = validate_device(raw, partial=True)
        if errors:
            return error(errors)
        if not data:
            return error("No se enviaron campos para actualizar")
        data["updated_at"] = noc.now_iso()      # la fecha de actualización cambia sola
        try:
            # Los nombres de columna salen de validate_device(), nunca del usuario
            db().execute(f"UPDATE devices SET {', '.join(k + ' = ?' for k in data)} WHERE id = ?",
                         (*data.values(), device_id))
            db().commit()
        except sqlite3.IntegrityError:
            return error("Ya existe un equipo con ese nombre o esa IP", 409)
        noc.audit(db(), operator(raw), "device.update", "devices", device_id,
                  ", ".join(f"{k}={v}" for k, v in data.items() if k != "updated_at"))
        return jsonify(dict(get_device_row(device_id)))

    @app.delete("/api/devices/<int:device_id>")
    def delete_device(device_id):
        row = get_device_row(device_id)
        if row is None:
            return error("Equipo no encontrado", 404)
        # Los eventos del equipo se conservan (device_id queda NULL) por trazabilidad
        db().execute("DELETE FROM devices WHERE id = ?", (device_id,))
        db().commit()
        noc.audit(db(), operator(request.args), "device.delete", "devices", device_id,
                  f"{row['name']} {row['ip']}")
        return jsonify(deleted=device_id)

    # ----------------------------------------------------------------- eventos
    @app.get("/api/events")
    def list_events():
        a = request.args
        where, params = [], []
        if a.get("desde") and local_day_to_utc(a["desde"]):
            where.append("e.received_at >= ?"); params.append(local_day_to_utc(a["desde"]))
        if a.get("hasta") and local_day_to_utc(a["hasta"], end=True):
            where.append("e.received_at <= ?"); params.append(local_day_to_utc(a["hasta"], end=True))
        if a.get("vendor"):
            where.append("e.vendor = ?"); params.append(a["vendor"])
        if to_int(a.get("device_id")) is not None:
            where.append("e.device_id = ?"); params.append(to_int(a["device_id"]))
        if to_int(a.get("severity"), 0, 7) is not None:
            where.append("e.severity = ?"); params.append(to_int(a["severity"]))
        if to_int(a.get("sev_max"), 0, 7) is not None:
            where.append("e.severity <= ?"); params.append(to_int(a["sev_max"]))
        limit = to_int(a.get("limit"), 1, 500) or 200
        sql = ("SELECT e.*, d.name AS device_name FROM events e "
               "LEFT JOIN devices d ON d.id = e.device_id")
        if where:
            sql += " WHERE " + " AND ".join(where)
        rows = db().execute(sql + " ORDER BY e.id DESC LIMIT ?", (*params, limit)).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.post("/api/events/import")
    def import_events():
        """Importa un archivo (.log/.txt) o texto pegado, indicando el equipo de origen."""
        device = get_device_row(to_int(request.form.get("device_id")))
        if device is None:
            return error("Seleccione el equipo de origen")
        file = request.files.get("file")
        if file and file.filename:
            text, name = file.read().decode("utf-8", errors="replace"), file.filename
        else:
            text, name = request.form.get("text", ""), "texto_pegado"
        if not text.strip():
            return error("Seleccione un archivo o pegue al menos un mensaje Syslog")
        stats = noc.import_lines(db(), text.splitlines(), device["ip"], operator(request.form), name)
        return jsonify(stats)

    # ----------------------------------------------------------------- dashboard
    @app.get("/api/dashboard")
    def dashboard():
        conn = db()
        since = noc.iso_ago(24 * 3600)
        devices = conn.execute(
            "SELECT d.id, d.name, d.ip, d.vendor, d.status, d.authorized, d.is_simulated, "
            "(SELECT COUNT(*) FROM events e WHERE e.device_id = d.id AND e.received_at >= ?) AS eventos_24h, "
            "(SELECT MAX(received_at) FROM events e WHERE e.device_id = d.id) AS ultimo_evento "
            "FROM devices d ORDER BY d.name", (since,)).fetchall()
        by_severity = [0] * 8
        for r in conn.execute("SELECT severity, COUNT(*) n FROM events WHERE received_at >= ? "
                              "GROUP BY severity", (since,)):
            by_severity[r["severity"]] = r["n"]
        q = ("SELECT e.id, e.received_at, e.severity, e.vendor, e.mnemonic, e.message, e.source_ip, "
             "e.flags, e.dup_count, d.name AS device_name FROM events e "
             "LEFT JOIN devices d ON d.id = e.device_id ")
        recent = conn.execute(q + "ORDER BY e.id DESC LIMIT 10").fetchall()
        critical = conn.execute(q + "WHERE e.severity <= 3 ORDER BY e.id DESC LIMIT 10").fetchall()
        incidents = conn.execute(
            "SELECT i.id, i.title, i.severity, i.status, i.assigned_to, i.event_count, d.name AS device_name "
            "FROM incidents i LEFT JOIN devices d ON d.id = i.device_id WHERE i.status != 'cerrado' "
            "ORDER BY i.severity, i.id DESC LIMIT 10").fetchall()
        status_count = {}
        for d in devices:
            status_count[d["status"]] = status_count.get(d["status"], 0) + 1
        return jsonify(
            devices=[dict(d) for d in devices], devices_by_status=status_count,
            events_24h=sum(by_severity), critical_24h=sum(by_severity[:4]), by_severity=by_severity,
            recent_events=[dict(r) for r in recent], critical_events=[dict(r) for r in critical],
            open_incidents=[dict(r) for r in incidents],
            incidents_open=conn.execute("SELECT COUNT(*) FROM incidents WHERE status != 'cerrado'").fetchone()[0])

    # ----------------------------------------------------------------- incidentes
    def get_incident_row(incident_id):
        return db().execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()

    def add_note(incident_id, author, note):
        db().execute("INSERT INTO incident_notes (incident_id, author, note, created_at) VALUES (?, ?, ?, ?)",
                     (incident_id, author, note, noc.now_iso()))
        db().execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (noc.now_iso(), incident_id))
        db().commit()

    @app.get("/api/incidents")
    def list_incidents():
        estado = request.args.get("estado", "abiertos")
        sql = ("SELECT i.*, d.name AS device_name FROM incidents i "
               "LEFT JOIN devices d ON d.id = i.device_id")
        if estado == "abiertos":
            sql += " WHERE i.status != 'cerrado'"
        elif estado == "cerrado":
            sql += " WHERE i.status = 'cerrado'"
        return jsonify([dict(r) for r in db().execute(sql + " ORDER BY i.id DESC LIMIT 300")])

    @app.get("/api/incidents/<int:incident_id>")
    def get_incident(incident_id):
        inc = db().execute("SELECT i.*, d.name AS device_name FROM incidents i "
                           "LEFT JOIN devices d ON d.id = i.device_id WHERE i.id = ?",
                           (incident_id,)).fetchone()
        if inc is None:
            return error("Incidente no encontrado", 404)
        notes = db().execute("SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY id",
                             (incident_id,)).fetchall()
        actions = db().execute("SELECT * FROM actions WHERE incident_id = ? ORDER BY id",
                               (incident_id,)).fetchall()
        event = None
        if inc["event_id"]:
            event = db().execute("SELECT id, received_at, severity, source_ip, mnemonic, message, raw, flags "
                                 "FROM events WHERE id = ?", (inc["event_id"],)).fetchone()
        return jsonify(incident=dict(inc), notes=[dict(n) for n in notes],
                       actions=[dict(a) for a in actions], event=dict(event) if event else None)

    @app.post("/api/incidents")
    def create_incident():
        data = body()
        title = str(data.get("title") or "").strip()
        severity = to_int(data.get("severity"), 0, 7)
        errors = []
        if not 5 <= len(title) <= 150:
            errors.append("El título debe tener entre 5 y 150 caracteres")
        if severity is None:
            errors.append("Severidad inválida (0-7)")
        device_id = to_int(data.get("device_id"))
        if device_id is not None and get_device_row(device_id) is None:
            errors.append("Equipo no encontrado")
        if errors:
            return error(errors)
        inc_id = noc.create_incident(db(), title=title, severity=severity, created_by=operator(data),
                                     description=str(data.get("description") or "")[:2000] or None,
                                     device_id=device_id, event_id=to_int(data.get("event_id")),
                                     is_simulated=True)
        return jsonify(dict(get_incident_row(inc_id))), 201

    @app.post("/api/incidents/<int:incident_id>/assign")
    def assign_incident(incident_id):
        inc, data = get_incident_row(incident_id), body()
        if inc is None:
            return error("Incidente no encontrado", 404)
        if inc["status"] == "cerrado":
            return error("Un incidente cerrado no se puede modificar", 409)
        who = str(data.get("assigned_to") or "").strip()
        if not RE_OPERATOR.match(who):
            return error("Responsable inválido (2-32 caracteres: letras, números, '.', '_' o '-')")
        new_status = "asignado" if inc["status"] == "abierto" else inc["status"]
        db().execute("UPDATE incidents SET assigned_to = ?, status = ? WHERE id = ?", (who, new_status, incident_id))
        add_note(incident_id, operator(data), f"Asignado a {who}")
        noc.audit(db(), operator(data), "incident.assign", "incidents", incident_id, f"responsable={who}")
        return jsonify(dict(get_incident_row(incident_id)))

    @app.post("/api/incidents/<int:incident_id>/status")
    def change_status(incident_id):
        inc, data = get_incident_row(incident_id), body()
        if inc is None:
            return error("Incidente no encontrado", 404)
        new = data.get("status")
        if new not in TRANSITIONS.get(inc["status"], set()):
            return error(f"Transición no permitida: {inc['status']} -> {new}", 409)
        if new == "cerrado":
            resolution = str(data.get("resolution") or "").strip()
            if len(resolution) < 10:
                return error("Para cerrar escriba la resolución (mínimo 10 caracteres)")
            db().execute("UPDATE incidents SET status = 'cerrado', resolution = ?, closed_at = ? WHERE id = ?",
                         (resolution[:2000], noc.now_iso(), incident_id))
            add_note(incident_id, operator(data), f"Cerrado. Resolución: {resolution[:2000]}")
        else:
            db().execute("UPDATE incidents SET status = ? WHERE id = ?", (new, incident_id))
            add_note(incident_id, operator(data), f"Estado: {inc['status']} -> {new}")
        noc.audit(db(), operator(data), "incident.status", "incidents", incident_id, f"{inc['status']} -> {new}")
        return jsonify(dict(get_incident_row(incident_id)))

    @app.post("/api/incidents/<int:incident_id>/notes")
    def add_incident_note(incident_id):
        inc, data = get_incident_row(incident_id), body()
        if inc is None:
            return error("Incidente no encontrado", 404)
        if inc["status"] == "cerrado":
            return error("Un incidente cerrado no se puede modificar", 409)
        note = str(data.get("note") or "").strip()
        if not 3 <= len(note) <= 2000:
            return error("La nota debe tener entre 3 y 2000 caracteres")
        add_note(incident_id, operator(data), note)
        noc.audit(db(), operator(data), "incident.note", "incidents", incident_id, note[:200])
        return jsonify(ok=True), 201

    # ----------------------------------------------------------------- acciones (aprobación humana)
    @app.post("/api/incidents/<int:incident_id>/actions")
    def propose_action(incident_id):
        """Un operador o el asistente de IA PROPONEN un comando. Nada se ejecuta aquí."""
        inc, data = get_incident_row(incident_id), body()
        if inc is None:
            return error("Incidente no encontrado", 404)
        if inc["status"] == "cerrado":
            return error("Un incidente cerrado no admite acciones", 409)
        command = str(data.get("command") or "").strip()
        if not 2 <= len(command) <= 200 or "\n" in command:
            return error("Comando inválido (una sola línea, 2-200 caracteres)")
        who = AI_ACTOR if data.get("actor") == AI_ACTOR else operator(data)
        cur = db().execute("INSERT INTO actions (incident_id, command, justification, proposed_by, created_at) "
                           "VALUES (?, ?, ?, ?, ?)",
                           (incident_id, command, str(data.get("justification") or "")[:500] or None,
                            who, noc.now_iso()))
        db().commit()
        noc.audit(db(), who, "action.propose", "actions", cur.lastrowid, f"incidente={incident_id} cmd={command!r}")
        return jsonify(id=cur.lastrowid, status="pendiente"), 201

    def get_action(action_id):
        return db().execute("SELECT * FROM actions WHERE id = ?", (action_id,)).fetchone()

    @app.post("/api/actions/<int:action_id>/review")
    def review_action(action_id):
        act, data = get_action(action_id), body()
        if act is None:
            return error("Acción no encontrada", 404)
        if data.get("actor") == AI_ACTOR:
            noc.audit(db(), AI_ACTOR, "action.review", "actions", action_id, "IA intentó aprobar", "bloqueado")
            return error("Un agente de IA no puede aprobar acciones: se requiere un humano", 403)
        if act["status"] != "pendiente":
            return error("La acción ya fue revisada", 409)
        decision = data.get("decision")
        if decision not in ("aprobar", "rechazar"):
            return error("Decisión inválida (aprobar | rechazar)")
        who = operator(data)
        if who == act["proposed_by"]:
            return error("Quien propone no puede aprobar su propia acción (doble control)", 403)
        status = "aprobada" if decision == "aprobar" else "rechazada"
        db().execute("UPDATE actions SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?",
                     (status, who, noc.now_iso(), action_id))
        db().commit()
        noc.audit(db(), who, f"action.{status}", "actions", action_id, act["command"])
        return jsonify(dict(get_action(action_id)))

    @app.post("/api/actions/<int:action_id>/execute")
    def execute_action(action_id):
        act, data = get_action(action_id), body()
        if act is None:
            return error("Acción no encontrada", 404)
        if act["status"] != "aprobada":
            noc.audit(db(), operator(data), "action.execute", "actions", action_id,
                      f"estado={act['status']}", "bloqueado")
            return error("Solo se ejecutan acciones APROBADAS por un humano", 409)
        result = ("EJECUCIÓN SIMULADA (MVP): el comando no se envió a ningún equipo. "
                  "Verificación: revisar nuevos eventos del equipo en el NOC.")
        db().execute("UPDATE actions SET status = 'ejecutada', result = ? WHERE id = ?", (result, action_id))
        db().commit()
        add_note(act["incident_id"], operator(data), f"Acción #{action_id} ejecutada (simulada): {act['command']}")
        noc.audit(db(), operator(data), "action.execute", "actions", action_id, act["command"])
        return jsonify(dict(get_action(action_id)))

    # ----------------------------------------------------------------- configuraciones
    @app.get("/api/config")
    def generate_config():
        v, errors = plantillas._validate(request.args)
        if errors:
            return error(errors)
        device = get_device_row(to_int(request.args.get("device_id")))
        text = plantillas.GENERATORS[v["vendor"]](v, device)
        noc.audit(db(), operator(request.args), "config.generate", "devices", device["id"] if device else None,
                  f"{v['vendor']} servidor={v['server_ip']}:{v['port']} sev={v['severity']}")
        return jsonify(vendor=v["vendor"], config=text)

    # ----------------------------------------------------------------- consola simulada
    @app.get("/api/console")
    def console_allowed():
        vendor = request.args.get("vendor", "Cisco")
        return jsonify(allowed=[{"command": c, "description": d}
                                for c, d in plantillas.ALLOWLIST.get(vendor, [])])

    @app.post("/api/console")
    def console_run():
        data = body()
        dev = get_device_row(to_int(data.get("device_id")))
        if dev is None:
            return error("Seleccione un equipo del inventario")
        command = str(data.get("command") or "")
        actor = AI_ACTOR if data.get("actor") == AI_ACTOR else operator(data)
        ok, reason = plantillas.check(dev["vendor"], command, actor)
        noc.audit(db(), actor, "console.allowed" if ok else "console.blocked", "devices", dev["id"],
                  f"{dev['name']}: {command[:120]!r} -> {reason}", "ok" if ok else "bloqueado")
        if not ok:
            return jsonify(allowed=False, reason=reason, command=command), 403
        return jsonify(allowed=True, reason=reason, command=command,
                       output=plantillas.simulate(db(), dev, command))

    # ----------------------------------------------------------------- política IA y auditoría
    @app.get("/api/policy")
    def policy():
        conn = db()
        count = lambda sql: conn.execute(sql).fetchone()[0]
        return jsonify(
            fuentes_autorizadas=count("SELECT COUNT(*) FROM devices WHERE authorized = 1"),
            eventos_no_autorizados=count("SELECT COUNT(*) FROM events WHERE authorized_source = 0"),
            posibles_prompt_injection=count("SELECT COUNT(*) FROM events WHERE flags LIKE '%posible_prompt_injection%'"),
            mensajes_deduplicados=count("SELECT COALESCE(SUM(dup_count - 1), 0) FROM events"),
            comandos_bloqueados=count("SELECT COUNT(*) FROM audit_log WHERE action = 'console.blocked'"),
            acciones_pendientes=count("SELECT COUNT(*) FROM actions WHERE status = 'pendiente'"),
            bloqueos_ia=count(f"SELECT COUNT(*) FROM audit_log WHERE actor = '{AI_ACTOR}' AND result = 'bloqueado'"))

    @app.get("/api/audit")
    def audit_log():
        limit = to_int(request.args.get("limit"), 1, 1000) or 200
        rows = db().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.errorhandler(413)
    def too_large(_e):
        return error("El archivo supera el máximo permitido (2 MB)", 413)

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
