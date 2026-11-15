"""
NOC Syslog Inteligente v1.0.0 - aplicación web Flask.

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

  v1.0.0 - Motor de políticas antes de la IA, asistente de solo lectura y Telegram:
    GET               /politicas                   Página: políticas, laboratorio, decisiones, Telegram
    GET               /api/policies                Catálogo P01-P06
    POST              /api/policies/evaluate       Laboratorio: evaluar un mensaje (no se guarda)
    GET               /api/decisions               Decisiones ALLOW / REVIEW / BLOCK registradas
    POST              /api/decisions/<id>/review   Revisión humana de una decisión (P04)
    GET               /api/events/<id>/analysis    Análisis del asistente (solo lectura)
    GET               /api/improvements            Mejoras recomendadas para la red
    GET               /api/telegram/status         Estado de la integración (sin exponer el token)
    POST              /api/telegram/test           Enviar mensaje de prueba
    GET               /api/notifications           Historial de alertas a Telegram

  Consola de EQUIPOS REALES (serial / Telnet-TCP), solo personas:
    GET               /api/real/status             Estado de la sesión, IP de este PC, Syslog
    GET               /api/real/ports              Puertos COM detectados
    POST              /api/real/open | close       Abrir / cerrar la conexión
    POST              /api/real/mode               lectura | administrador (requiere aceptar responsabilidad)
    POST              /api/real/send | key         Enviar un comando / una tecla especial
    GET               /api/real/read?since=N       Salida del equipo (sondeo)
    POST              /api/real/apply-syslog       Aplicar la configuración Syslog del NOC (administrador)
    POST              /api/real/test               Prueba Syslog: desde el equipo o directa al NOC (-> Telegram)

  Usuarios y roles (inicio de sesión):
  Observabilidad:
    GET               /api/topology                Estado, salud, dependencias, impacto y causa raíz
    GET               /api/devices/<id>/health     Detalle de un equipo con su serie de latencia
    POST              /api/devices/<id>/probe      Sondear ahora (ICMP real o simulado)
    PUT               /api/devices/<id>/dependencies   De qué equipos depende (administrador)

    GET/POST          /login                       Página e inicio de sesión (paso 1: usuario y contraseña)
    POST              /login/mfa                   Paso 2: código TOTP (RFC 6238) o código de recuperación
    POST              /api/me/mfa/setup|enable|disable   Activar / desactivar el doble factor propio
    POST              /logout                      Cerrar sesión
    GET               /api/me                      Usuario actual y permisos
    POST              /api/me/password             Cambiar la propia contraseña
    GET/POST          /api/users                   Listar / crear usuarios (administrador)
    PUT               /api/users/<id>              Rol, nombre, activar/desactivar, restablecer clave (administrador)

SEGURIDAD: todas las consultas SQL usan parámetros "?" (sin inyección SQL),
toda entrada se valida y toda acción queda en la auditoría.
"""
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import timedelta
from pathlib import Path

from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for

import asistente_ia
import auth
import observabilidad
import totp
import consola_real
import noc
import plantillas
import telegram_noc
from security import policy_engine

VERSION = "1.0.0"
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
# Última decisión del motor de políticas para cada evento (subconsulta reutilizable)
DECISION_SQL = ("(SELECT pd.decision FROM policy_decisions pd WHERE pd.event_id = e.id "
                "ORDER BY pd.id DESC LIMIT 1) AS decision")


def secret_key(db_path) -> str:
    """Clave para firmar la cookie de sesión: SECRET_KEY del .env o una aleatoria guardada junto a la BD."""
    if os.getenv("SECRET_KEY"):
        return os.getenv("SECRET_KEY")
    f = Path(db_path).with_name(".secret_key")
    try:
        if f.exists():
            return f.read_text(encoding="utf-8").strip()
        key = secrets.token_hex(32)
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(key, encoding="utf-8")
        return key
    except OSError:
        return secrets.token_hex(32)


def create_app(db_path=None):
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = db_path or noc.DB_PATH
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024   # archivos de máx. 2 MB
    app.config["SECRET_KEY"] = secret_key(app.config["DATABASE_PATH"])
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      PERMANENT_SESSION_LIFETIME=timedelta(hours=8))

    conn = noc.connect(app.config["DATABASE_PATH"])
    noc.init_db(conn)
    observabilidad.seed_links(conn)
    if auth.seed_users(conn):
        print("[NOC] Usuarios iniciales creados: admin (administrador), operador (operador), "
              "monitoreo (solo lectura). Contraseñas en el README / Manual de usuario.")
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

    # ----------------------------------------------------------------- sesión y roles
    def auth_on() -> bool:
        """El inicio de sesión es obligatorio. Solo las pruebas unitarias de la API (TESTING) lo
        omiten, salvo que pidan AUTH_REQUIRED para probar precisamente la autenticación."""
        return not app.config.get("TESTING") or app.config.get("AUTH_REQUIRED", False)

    def current_user():
        return g.get("user")

    PUBLIC = {"login_page", "login", "login_mfa", "health", "static"}
    MFA_PENDING_SECONDS = 300            # tiempo para escribir el código tras la contraseña

    @app.before_request
    def require_login():
        if not auth_on() or request.endpoint in PUBLIC:
            return None
        uid = session.get("uid")
        user = db().execute("SELECT * FROM users WHERE id = ? AND active = 1", (uid,)).fetchone() if uid else None
        is_api = request.path.startswith("/api/")
        if user is None:
            session.pop("uid", None)          # no borra un ingreso a medias (segundo factor pendiente)
            session.pop("csrf", None)
            if is_api:
                return error("Sesión no iniciada o vencida: inicie sesión", 401)
            return redirect(url_for("login_page", next=request.path))
        g.user = user
        # Protección CSRF: toda petición que cambia datos debe traer el token de la sesión
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), session.get("csrf", "")):
                return error("Token de seguridad inválido: recargue la página", 403)
        if (why := auth.authorize(user["role"], request.method, request.endpoint)):
            noc.audit(db(), user["username"], "auth.denied", detail=f"{request.method} {request.path}: {why}",
                      result="bloqueado")
            return error(why, 403)
        return None

    def operator(data=None) -> str:
        """Responsable de la acción = usuario con sesión iniciada (no se puede suplantar).
        Sin sesión (solo pruebas unitarias) se toma del formulario o del .env.
        Ningún humano puede hacerse pasar por 'asistente_ia' ni por 'sistema'."""
        if current_user() is not None:
            return current_user()["username"]
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
    def page(start):
        u = current_user()
        return render_template("index.html", version=VERSION, start_view=start,
                               operator=u["username"] if u else noc.DEFAULT_OPERATOR,
                               user=auth.public(u), csrf=session.get("csrf", ""), auth=auth_on())

    @app.get("/")
    def index():
        return page("dashboard")

    # ----------------------------------------------------------------- observabilidad
    @app.get("/api/topology")
    def topology():
        return jsonify(observabilidad.topology(db()))

    def device_or_404(device_id):
        return db().execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()

    @app.get("/api/devices/<int:device_id>/health")
    def device_health(device_id):
        if device_or_404(device_id) is None:
            return error("Equipo no encontrado", 404)
        topo = observabilidad.topology(db())
        node = next(n for n in topo["nodes"] if n["id"] == device_id)
        names = {n["id"]: n["name"] for n in topo["nodes"]}
        node["parent_names"] = [names[i] for i in node["parents"]]
        node["child_names"] = [names[i] for i in node["children"]]
        node["recent_events"] = [dict(r) for r in db().execute(
            "SELECT id, received_at, severity, mnemonic, substr(message, 1, 140) AS message FROM events "
            "WHERE device_id = ? ORDER BY id DESC LIMIT 6", (device_id,))]
        return jsonify(node)

    @app.post("/api/devices/<int:device_id>/probe")
    def probe_device(device_id):
        dev = device_or_404(device_id)
        if dev is None:
            return error("Equipo no encontrado", 404)
        if dev["status"] == "mantenimiento":
            return error("El equipo está en mantenimiento: no se sondea", 409)
        res = observabilidad.run_probes(db(), only_id=device_id)[0]
        noc.audit(db(), operator(body()), "obs.probe", "devices", device_id,
                  f"{dev['name']}: {'responde' if res['ok'] else 'sin respuesta'} ({res['method']}"
                  f"{', ' + str(res['latency_ms']) + ' ms' if res['latency_ms'] is not None else ''})",
                  "ok" if res["ok"] else "alerta")
        return jsonify(res)

    @app.put("/api/devices/<int:device_id>/dependencies")
    def set_dependencies(device_id):
        dev = device_or_404(device_id)
        if dev is None:
            return error("Equipo no encontrado", 404)
        raw = body().get("parents")
        if not isinstance(raw, list) or len(raw) > 10:
            return error("Envíe 'parents' como una lista de hasta 10 equipos")
        try:
            parents = sorted({int(x) for x in raw})
        except (TypeError, ValueError):
            return error("Los equipos deben indicarse por su número")
        if device_id in parents:
            return error("Un equipo no puede depender de sí mismo")
        known = {r[0] for r in db().execute("SELECT id FROM devices")}
        if any(p not in known for p in parents):
            return error("Alguno de los equipos no existe")
        if observabilidad.creates_cycle(db(), device_id, parents):
            return error("Esa dependencia formaría un ciclo (A depende de B y B de A)", 409)
        observabilidad.set_parents(db(), device_id, parents)
        names = [r[0] for r in db().execute(f"SELECT name FROM devices WHERE id IN ({','.join('?' * len(parents))})",
                                             parents)] if parents else []
        noc.audit(db(), operator(), "obs.dependencies", "devices", device_id,
                  f"{dev['name']} depende de: {', '.join(names) or 'ninguno'}")
        return jsonify(ok=True, parents=parents)

    # ----------------------------------------------------------------- inicio de sesión
    @app.get("/login")
    def login_page():
        if auth_on() and session.get("uid"):
            return redirect(url_for("index"))
        return render_template("login.html", version=VERSION)

    @app.post("/login")
    def login():
        data = request.get_json(silent=True) or request.form
        username = str(data.get("username") or "")[:32]
        user, msg, event = auth.authenticate(db(), username, str(data.get("password") or ""))
        who = username.strip().lower() if auth.RE_USERNAME.match(username.strip().lower()) else "desconocido"
        if user is None:
            noc.audit(db(), who, event, "users", None, msg, "alerta" if event == "login.lock" else "bloqueado")
            if event == "login.lock":
                notify_admin(f"🔒 <b>NOC · Cuenta bloqueada</b>\nLa cuenta <b>{telegram_noc.esc(who)}</b> superó "
                             f"{auth.MAX_FAILED} intentos fallidos de inicio de sesión y quedó bloqueada "
                             f"{auth.LOCK_MINUTES} minutos.")
            return error(msg, 423 if event in ("login.lock", "login.locked") else 401)
        nxt = str(data.get("next") or "/")
        nxt = nxt if nxt.startswith("/") and not nxt.startswith("//") else "/"
        if user["totp_enabled"]:
            # Paso 2: la sesión aún NO está iniciada; solo se recuerda quién superó la contraseña.
            session.clear()
            session["mfa_uid"] = user["id"]
            session["mfa_at"] = int(time.time())
            session["mfa_next"] = nxt
            noc.audit(db(), user["username"], "login.password_ok", "users", user["id"], "falta el segundo factor")
            return jsonify(ok=True, mfa_required=True)
        return finish_login(user, nxt, "sin doble factor")

    def finish_login(user, nxt, how):
        user = auth.complete_login(db(), user)
        session.clear()
        session.permanent = True
        session["uid"] = user["id"]
        session["csrf"] = secrets.token_hex(24)
        noc.audit(db(), user["username"], "login.ok", "users", user["id"], f"rol={user['role']}; {how}")
        return jsonify(ok=True, user=auth.public(user), next=nxt)

    @app.post("/login/mfa")
    def login_mfa():
        uid, started = session.get("mfa_uid"), session.get("mfa_at", 0)
        if not uid or time.time() - started > MFA_PENDING_SECONDS:
            session.clear()
            return error("La verificación venció: escriba de nuevo usuario y contraseña", 401)
        data = request.get_json(silent=True) or request.form
        user = db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if user is None or not user["active"]:
            session.clear()
            return error("La cuenta no está disponible", 401)
        if user["locked_until"] and user["locked_until"] > noc.now_iso():
            session.clear()
            return error(f"Cuenta bloqueada temporalmente. Intente después de {auth.LOCK_MINUTES} minutos.", 423)
        ok, how = auth.check_second_factor(db(), user, str(data.get("code") or "")[:20])
        if not ok:
            locked = auth.register_failure(db(), user)
            noc.audit(db(), user["username"], "login.lock" if locked else "login.mfa_fail", "users", user["id"],
                      "segundo factor incorrecto", "alerta" if locked else "bloqueado")
            if locked:
                session.clear()
                notify_admin(f"🔒 <b>NOC · Cuenta bloqueada</b>\nLa cuenta <b>{telegram_noc.esc(user['username'])}</b> "
                             f"falló {auth.MAX_FAILED} veces el segundo factor y quedó bloqueada {auth.LOCK_MINUTES} minutos.")
                return error("Demasiados intentos fallidos: la cuenta queda bloqueada 5 minutos.", 423)
            return error(how, 401)
        if how == "recuperacion":
            left = len(json.loads(db().execute("SELECT recovery_codes FROM users WHERE id = ?",
                                               (uid,)).fetchone()[0] or "[]"))
            noc.audit(db(), user["username"], "user.mfa_recovery", "users", uid, f"quedan {left} códigos", "alerta")
        return finish_login(user, session.get("mfa_next", "/"),
                            "2FA TOTP" if how == "totp" else "2FA con código de recuperación")

    @app.post("/logout")
    def logout():
        u = current_user()
        if u is not None:
            noc.audit(db(), u["username"], "logout", "users", u["id"])
        session.clear()
        return jsonify(ok=True)

    @app.get("/api/me")
    def me():
        u = current_user()
        return jsonify(user=auth.public(u), auth=auth_on(), roles=auth.ROLES)

    @app.post("/api/me/password")
    def change_password():
        u = current_user()
        if u is None:
            return error("No hay sesión iniciada", 401)
        data = body()
        from werkzeug.security import check_password_hash
        if not check_password_hash(u["password_hash"], str(data.get("current") or "")):
            noc.audit(db(), u["username"], "user.password", "users", u["id"], "contraseña actual incorrecta", "bloqueado")
            return error("La contraseña actual no es correcta", 403)
        new = str(data.get("new") or "")
        if (probs := auth.password_problems(new)):
            return error(probs)
        db().execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                     (auth.hash_password(new), noc.now_iso(), u["id"]))
        db().commit()
        noc.audit(db(), u["username"], "user.password", "users", u["id"], "cambió su contraseña")
        return jsonify(ok=True)

    # ----------------------------------------------------------------- doble factor propio (TOTP)
    def password_ok(u, pw) -> bool:
        from werkzeug.security import check_password_hash
        return check_password_hash(u["password_hash"], str(pw or ""))

    @app.post("/api/me/mfa/setup")
    def mfa_setup():
        """Genera un secreto PENDIENTE (en la sesión, no en la BD) y su QR. Se guarda al confirmar un código."""
        u = current_user()
        if u is None:
            return error("No hay sesión iniciada", 401)
        if u["totp_enabled"]:
            return error("El doble factor ya está activo", 409)
        secret = totp.generate_secret()
        session["mfa_setup"] = secret
        uri = totp.provisioning_uri(u["username"], secret)
        return jsonify(secret=totp.format_secret(secret), uri=uri, qr=totp.qr_data_uri(uri),
                       issuer=totp.ISSUER, digits=totp.DIGITS, period=totp.PERIOD)

    @app.post("/api/me/mfa/enable")
    def mfa_enable():
        u = current_user()
        secret = session.get("mfa_setup")
        if u is None or not secret:
            return error("Primero genere el código QR", 400)
        c = totp.verify(secret, str(body().get("code") or ""))
        if c is None:
            return error("El código no coincide: revise que el reloj del celular y del PC estén en hora", 400)
        codes = totp.generate_recovery_codes()
        db().execute("UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_last_counter = ?, recovery_codes = ?, "
                     "updated_at = ? WHERE id = ?", (secret, c, auth.hash_recovery(codes), noc.now_iso(), u["id"]))
        db().commit()
        session.pop("mfa_setup", None)
        noc.audit(db(), u["username"], "user.mfa_enable", "users", u["id"], "doble factor TOTP activado")
        return jsonify(ok=True, recovery_codes=codes)

    @app.post("/api/me/mfa/disable")
    def mfa_disable():
        u = current_user()
        data = body()
        if u is None or not u["totp_enabled"]:
            return error("El doble factor no está activo", 400)
        if not password_ok(u, data.get("password")):
            return error("La contraseña no es correcta", 403)
        ok, how = auth.check_second_factor(db(), u, str(data.get("code") or ""))
        if not ok:
            return error(how, 403)
        db().execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_counter = NULL, "
                     "recovery_codes = NULL, updated_at = ? WHERE id = ?", (noc.now_iso(), u["id"]))
        db().commit()
        noc.audit(db(), u["username"], "user.mfa_disable", "users", u["id"], "doble factor desactivado", "alerta")
        return jsonify(ok=True)

    # ----------------------------------------------------------------- gestión de usuarios (administrador)
    def active_admins(exclude_id=None):
        return db().execute("SELECT COUNT(*) FROM users WHERE role = 'administrador' AND active = 1 AND id != ?",
                            (exclude_id or 0,)).fetchone()[0]

    @app.get("/api/users")
    def list_users():
        return jsonify([auth.public(r) for r in db().execute("SELECT * FROM users ORDER BY id")])

    @app.post("/api/users")
    def create_user():
        data = body()
        username = str(data.get("username") or "").strip().lower()
        full_name = str(data.get("full_name") or "").strip()[:80]
        role = data.get("role")
        errors = []
        if not auth.RE_USERNAME.match(username):
            errors.append("Usuario inválido: 3-32 caracteres en minúscula, números, '.', '_' o '-'")
        if username in (AI_ACTOR, "sistema", "desconocido"):
            errors.append("Ese nombre de usuario está reservado")
        if len(full_name) < 3:
            errors.append("Escriba el nombre completo")
        if role not in auth.ROLES:
            errors.append("Rol inválido (administrador, operador, monitoreo)")
        errors += auth.password_problems(str(data.get("password") or ""))
        if errors:
            return error(errors)
        try:
            cur = db().execute("INSERT INTO users (username, full_name, role, password_hash, created_at, updated_at) "
                               "VALUES (?, ?, ?, ?, ?, ?)", (username, full_name, role,
                                                             auth.hash_password(data["password"]), noc.now_iso(), noc.now_iso()))
        except sqlite3.IntegrityError:
            return error("Ese nombre de usuario ya existe", 409)
        db().commit()
        noc.audit(db(), operator(), "user.create", "users", cur.lastrowid, f"{username} rol={role}")
        return jsonify(auth.public(db().execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone())), 201

    @app.put("/api/users/<int:user_id>")
    def update_user(user_id):
        data = body()
        target = db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if target is None:
            return error("Usuario no encontrado", 404)
        changes, detail = {}, []
        if "full_name" in data:
            name = str(data["full_name"] or "").strip()[:80]
            if len(name) < 3:
                return error("Escriba el nombre completo")
            changes["full_name"] = name
        if "role" in data:
            if data["role"] not in auth.ROLES:
                return error("Rol inválido")
            changes["role"] = data["role"]
        if "active" in data:
            changes["active"] = 1 if data["active"] in (True, 1, "1", "true") else 0
        if data.get("password"):
            if (probs := auth.password_problems(str(data["password"]))):
                return error(probs)
            changes["password_hash"] = auth.hash_password(str(data["password"]))
            changes["failed_attempts"], changes["locked_until"] = 0, None
            detail.append("restableció la contraseña")
        if data.get("unlock"):
            changes["failed_attempts"], changes["locked_until"] = 0, None
            detail.append("desbloqueó la cuenta")
        if data.get("reset_mfa"):
            changes.update(totp_secret=None, totp_enabled=0, totp_last_counter=None, recovery_codes=None)
            detail.append("reinició el doble factor")
        demoted = changes.get("role", target["role"]) != "administrador" or changes.get("active", target["active"]) == 0
        if target["role"] == "administrador" and target["active"] and demoted and active_admins(user_id) == 0:
            return error("Debe quedar al menos un administrador activo", 409)
        if not changes:
            return error("No hay cambios")
        changes["updated_at"] = noc.now_iso()
        cols = ", ".join(f"{k} = ?" for k in changes)
        db().execute(f"UPDATE users SET {cols} WHERE id = ?", (*changes.values(), user_id))
        db().commit()
        detail += [f"{k}={v}" for k, v in changes.items() if k in ("full_name", "role", "active")]
        noc.audit(db(), operator(), "user.update", "users", user_id, f"{target['username']}: " + ", ".join(detail))
        return jsonify(auth.public(db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()))

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
        sql = ("SELECT e.*, d.name AS device_name, "
               "(SELECT pd.decision FROM policy_decisions pd WHERE pd.event_id = e.id "
               "ORDER BY pd.id DESC LIMIT 1) AS decision FROM events e "
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
             "e.flags, e.dup_count, d.name AS device_name, (SELECT pd.decision FROM policy_decisions pd "
             "WHERE pd.event_id = e.id ORDER BY pd.id DESC LIMIT 1) AS decision FROM events e "
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
        # Línea de tiempo: eventos por hora en las últimas 24 h (24 posiciones, la última = hora actual)
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        timeline, timeline_crit = [0] * 24, [0] * 24
        for r in conn.execute("SELECT received_at, severity, dup_count FROM events WHERE received_at >= ?", (since,)):
            try:
                t = datetime.strptime(r["received_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            idx = 23 - min(23, int((now - t).total_seconds() // 3600))
            timeline[idx] += r["dup_count"]
            if r["severity"] <= 3:
                timeline_crit[idx] += r["dup_count"]
        decisions = {k: 0 for k in ("ALLOW", "REVIEW", "BLOCK")}
        for r in conn.execute("SELECT decision, COUNT(*) n FROM policy_decisions WHERE created_at >= ? "
                              "GROUP BY decision", (since,)):
            decisions[r["decision"]] = r["n"]
        pending_reviews = conn.execute("SELECT COUNT(*) FROM policy_decisions WHERE decision != 'ALLOW' "
                                       "AND reviewed_by IS NULL").fetchone()[0]
        return jsonify(
            timeline=timeline, timeline_critical=timeline_crit, decisions_24h=decisions,
            pending_reviews=pending_reviews,
            last_event_at=conn.execute("SELECT MAX(received_at) FROM events").fetchone()[0],
            actions_pending=conn.execute("SELECT COUNT(*) FROM actions WHERE status = 'pendiente'").fetchone()[0],
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
            bloqueos_ia=count(f"SELECT COUNT(*) FROM audit_log WHERE actor = '{AI_ACTOR}' AND result = 'bloqueado'"),
            decisiones_allow=count("SELECT COUNT(*) FROM policy_decisions WHERE decision = 'ALLOW'"),
            decisiones_review=count("SELECT COUNT(*) FROM policy_decisions WHERE decision = 'REVIEW'"),
            decisiones_block=count("SELECT COUNT(*) FROM policy_decisions WHERE decision = 'BLOCK'"),
            secretos_redactados=count("SELECT COUNT(*) FROM policy_decisions WHERE secrets IS NOT NULL"),
            alertas_telegram=count("SELECT COUNT(*) FROM notifications WHERE status = 'enviada'"))

    @app.get("/api/audit")
    def audit_log():
        limit = to_int(request.args.get("limit"), 1, 1000) or 200
        rows = db().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return jsonify([dict(r) for r in rows])

    # ----------------------------------------------------------------- v1.0: políticas antes de la IA
    @app.get("/politicas")
    def politicas_page():
        """La sección de políticas vive dentro de la misma aplicación de una sola página."""
        return page("politicas")

    @app.get("/api/stats/spectrum")
    def spectrum():
        """Espectro de eventos: matriz hora (últimas N horas, hora Colombia) x severidad 0-7."""
        from datetime import datetime, timedelta, timezone
        hours = to_int(request.args.get("hours"), 6, 72) or 24
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        start = now - timedelta(hours=hours - 1)
        keys = [(start + timedelta(hours=i)).strftime("%Y-%m-%dT%H") for i in range(hours)]
        index = {k: i for i, k in enumerate(keys)}
        matrix = [[0] * 8 for _ in keys]
        for r in db().execute("SELECT substr(received_at, 1, 13) h, severity, SUM(dup_count) n FROM events "
                              "WHERE received_at >= ? GROUP BY h, severity", (start.strftime("%Y-%m-%dT%H:00:00Z"),)):
            if r["h"] in index:
                matrix[index[r["h"]]][r["severity"]] = r["n"]
        labels = [(start + timedelta(hours=i + noc.LOCAL_UTC_OFFSET)).strftime("%H:00") for i in range(hours)]
        decisions = {r["decision"]: r["n"] for r in db().execute(
            "SELECT decision, COUNT(*) n FROM policy_decisions WHERE created_at >= ? GROUP BY decision",
            (start.strftime("%Y-%m-%dT%H:00:00Z"),))}
        last = db().execute("SELECT MAX(received_at) FROM events").fetchone()[0]
        return jsonify(labels=labels, matrix=matrix, decisions=decisions, last_event=last, now=noc.now_iso())

    @app.get("/api/policies")
    def policies_catalog():
        return jsonify(policies=policy_engine.POLICIES, meaning=policy_engine.MEANING,
                       brute_force_threshold=policy_engine.BRUTE_FORCE_THRESHOLD)

    @app.post("/api/policies/evaluate")
    def policies_evaluate():
        """Laboratorio: evalúa un mensaje con las políticas elegidas. NO se guarda como evento."""
        data = body()
        text = str(data.get("message") or "")
        if not 1 <= len(text.strip()) <= 2000:
            return error("Escriba un mensaje de 1 a 2000 caracteres")
        active = data.get("active")
        if active is not None:
            if not isinstance(active, list) or any(p not in policy_engine.POLICY_IDS for p in active):
                return error("Lista de políticas inválida")
        from syslog_parser import parse
        parsed = parse(text)
        severity = to_int(data.get("severity"), 0, 7)
        severity = parsed["severity"] if severity is None else severity
        event = {"message": parsed["message"], "raw": text, "severity": severity,
                 "authorized": data.get("authorized", True) in (True, 1, "1", "true", "on"),
                 "flags": parsed["parse_flags"] + (["posible_prompt_injection"] if noc.detect_prompt_injection(text)
                                                  else []),
                 "mnemonic": parsed["mnemonic"]}
        decision = policy_engine.evaluate(event, active=active,
                                          context={"auth_failures": to_int(data.get("auth_failures"), 0, 10000) or 0})
        analysis = asistente_ia.analyze({**event, "message": decision["redacted_message"],
                                         "vendor": parsed["vendor_hint"] or "Cisco", "device_name": "laboratorio"},
                                        decision)
        noc.audit(db(), operator(data), "policy.lab", detail=f"{decision['decision']} "
                  f"activas={','.join(active) if active is not None else 'todas'} hash={decision['event_hash'][:16]}")
        return jsonify(decision=decision, analysis=analysis, meaning=policy_engine.MEANING[decision["decision"]],
                       parsed={"severity": severity, "vendor": parsed["vendor_hint"], "mnemonic": parsed["mnemonic"],
                               "format": parsed["format"]})

    @app.get("/api/decisions")
    def list_decisions():
        a = request.args
        where, params = [], []
        if a.get("decision") in ("ALLOW", "REVIEW", "BLOCK"):
            where.append("pd.decision = ?"); params.append(a["decision"])
        if a.get("pendientes") == "1":
            where.append("pd.decision != 'ALLOW' AND pd.reviewed_by IS NULL")
        limit = to_int(a.get("limit"), 1, 500) or 100
        sql = ("SELECT pd.*, e.severity, e.message, e.source_ip, e.vendor, e.mnemonic, e.received_at, "
               "d.name AS device_name FROM policy_decisions pd JOIN events e ON e.id = pd.event_id "
               "LEFT JOIN devices d ON d.id = e.device_id")
        if where:
            sql += " WHERE " + " AND ".join(where)
        rows = db().execute(sql + " ORDER BY pd.id DESC LIMIT ?", (*params, limit)).fetchall()
        counts = {r["decision"]: r["n"] for r in db().execute(
            "SELECT decision, COUNT(*) n FROM policy_decisions GROUP BY decision")}
        return jsonify(decisions=[dict(r) for r in rows],
                       counts={k: counts.get(k, 0) for k in ("ALLOW", "REVIEW", "BLOCK")})

    @app.post("/api/decisions/<int:decision_id>/review")
    def review_decision(decision_id):
        """P04: un humano confirma o descarta una decisión REVIEW/BLOCK. La IA no puede hacerlo."""
        data = body()
        if data.get("actor") == AI_ACTOR:
            noc.audit(db(), AI_ACTOR, "decision.review", "policy_decisions", decision_id,
                      "IA intentó revisar", "bloqueado")
            return error("Un agente de IA no puede revisar decisiones: se requiere un humano", 403)
        row = db().execute("SELECT * FROM policy_decisions WHERE id = ?", (decision_id,)).fetchone()
        if row is None:
            return error("Decisión no encontrada", 404)
        if row["decision"] == "ALLOW":
            return error("Las decisiones ALLOW no requieren revisión", 409)
        if row["reviewed_by"]:
            return error("La decisión ya fue revisada", 409)
        verdict = data.get("verdict")
        if verdict not in ("confirmado", "falso_positivo"):
            return error("Veredicto inválido (confirmado | falso_positivo)")
        note = str(data.get("note") or "").strip()
        if len(note) < 10:
            return error("Escriba la justificación (mínimo 10 caracteres)")
        who = operator(data)
        db().execute("UPDATE policy_decisions SET reviewed_by = ?, review_note = ?, reviewed_at = ? WHERE id = ?",
                     (who, f"{verdict}: {note[:500]}", noc.now_iso(), decision_id))
        db().commit()
        noc.audit(db(), who, "decision.review", "policy_decisions", decision_id,
                  f"{row['decision']} -> {verdict}: {note[:200]}")
        return jsonify(dict(db().execute("SELECT * FROM policy_decisions WHERE id = ?", (decision_id,)).fetchone()))

    @app.get("/api/events/<int:event_id>/analysis")
    def event_analysis(event_id):
        ev, decision, analysis = asistente_ia.analysis_for_event(db(), event_id)
        if ev is None:
            return error("Evento no encontrado", 404)
        if decision["decision"] == "BLOCK":      # el contenido bloqueado no se reexpone completo
            ev["raw"] = "[contenido aislado por P06]"
        return jsonify(event=ev, decision=decision, analysis=analysis)

    @app.get("/api/improvements")
    def improvements():
        return jsonify(asistente_ia.improvements(db()))

    @app.get("/api/telegram/status")
    def telegram_status():
        c = telegram_noc.CONFIG
        return jsonify(enabled=c.enabled, token_configured=bool(c.token), chats=len(c.chat_ids),
                       max_severity=c.max_severity, rate_per_minute=c.rate_per_minute,
                       sent=db().execute("SELECT COUNT(*) FROM notifications WHERE status = 'enviada'").fetchone()[0],
                       failed=db().execute("SELECT COUNT(*) FROM notifications WHERE status = 'fallida'").fetchone()[0])

    @app.post("/api/telegram/test")
    def telegram_test():
        data = body()
        if not telegram_noc.CONFIG.enabled:
            return error("Telegram no está activo: configure TELEGRAM_ENABLED=1, TELEGRAM_BOT_TOKEN y "
                         "TELEGRAM_CHAT_IDS en el .env y reinicie la aplicación", 409)
        ok, detail = telegram_noc.send_text(
            f"✅ <b>NOC Syslog Inteligente v{VERSION}</b>\nMensaje de prueba enviado por "
            f"{telegram_noc.esc(operator(data))}. Las alertas llegarán a este chat.\nUse /ayuda para ver los comandos.")
        db().execute("INSERT INTO notifications (channel, kind, text, status, detail, created_at) "
                     "VALUES ('telegram', 'prueba', 'Mensaje de prueba', ?, ?, ?)",
                     ("enviada" if ok else "fallida", detail, noc.now_iso()))
        db().commit()
        noc.audit(db(), operator(data), "telegram.test", detail=detail, result="ok" if ok else "error")
        return (jsonify(ok=True, detail=detail), 200) if ok else error(f"No se pudo enviar: {detail}", 502)

    @app.get("/api/notifications")
    def notifications():
        limit = to_int(request.args.get("limit"), 1, 200) or 50
        rows = db().execute("SELECT * FROM notifications ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return jsonify([dict(r) for r in rows])

    # ----------------------------------------------------------------- consola de equipos REALES
    REAL = {"session": None}

    def real_session():
        s = REAL["session"]
        if s is not None and not s.alive:
            REAL["session"] = None
            return None
        return s

    def human_only(data):
        if data.get("actor") == AI_ACTOR:
            noc.audit(db(), AI_ACTOR, "real.blocked", detail="la IA intentó usar la consola real", result="bloqueado")
            return error("Un agente de IA no puede usar la consola de equipos reales (P03)", 403)
        return None

    def notify_admin(text):
        """Aviso de seguridad a Telegram (si está activo) y registro en el historial."""
        status, detail = "desactivada", "Telegram no configurado"
        if telegram_noc.CONFIG.enabled:
            ok, detail = telegram_noc.send_text(text)
            status = "enviada" if ok else "fallida"
        db().execute("INSERT INTO notifications (channel, kind, text, status, detail, created_at) "
                     "VALUES ('telegram', 'consola_admin', ?, ?, ?, ?)", (text, status, detail, noc.now_iso()))
        db().commit()

    @app.get("/api/real/status")
    def real_status():
        import socket as _s
        try:
            ips = sorted({ip for ip in _s.gethostbyname_ex(_s.gethostname())[2] if not ip.startswith("127.")})
        except OSError:
            ips = []
        s = real_session()
        return jsonify(available=consola_real.HAVE_SERIAL, session=s.info() if s else None, local_ips=ips,
                       syslog_host=noc.SYSLOG_HOST, syslog_port=noc.SYSLOG_PORT,
                       baudrates=consola_real.BAUDRATES, keys=list(consola_real.SPECIAL_KEYS))

    @app.get("/api/real/ports")
    def real_ports():
        if not consola_real.HAVE_SERIAL:
            return error("Falta el paquete pyserial: ejecute  pip install -r requirements.txt", 503)
        return jsonify(consola_real.list_ports())

    @app.post("/api/real/open")
    def real_open():
        data = body()
        if (blocked := human_only(data)):
            return blocked
        if real_session():
            return error("Ya hay una sesión abierta: ciérrela antes de abrir otra", 409)
        kind, target = str(data.get("kind") or ""), str(data.get("target") or "").strip()
        if kind == "loop" and not app.config.get("TESTING"):
            return error("Tipo de conexión inválido (serial | tcp)")
        if (msg := consola_real.validate_target(kind, target)):
            return error(msg)
        baud = to_int(data.get("baudrate")) or 9600
        if baud not in consola_real.BAUDRATES:
            return error("Velocidad inválida")
        device = get_device_row(to_int(data.get("device_id")))
        try:
            s = consola_real.Session(kind, target, baud, operator(data), dict(device) if device else None)
        except Exception as e:
            noc.audit(db(), operator(data), "real.open", detail=f"{kind} {target}: {type(e).__name__}", result="error")
            hint = (" Revise que el cable esté conectado, que el puerto no esté abierto en PuTTY u otro programa "
                    "y el controlador del adaptador USB-serial." if kind == "serial" else
                    " Revise que el nodo esté encendido en GNS3 y el puerto de consola.")
            return error(f"No se pudo abrir {target}: {e}.{hint}", 502)
        REAL["session"] = s
        noc.audit(db(), s.operator, "real.open", "devices", device["id"] if device else None,
                  f"{kind} {target} {baud} bps")
        return jsonify(s.info())

    @app.post("/api/real/close")
    def real_close():
        s = real_session()
        if s:
            s.close()
            noc.audit(db(), operator(body()), "real.close", detail=f"{s.target} comandos={s.commands}")
        REAL["session"] = None
        return jsonify(ok=True)

    @app.post("/api/real/mode")
    def real_mode():
        data = body()
        if (blocked := human_only(data)):
            return blocked
        s = real_session()
        if not s:
            return error("No hay una sesión abierta", 409)
        mode = data.get("mode")
        if mode not in ("lectura", "administrador"):
            return error("Modo inválido (lectura | administrador)")
        if mode == "administrador" and current_user() is not None and current_user()["role"] != "administrador":
            noc.audit(db(), operator(data), "real.blocked", detail=f"{s.target}: modo administrador sin rol", result="bloqueado")
            return error("Solo un usuario con rol administrador puede activar el modo administrador", 403)
        if mode == "administrador" and data.get("ack") is not True:
            return error("Para configurar el equipo confirme que es el administrador responsable", 400)
        s.mode = mode
        who = operator(data)
        noc.audit(db(), who, "real.mode", detail=f"{s.target} -> {mode}", result="alerta" if mode == "administrador" else "ok")
        if mode == "administrador":
            dev = s.device["name"] if s.device else s.target
            notify_admin(f"🔐 <b>NOC · Sesión de administración</b>\n{telegram_noc.esc(who)} activó el modo "
                         f"administrador en <b>{telegram_noc.esc(dev)}</b> ({telegram_noc.esc(s.target)}).\n"
                         "<i>Cada comando queda en la auditoría.</i>")
        return jsonify(s.info())

    @app.post("/api/real/send")
    def real_send():
        data = body()
        if (blocked := human_only(data)):
            return blocked
        s = real_session()
        if not s:
            return error("No hay una sesión abierta", 409)
        command = str(data.get("command") or "")
        if s.mode == "administrador" and current_user() is not None and current_user()["role"] != "administrador":
            return jsonify(allowed=False, reason="La sesión está en modo administrador: solo un administrador puede "
                                                 "enviar comandos", needs_confirm=False), 403
        vendor = (s.device or {}).get("vendor") or "Otro"
        ok, reason, needs = consola_real.check_command(command, s.mode, vendor, data.get("confirm") is True)
        safe = consola_real.redact_command(command)
        who = operator(data)
        if not ok:
            noc.audit(db(), who, "real.blocked", detail=f"{s.target} [{s.mode}] {safe!r}: {reason}", result="bloqueado")
            return jsonify(allowed=False, reason=reason, needs_confirm=needs), 403
        try:
            s.write_line(command)
        except Exception as e:
            return error(f"No se pudo escribir en el equipo: {e}", 502)
        destructive = bool(consola_real.DESTRUCTIVE.match(command))
        noc.audit(db(), who, "real.command", "devices", (s.device or {}).get("id"),
                  f"{s.target} [{s.mode}] {safe}", "alerta" if destructive else "ok")
        if destructive:
            dev = s.device["name"] if s.device else s.target
            notify_admin(f"⚠️ <b>NOC · Comando destructivo confirmado</b>\n{telegram_noc.esc(who)} ejecutó "
                         f"<code>{telegram_noc.esc(safe)}</code> en <b>{telegram_noc.esc(dev)}</b>.")
        return jsonify(allowed=True, reason=reason)

    @app.post("/api/real/key")
    def real_key():
        data = body()
        if (blocked := human_only(data)):
            return blocked
        s = real_session()
        if not s:
            return error("No hay una sesión abierta", 409)
        key = data.get("key")
        if key == "break":
            s.send_break()
        elif key in consola_real.SPECIAL_KEYS:
            s.write_raw(consola_real.SPECIAL_KEYS[key])
        else:
            return error("Tecla inválida")
        return jsonify(ok=True)

    @app.get("/api/real/read")
    def real_read():
        s = real_session()
        if not s:
            return jsonify(open=False, seq=0, text="")
        seq, text = s.read_since(to_int(request.args.get("since")) or 0)
        return jsonify(open=True, seq=seq, text=text, info=s.info())

    @app.post("/api/real/apply-syslog")
    def real_apply_syslog():
        """Envía al equipo, línea por línea, la configuración Syslog que genera el NOC."""
        data = body()
        if (blocked := human_only(data)):
            return blocked
        s = real_session()
        if not s:
            return error("No hay una sesión abierta", 409)
        if s.mode != "administrador":
            return error("Active el modo administrador para configurar el equipo", 409)
        if data.get("confirm") is not True:
            return error("Confirme que desea aplicar la configuración en el equipo real")
        vendor = (s.device or {}).get("vendor")
        if vendor not in plantillas.GENERATORS:
            return error("Asocie la sesión a un equipo Cisco, Fortinet o Huawei del inventario")
        v, errors = plantillas._validate({**data, "vendor": vendor})
        if errors:
            return error(errors)
        lines = [ln for ln in plantillas.GENERATORS[vendor](v, s.device).splitlines()
                 if ln.strip() and not ln.lstrip().startswith(("!", "#"))]
        import time as _t
        for ln in lines:
            s.write_line(ln)
            _t.sleep(0.25)          # dar tiempo al CLI del equipo
        noc.audit(db(), operator(data), "real.apply_syslog", "devices", s.device["id"],
                  f"{vendor} servidor={v['server_ip']}:{v['port']} sev={v['severity']} lineas={len(lines)}", "alerta")
        notify_admin(f"🛠 <b>NOC · Configuración Syslog aplicada</b>\n{telegram_noc.esc(operator(data))} configuró "
                     f"<b>{telegram_noc.esc(s.device['name'])}</b> para enviar Syslog a "
                     f"<code>{telegram_noc.esc(v['server_ip'])}:{v['port']}</code>.")
        return jsonify(ok=True, lines=len(lines))

    @app.post("/api/real/test")
    def real_test():
        """Prueba de extremo a extremo hacia Telegram.
        via=equipo  -> el equipo real genera el Syslog (requiere que llegue al receptor)
        via=directa -> el NOC registra un evento de prueba con la IP del equipo (alerta inmediata)"""
        data = body()
        if (blocked := human_only(data)):
            return blocked
        sev = to_int(data.get("severity"), 0, 7)
        sev = 2 if sev is None else sev
        text = re.sub(r"[^\w .,:;()/-]", "", str(data.get("text") or "Prueba de alerta desde la consola del NOC"))[:120]
        via = data.get("via")
        if via == "equipo":
            s = real_session()
            if not s:
                return error("Abra la conexión con el equipo para enviar la prueba desde él", 409)
            vendor = (s.device or {}).get("vendor")
            cmds = consola_real.DEVICE_TEST_COMMANDS.get(vendor, lambda *_: [])(sev, text)
            if not cmds:
                return error("Este fabricante no tiene un comando de prueba estándar: use la prueba directa al NOC", 409)
            for c in cmds:
                s.write_line(c)
            noc.audit(db(), operator(data), "real.test", "devices", s.device["id"], f"via=equipo {cmds}")
            return jsonify(via="equipo", commands=cmds,
                           note="El equipo generará el mensaje; llegará a Telegram si su Syslog apunta a este NOC "
                                "y receptor.py está corriendo.")
        if via == "directa":
            device = get_device_row(to_int(data.get("device_id"))) or (
                get_device_row(real_session().device["id"]) if real_session() and real_session().device else None)
            if device is None:
                return error("Elija el equipo del inventario para la prueba")
            import secrets as _sec
            ref = "".join(_sec.choice("abcdefghjkmnpqrstuvwxyz") for _ in range(6))
            from datetime import datetime as _dt
            msg = (f"<{23 * 8 + sev}>{_dt.now():%b %d %H:%M:%S} {device['name']} "
                   f"%NOC-{sev}-PRUEBA: {text} (ref {ref})")
            r = noc.ingest(db(), msg, device["ip"], "importacion")
            noc.audit(db(), operator(data), "real.test", "devices", device["id"], f"via=directa sev={sev} evento={r['id']}")
            return jsonify(via="directa", event_id=r["id"], decision=(r.get("policy") or {}).get("decision"),
                           notification=r.get("notification"), incident=r.get("incident"))
        return error("Elija el tipo de prueba (equipo | directa)")

    @app.errorhandler(413)
    def too_large(_e):
        return error("El archivo supera el máximo permitido (2 MB)", 413)

    return app


def _poller_notify(db_path):
    """Avisos del sondeo periódico: Telegram (si está activo) + historial de notificaciones."""
    def send(text):
        status, detail = "desactivada", "Telegram no configurado"
        if telegram_noc.CONFIG.enabled:
            ok, detail = telegram_noc.send_text(text)
            status = "enviada" if ok else "fallida"
        conn = noc.connect(db_path)
        conn.execute("INSERT INTO notifications (channel, kind, text, status, detail, created_at) "
                     "VALUES ('telegram', 'observabilidad', ?, ?, ?, ?)", (text, status, detail, noc.now_iso()))
        conn.commit()
        conn.close()
    return send


if __name__ == "__main__":
    application = create_app()
    db_path = application.config["DATABASE_PATH"]
    if observabilidad.start_poller(db_path, _poller_notify(db_path)):
        print(f"[NOC] Observabilidad: sondeo de disponibilidad cada {observabilidad.PROBE_SECONDS} s")
    application.run(host="127.0.0.1", port=5000, debug=False)
