"""
Usuarios, contraseñas y roles del NOC.

- Las contraseñas se guardan solo como hash con sal (Werkzeug: scrypt/pbkdf2); nunca en claro.
- Tres roles:
    administrador  todo, incluida la gestión de usuarios, el inventario y el modo administrador de la consola real
    operador       opera el NOC (eventos, incidentes, acciones, revisiones, consola en solo lectura); no administra
    monitoreo      solo lectura: ve paneles, eventos, incidentes y auditoría; no cambia nada
- Protección de fuerza bruta: 5 intentos fallidos bloquean la cuenta 5 minutos (y se audita).
- Si la base de datos no tiene usuarios, se crean las tres cuentas de demostración documentadas
  en el README y en el Manual de usuario. El administrador puede cambiar sus contraseñas desde la web.
- Doble factor TOTP (RFC 6238, módulo totp.py): opcional por usuario; la cuenta admin de demostración
  lo trae activado con un secreto y códigos de recuperación documentados, para que el docente pueda ingresar.
"""
import json
import os
import re
from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash

import totp

ROLES = {
    "administrador": "Administrador",
    "operador": "Operador",
    "monitoreo": "Monitoreo (solo lectura)",
}
MAX_FAILED = 5                    # intentos antes del bloqueo
LOCK_MINUTES = 5                  # duración del bloqueo
RE_USERNAME = re.compile(r"^[a-z0-9._-]{3,32}$")

# Cuentas de demostración (se crean solo si no existe ningún usuario).
# Las contraseñas pueden cambiarse antes del primer inicio con variables del .env.
DEMO_USERS = [
    ("admin", "Roger Fabian Murcia Fino", "administrador", "NOC_ADMIN_PASSWORD", "Admin.NOC2026"),
    ("operador", "Operador de turno NOC", "operador", "NOC_OPERADOR_PASSWORD", "Operador.NOC2026"),
    ("monitoreo", "Monitoreo y auditoría", "monitoreo", "NOC_MONITOREO_PASSWORD", "Monitoreo.NOC2026"),
]

# Doble factor de la cuenta admin de DEMOSTRACIÓN (documentado en el README con su código QR).
# Cualquier usuario puede activar el suyo propio desde «Mi cuenta»; el administrador puede reiniciarlo.
DEMO_ADMIN_TOTP_SECRET = "R4PWXMW3OGAM3BS6TE4232EKSNMBREEI"
DEMO_ADMIN_RECOVERY = ["y32x-hzgs", "smpy-rz66", "tvx7-6ndb", "za8c-ek8g",
                       "cc5e-hev7", "z3mf-c6cf", "yn4g-abut", "cbmk-xtgr"]
MFA_COLUMNS = {"totp_secret": "TEXT", "totp_enabled": "INTEGER NOT NULL DEFAULT 0",
               "totp_last_counter": "INTEGER", "recovery_codes": "TEXT"}

# Endpoints (nombre de la función en app.py) por rol. Los GET son lectura y se permiten a todos,
# salvo los marcados como solo administrador.
ADMIN_ONLY = {"create_device", "update_device", "delete_device", "real_apply_syslog",
              "list_users", "create_user", "update_user", "set_dependencies"}
READ_ONLY_ALLOWED_POST = {"policies_evaluate", "change_password", "logout",
                          "mfa_setup", "mfa_enable", "mfa_disable"}


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def password_problems(pw: str) -> list[str]:
    """Política de contraseñas: mínimo 8 caracteres, con letras y números."""
    errors = []
    if len(pw or "") < 8:
        errors.append("La contraseña debe tener al menos 8 caracteres")
    if not re.search(r"[A-Za-z]", pw or "") or not re.search(r"\d", pw or ""):
        errors.append("La contraseña debe combinar letras y números")
    if len(pw or "") > 128:
        errors.append("La contraseña es demasiado larga")
    return errors


def hash_password(pw: str) -> str:
    return generate_password_hash(pw)


def hash_recovery(codes: list[str]) -> str:
    """Hash con sal de cada código de recuperación (PBKDF2-SHA256; los códigos tienen ~40 bits de azar)."""
    return json.dumps([generate_password_hash(c.strip().lower(), method="pbkdf2:sha256:30000") for c in codes])


def _enable_demo_mfa(conn, user_id: int):
    secret = os.getenv("NOC_ADMIN_TOTP_SECRET") or DEMO_ADMIN_TOTP_SECRET
    conn.execute("UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_last_counter = NULL, recovery_codes = ? "
                 "WHERE id = ?", (secret, hash_recovery(DEMO_ADMIN_RECOVERY), user_id))


def migrate(conn) -> list[str]:
    """Agrega las columnas del doble factor a una tabla users creada por una versión anterior.
    Si la cuenta admin aún tiene la contraseña de demostración, recibe el doble factor de demostración."""
    have = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
    added = [c for c in MFA_COLUMNS if c not in have]
    for col in added:
        conn.execute(f"ALTER TABLE users ADD COLUMN {col} {MFA_COLUMNS[col]}")
    if added:
        admin = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
        if admin and check_password_hash(admin["password_hash"], os.getenv("NOC_ADMIN_PASSWORD") or "Admin.NOC2026"):
            _enable_demo_mfa(conn, admin["id"])
    conn.commit()
    return added


def seed_users(conn) -> bool:
    """Crea las cuentas de demostración si la tabla está vacía. Devuelve True si las creó."""
    migrate(conn)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        return False
    now = _iso(_now())
    for username, full_name, role, env, default in DEMO_USERS:
        pw = os.getenv(env) or default
        cur = conn.execute("INSERT INTO users (username, full_name, role, password_hash, created_at, updated_at) "
                           "VALUES (?, ?, ?, ?, ?, ?)", (username, full_name, role, hash_password(pw), now, now))
        if username == "admin" and os.getenv("NOC_ADMIN_MFA", "1") != "0":
            _enable_demo_mfa(conn, cur.lastrowid)
    conn.commit()
    return True


def check_second_factor(conn, user, code: str):
    """Valida un código TOTP o un código de recuperación. Devuelve (True|False, 'totp'|'recuperacion'|motivo)."""
    code = (code or "").strip()
    if code.replace(" ", "").isdigit():
        c = totp.verify(user["totp_secret"], code, user["totp_last_counter"])
        if c is None:
            return False, "Código de verificación incorrecto o vencido"
        conn.execute("UPDATE users SET totp_last_counter = ? WHERE id = ?", (c, user["id"]))
        conn.commit()
        return True, "totp"
    hashes = json.loads(user["recovery_codes"] or "[]")
    for i, h in enumerate(hashes):
        if check_password_hash(h, code.lower()):
            hashes.pop(i)                     # un solo uso
            conn.execute("UPDATE users SET recovery_codes = ? WHERE id = ?", (json.dumps(hashes), user["id"]))
            conn.commit()
            return True, "recuperacion"
    return False, "Código de verificación incorrecto o vencido"


def register_failure(conn, user) -> bool:
    """Cuenta un intento fallido (contraseña o segundo factor). Devuelve True si la cuenta quedó bloqueada."""
    fails = user["failed_attempts"] + 1
    locked = _iso(_now() + timedelta(minutes=LOCK_MINUTES)) if fails >= MAX_FAILED else None
    conn.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                 (0 if locked else fails, locked, user["id"]))
    conn.commit()
    return bool(locked)


def public(user) -> dict:
    """Datos del usuario que se pueden mostrar (nunca el hash)."""
    if user is None:
        return None
    u = dict(user)
    out = {k: u.get(k) for k in ("id", "username", "full_name", "role", "active", "last_login",
                                 "locked_until", "failed_attempts", "created_at")}
    out["role_name"] = ROLES.get(u["role"])
    out["mfa"] = bool(u.get("totp_enabled"))
    out["recovery_left"] = len(json.loads(u.get("recovery_codes") or "[]")) if u.get("totp_enabled") else 0
    return out


def authenticate(conn, username: str, password: str):
    """Valida usuario y contraseña. Devuelve (usuario | None, mensaje, evento_de_auditoria).

    El mensaje de error es el mismo si el usuario no existe o la contraseña es incorrecta,
    para no revelar qué cuentas existen."""
    generic = "Usuario o contraseña incorrectos"
    username = (username or "").strip().lower()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        check_password_hash(hash_password("x"), password or "")      # tiempo similar al caso real
        return None, generic, "login.fail"
    now = _now()
    if user["locked_until"] and user["locked_until"] > _iso(now):
        return None, f"Cuenta bloqueada temporalmente por intentos fallidos. Intente después de {LOCK_MINUTES} minutos.", "login.locked"
    if not user["active"]:
        return None, "La cuenta está desactivada. Contacte al administrador.", "login.inactive"
    if not check_password_hash(user["password_hash"], password or ""):
        if register_failure(conn, user):
            return None, f"Demasiados intentos fallidos: la cuenta queda bloqueada {LOCK_MINUTES} minutos.", "login.lock"
        return None, generic, "login.fail"
    return user, "ok", "login.password_ok"


def complete_login(conn, user):
    """Paso final del ingreso (tras la contraseña y, si aplica, el segundo factor)."""
    conn.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
                 (_iso(_now()), user["id"]))
    conn.commit()
    return conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()


def authorize(role: str, method: str, endpoint: str | None) -> str | None:
    """Devuelve None si el rol puede usar el endpoint, o el motivo del rechazo."""
    if endpoint in ADMIN_ONLY and role != "administrador":
        return "Solo un administrador puede hacer esto"
    if method in ("GET", "HEAD", "OPTIONS"):
        return None
    if role == "monitoreo" and endpoint not in READ_ONLY_ALLOWED_POST:
        return "Su rol (monitoreo) es de solo lectura"
    return None
