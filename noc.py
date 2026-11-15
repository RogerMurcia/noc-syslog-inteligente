"""
Núcleo del NOC: configuración, base de datos, auditoría e ingesta de eventos.

Lo usan la aplicación web (app.py), el receptor UDP (receptor.py) y las pruebas.

Camino de cada mensaje Syslog (función ingest):

    mensaje crudo
      1. parse()                      -> facility, severidad, fabricante, mensaje
      2. ¿IP en el inventario?        -> asocia el equipo
      3. ¿Equipo autorizado?          -> lista permitida de fuentes
      4. ¿Texto tipo prompt injection?-> se MARCA (nunca se ejecuta nada)
      5. ¿Repetido en 60 s?           -> deduplicación (suma al contador)
      6. Se guarda en la tabla events
      7. Severidad 0-3 de fuente autorizada -> incidente (o se suma al abierto)

v1.0.0 - MOTOR DE POLÍTICAS ANTES DE LA IA (security/policy_engine.py):
      P02. Los secretos se REDACTAN antes de guardar el evento (se guarda el hash del original)
      8. evaluate() -> ALLOW / REVIEW / BLOCK + políticas + evidencia -> tabla policy_decisions (P05)
      9. Asistente de IA de SOLO LECTURA (asistente_ia.py): no se invoca si la decisión es BLOCK
     10. Alerta a Telegram (telegram_noc.py) para BLOCK, REVIEW crítico e incidentes nuevos
"""
import hashlib
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

import syslog_parser
from security import policy_engine

# ---------------------------------------------------------------------------
# Configuración (.env; nunca se escriben secretos en el código)
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

_db = Path(os.getenv("DATABASE_PATH", "data/noc.db"))
DB_PATH = _db if _db.is_absolute() else BASE_DIR / _db
SYSLOG_HOST = os.getenv("SYSLOG_HOST", "127.0.0.1")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "5514"))
DEFAULT_OPERATOR = os.getenv("DEFAULT_OPERATOR", "operador_noc")
LOCAL_UTC_OFFSET = int(os.getenv("LOCAL_UTC_OFFSET", "-5"))   # Colombia = UTC-5

SEVERITY_NAMES = ["Emergency", "Alert", "Critical", "Error",
                  "Warning", "Notice", "Informational", "Debug"]
INCIDENT_MAX_SEVERITY = 3     # Política: severidades 0-3 generan incidente
DEDUP_WINDOW_SECONDS = 60
MAX_IMPORT_LINES = 5000

# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------
def now_iso() -> str:
    """Fecha y hora actual en UTC (ISO 8601)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_ago(seconds: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(db_path=DB_PATH) -> sqlite3.Connection:
    """Conexión SQLite con filas tipo diccionario y claves foráneas activas."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn, seed: bool = True):
    """Crea las tablas (si no existen) y, si el inventario está vacío, carga los equipos simulados."""
    conn.executescript((BASE_DIR / "schema.sql").read_text(encoding="utf-8"))
    if seed and conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0:
        seed_devices(conn)
    conn.commit()


def audit(conn, actor, action, entity=None, entity_id=None, detail=None, result="ok"):
    """Registra una acción en la auditoría (solo inserción)."""
    conn.execute("INSERT INTO audit_log (ts, actor, action, entity, entity_id, detail, result) "
                 "VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (now_iso(), actor, action, entity, entity_id, detail, result))
    conn.commit()


# ---------------------------------------------------------------------------
# Datos SIMULADOS. IP de documentación (RFC 5737): no existen en Internet.
# 127.0.0.1 = el simulador que corre en este mismo PC.
# ---------------------------------------------------------------------------
SIMULATED_DEVICES = [
    # nombre,          ip,              marca,      modelo,          versión,         ubicación,               estado,        autorizado
    ("SIM-CORE-RTR01", "192.0.2.1",     "Cisco",    "ISR 4331",      "IOS-XE 17.9.4", "Sede Bogotá - Rack A",  "activo",      1),
    ("SIM-DIST-SW01",  "192.0.2.10",    "Cisco",    "Catalyst 9300", "IOS-XE 17.9.4", "Sede Bogotá - Piso 2",  "activo",      1),
    ("SIM-EDGE-FW01",  "198.51.100.1",  "Fortinet", "FortiGate 60F", "FortiOS 7.4.3", "Sede Bogotá - DMZ",     "alerta",      1),
    ("SIM-BR-RTR02",   "198.51.100.20", "Huawei",   "AR6120",        "VRP V300R022",  "Sede Medellín",         "activo",      1),
    ("SIM-BR-SW02",    "203.0.113.5",   "Huawei",   "S5735-L",       "VRP V200R022",  "Sede Cali",             "caido",       1),
    ("SIM-LAB-AP01",   "203.0.113.99",  "Otro",     "AP genérico",   "1.0",           "Laboratorio",           "desconocido", 0),
    ("SIM-GEN-LOCAL",  "127.0.0.1",     "Otro",     "Simulador",     "simulador.py",  "Este PC (pruebas)",     "activo",      1),
]


def seed_devices(conn) -> int:
    ts = now_iso()
    for row in SIMULATED_DEVICES:
        conn.execute("INSERT OR IGNORE INTO devices (name, ip, vendor, model, version, location, "
                     "status, authorized, is_simulated, created_at, updated_at) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)", (*row, ts, ts))
    conn.commit()
    audit(conn, "sistema", "seed.devices", "devices", None,
          f"{len(SIMULATED_DEVICES)} equipos SIMULADOS cargados")
    return len(SIMULATED_DEVICES)


# ---------------------------------------------------------------------------
# Controles de seguridad sobre los logs
# ---------------------------------------------------------------------------
# Frases típicas de un intento de manipular a un asistente de IA que lea los
# logs (prompt injection). Detección heurística: solo MARCA, no bloquea.
INJECTION_PATTERNS = [re.compile(p, re.I) for p in (
    r"ignor\w*\s+(?:\w+\s+){0,3}(?:reglas|instrucciones|instructions|rules|pol[ií]ticas)",
    r"\b(?:you are now|ahora eres|act[uú]a como|act as)\b",
    r"\b(?:system prompt|prompt del sistema|developer mode|modo desarrollador)\b",
    r"\b(?:ejecuta|ejecutar|execute|run)\s+(?:el\s+|the\s+|este\s+)?(?:comando|command)",
    r"\b(?:sin (?:aprobaci[oó]n|autorizaci[oó]n)|without (?:approval|authorization))\b",
)]


def detect_prompt_injection(text: str) -> bool:
    """Heurística básica (v0.2) + patrones del motor de políticas (P06)."""
    return any(p.search(text or "") for p in INJECTION_PATTERNS) or bool(policy_engine.detect_injection(text))


AUTH_WINDOW_SECONDS = 300      # ventana para correlacionar fallos de autenticación (fuerza bruta)


def auth_failures(conn, source_ip: str) -> int:
    """Fallos de autenticación del mismo origen en la ventana (incluye repeticiones deduplicadas)."""
    rows = conn.execute("SELECT mnemonic, message, dup_count FROM events WHERE source_ip = ? AND received_at >= ? "
                        "ORDER BY id DESC LIMIT 500", (source_ip, iso_ago(AUTH_WINDOW_SECONDS))).fetchall()
    return sum(r["dup_count"] for r in rows
               if policy_engine.AUTH_FAIL.search(r["mnemonic"] or "") or policy_engine.AUTH_FAIL.search(r["message"]))


def fingerprint(source_ip, severity, mnemonic, message) -> str:
    """Huella para deduplicar: los números se cambian por '#' (puerto 1 = puerto 2)."""
    normalized = re.sub(r"\d+", "#", (message or "").lower()).strip()
    return hashlib.sha256(f"{source_ip}|{severity}|{mnemonic or ''}|{normalized}".encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Incidentes
# ---------------------------------------------------------------------------
def create_incident(conn, *, title, severity, created_by, description=None, device_id=None,
                    event_id=None, correlation_key=None, is_simulated=False) -> int:
    ts = now_iso()
    cur = conn.execute(
        "INSERT INTO incidents (title, description, severity, device_id, event_id, correlation_key, "
        "created_by, created_at, updated_at, is_simulated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (title, description, severity, device_id, event_id, correlation_key,
         created_by, ts, ts, int(is_simulated)))
    conn.execute("INSERT INTO incident_notes (incident_id, author, note, created_at) VALUES (?, ?, ?, ?)",
                 (cur.lastrowid, created_by, "Incidente creado", ts))
    conn.commit()
    audit(conn, created_by, "incident.create", "incidents", cur.lastrowid, f"sev={severity} {title}")
    return cur.lastrowid


def _auto_incident(conn, ev: dict):
    """
    Política: severidad 0-3 de una fuente AUTORIZADA -> incidente.
    Si ya hay uno abierto del mismo equipo y mismo código, se suma a ese (correlación).
    El título lo arma el sistema con datos estructurados; NUNCA copia el texto del log.
    """
    forced = ev.get("force_reason")          # v1.0: BLOCK o fuerza bruta también abren incidente
    if not ev["authorized"] or (ev["severity"] > INCIDENT_MAX_SEVERITY and not forced):
        return None
    key = f"{ev['device_id']}|{ev.get('correlation') or ev['mnemonic'] or ev['fingerprint']}"
    row = conn.execute("SELECT id FROM incidents WHERE correlation_key = ? AND status != 'cerrado'",
                       (key,)).fetchone()
    if row:
        conn.execute("UPDATE incidents SET event_count = event_count + 1, updated_at = ?, "
                     "severity = MIN(severity, ?) WHERE id = ?", (now_iso(), ev["severity"], row["id"]))
        conn.commit()
        return {"id": row["id"], "correlated": True}
    if "posible_prompt_injection" in ev["flags"]:
        title = f"Posible prompt injection en log de {ev['device_name']}"
    elif forced == "fuerza_bruta":
        title = f"Posible fuerza bruta contra {ev['device_name']}"
    else:
        title = f"{ev['mnemonic'] or 'Evento ' + SEVERITY_NAMES[ev['severity']]} en {ev['device_name']}"
    inc_id = create_incident(
        conn, title=title, severity=ev["severity"], created_by="sistema",
        description=f"Generado por el motor de políticas (evento #{ev['id']}, severidad {ev['severity']} "
                    f"{SEVERITY_NAMES[ev['severity']]}, decisión {ev.get('decision', '-')}, "
                    f"políticas {ev.get('policies', '-')}).",
        device_id=ev["device_id"], event_id=ev["id"], correlation_key=key,
        is_simulated=ev["is_simulated"])
    return {"id": inc_id, "correlated": False}


# ---------------------------------------------------------------------------
# Ingesta
# ---------------------------------------------------------------------------
def ingest(conn, raw: str, source_ip: str, origin: str, notify: bool = True) -> dict:
    """Procesa y guarda UN mensaje. origin: 'udp' | 'importacion'."""
    p = syslog_parser.parse(raw)
    flags = list(p["parse_flags"])
    original_raw = raw
    # P02: los secretos se ocultan ANTES de guardar o mostrar nada
    p["message"], secrets_msg = policy_engine.redact(p["message"])
    raw, secrets_raw = policy_engine.redact(raw)
    if secrets_msg or secrets_raw:
        flags.append("secretos_redactados")

    # La IP de ORIGEN del paquete identifica al equipo; el nombre que trae
    # el texto no se usa porque cualquiera puede escribir cualquier nombre.
    dev = conn.execute("SELECT id, name, vendor, authorized, is_simulated FROM devices WHERE ip = ?",
                       (source_ip,)).fetchone()
    authorized = bool(dev and dev["authorized"])
    if dev is None:
        flags.append("equipo_desconocido")
    if not authorized:
        flags.append("fuente_no_autorizada")
    vendor = dev["vendor"] if dev and dev["vendor"] != "Otro" else (p["vendor_hint"] or "Desconocido")
    is_simulated = bool(dev and dev["is_simulated"])

    if detect_prompt_injection(p["message"]):
        flags.append("posible_prompt_injection")

    # Deduplicación: mismo mensaje en los últimos 60 s -> solo se suma al contador
    fp = fingerprint(source_ip, p["severity"], p["mnemonic"], p["message"])
    prev = conn.execute("SELECT id, dup_count FROM events WHERE fingerprint = ? AND received_at >= ? "
                        "ORDER BY id DESC LIMIT 1", (fp, iso_ago(DEDUP_WINDOW_SECONDS))).fetchone()
    ctx = {"p": p, "original_raw": original_raw, "source_ip": source_ip, "dev": dev, "authorized": authorized,
           "vendor": vendor, "is_simulated": is_simulated, "flags": flags, "notify": notify}
    if prev:
        conn.execute("UPDATE events SET dup_count = dup_count + 1 WHERE id = ?", (prev["id"],))
        conn.commit()
        result = {"id": prev["id"], "duplicate": True, "severity": p["severity"],
                  "severity_name": p["severity_name"], "vendor": vendor, "flags": flags,
                  "message": p["message"], "incident": None}
        # Los fallos de acceso idénticos se deduplican, pero SIGUEN contando para la fuerza bruta:
        # al cruzar el umbral se evalúa de nuevo para abrir el incidente y avisar a Telegram.
        is_auth = (policy_engine.AUTH_FAIL.search(p["mnemonic"] or "")
                   or policy_engine.AUTH_FAIL.search(p["message"]))
        if is_auth and auth_failures(conn, source_ip) == policy_engine.BRUTE_FORCE_THRESHOLD:
            result.update(_apply_policies(conn, prev["id"], fp, ctx))
        return result

    cur = conn.execute(
        "INSERT INTO events (received_at, event_time, source_ip, device_id, vendor, facility, severity, "
        "hostname, app_name, mnemonic, message, raw, origin, authorized_source, flags, fingerprint, "
        "is_simulated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (now_iso(), p["event_time"], source_ip, dev["id"] if dev else None, vendor, p["facility"],
         p["severity"], p["hostname"], p["app_name"], p["mnemonic"], p["message"], raw[:4000],
         origin, int(authorized), ",".join(flags) or None, fp, int(is_simulated)))
    conn.commit()
    event_id = cur.lastrowid

    suspicious = [f for f in flags if f in ("fuente_no_autorizada", "posible_prompt_injection")]
    if suspicious:
        audit(conn, "sistema", "syslog.sospechoso", "events", event_id,
              f"origen={source_ip} marcas={','.join(suspicious)}", "alerta")

    result = {"id": event_id, "duplicate": False, "severity": p["severity"],
              "severity_name": p["severity_name"], "vendor": vendor, "flags": flags, "message": p["message"]}
    result.update(_apply_policies(conn, event_id, fp, ctx))
    return result


def _apply_policies(conn, event_id: int, fp: str, ctx: dict) -> dict:
    """Motor de políticas -> incidente -> asistente IA (solo lectura) -> Telegram."""
    p, dev, source_ip = ctx["p"], ctx["dev"], ctx["source_ip"]
    failures = auth_failures(conn, source_ip)
    decision = policy_engine.evaluate(
        {"message": p["message"], "raw": ctx["original_raw"], "severity": p["severity"],
         "authorized": ctx["authorized"], "flags": ctx["flags"], "mnemonic": p["mnemonic"], "source_ip": source_ip},
        context={"auth_failures": failures})
    decision_id = record_decision(conn, event_id, decision)
    reasons = " ".join(decision["reasons"])
    force = ("bloqueo_ia" if decision["decision"] == "BLOCK"
             else "fuerza_bruta" if "fuerza bruta" in reasons else None)

    device_name = dev["name"] if dev else source_ip
    incident = _auto_incident(conn, {
        "id": event_id, "device_id": dev["id"] if dev else None,
        "device_name": device_name, "severity": p["severity"],
        "mnemonic": p["mnemonic"], "fingerprint": fp, "flags": ctx["flags"],
        "authorized": ctx["authorized"], "is_simulated": ctx["is_simulated"],
        "force_reason": force, "correlation": "FUERZA_BRUTA" if force == "fuerza_bruta" else None,
        "decision": decision["decision"], "policies": ",".join(decision["policies"])})

    import asistente_ia      # import tardío: evita importaciones circulares
    import telegram_noc
    ev = {"id": event_id, "severity": p["severity"], "vendor": ctx["vendor"], "mnemonic": p["mnemonic"],
          "message": p["message"], "device_name": device_name, "source_ip": source_ip}
    try:
        analysis = asistente_ia.analyze(ev, decision)
    except Exception as e:      # falla segura: si la IA falla, las reglas ya decidieron
        analysis = {"invocada": False, "titulo": "Asistente no disponible", "riesgo": "-",
                    "soluciones": [], "verificacion": [], "error": type(e).__name__}
        audit(conn, "sistema", "ia.error", "events", event_id, type(e).__name__, "error")
    notification = (telegram_noc.notify(conn, ev, decision, analysis, incident, now_iso)
                    if ctx["notify"] else None)
    return {"incident": incident, "notification": notification,
            "policy": {"id": decision_id, "decision": decision["decision"], "policies": decision["policies"],
                       "reasons": decision["reasons"], "ai_invoked": decision["ai_invoked"]}}


def record_decision(conn, event_id, decision: dict) -> int:
    """P05: guarda la decisión del motor y la deja en la auditoría."""
    cur = conn.execute(
        "INSERT INTO policy_decisions (event_id, decision, policies, reasons, evidence, secrets, injection, "
        "ai_invoked, event_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (event_id, decision["decision"], ",".join(decision["policies"]), " | ".join(decision["reasons"]),
         " | ".join(decision["evidence"]), ",".join(decision["secrets"]) or None,
         ",".join(decision["injection"]) or None, int(decision["ai_invoked"]), decision["event_hash"], now_iso()))
    conn.commit()
    result = {"ALLOW": "ok", "REVIEW": "alerta", "BLOCK": "bloqueado"}[decision["decision"]]
    audit(conn, "motor_politicas", "policy.decision", "events", event_id,
          f"{decision['decision']} políticas={','.join(decision['policies'])} hash={decision['event_hash'][:16]}",
          result)
    return cur.lastrowid


def import_lines(conn, lines, source_ip: str, actor: str, filename: str = "") -> dict:
    """Importa un archivo de log: una línea = un mensaje. Ignora vacías y comentarios (#)."""
    stats = {"leidas": 0, "nuevas": 0, "duplicadas": 0, "incidentes_nuevos": 0,
             "allow": 0, "review": 0, "block": 0}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if stats["leidas"] >= MAX_IMPORT_LINES:
            break
        stats["leidas"] += 1
        r = ingest(conn, line, source_ip, "importacion")
        stats["duplicadas" if r["duplicate"] else "nuevas"] += 1
        if r["incident"] and not r["incident"]["correlated"]:
            stats["incidentes_nuevos"] += 1
        if r.get("policy"):
            stats[r["policy"]["decision"].lower()] += 1
    audit(conn, actor, "syslog.import", "events", None, f"archivo={filename or '-'} origen={source_ip} {stats}")
    return stats
