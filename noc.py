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
"""
import hashlib
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

import syslog_parser

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
    return any(p.search(text or "") for p in INJECTION_PATTERNS)


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
    if not ev["authorized"] or ev["severity"] > INCIDENT_MAX_SEVERITY:
        return None
    key = f"{ev['device_id']}|{ev['mnemonic'] or ev['fingerprint']}"
    row = conn.execute("SELECT id FROM incidents WHERE correlation_key = ? AND status != 'cerrado'",
                       (key,)).fetchone()
    if row:
        conn.execute("UPDATE incidents SET event_count = event_count + 1, updated_at = ?, "
                     "severity = MIN(severity, ?) WHERE id = ?", (now_iso(), ev["severity"], row["id"]))
        conn.commit()
        return {"id": row["id"], "correlated": True}
    if "posible_prompt_injection" in ev["flags"]:
        title = f"Posible prompt injection en log de {ev['device_name']}"
    else:
        title = f"{ev['mnemonic'] or 'Evento ' + SEVERITY_NAMES[ev['severity']]} en {ev['device_name']}"
    inc_id = create_incident(
        conn, title=title, severity=ev["severity"], created_by="sistema",
        description=f"Generado por la política de severidades (evento #{ev['id']}, "
                    f"severidad {ev['severity']} {SEVERITY_NAMES[ev['severity']]}).",
        device_id=ev["device_id"], event_id=ev["id"], correlation_key=key,
        is_simulated=ev["is_simulated"])
    return {"id": inc_id, "correlated": False}


# ---------------------------------------------------------------------------
# Ingesta
# ---------------------------------------------------------------------------
def ingest(conn, raw: str, source_ip: str, origin: str) -> dict:
    """Procesa y guarda UN mensaje. origin: 'udp' | 'importacion'."""
    p = syslog_parser.parse(raw)
    flags = list(p["parse_flags"])

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
    if prev:
        conn.execute("UPDATE events SET dup_count = dup_count + 1 WHERE id = ?", (prev["id"],))
        conn.commit()
        return {"id": prev["id"], "duplicate": True, "severity": p["severity"],
                "severity_name": p["severity_name"], "vendor": vendor, "flags": flags,
                "message": p["message"], "incident": None}

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

    incident = _auto_incident(conn, {
        "id": event_id, "device_id": dev["id"] if dev else None,
        "device_name": dev["name"] if dev else source_ip, "severity": p["severity"],
        "mnemonic": p["mnemonic"], "fingerprint": fp, "flags": flags,
        "authorized": authorized, "is_simulated": is_simulated})
    return {"id": event_id, "duplicate": False, "severity": p["severity"],
            "severity_name": p["severity_name"], "vendor": vendor, "flags": flags,
            "message": p["message"], "incident": incident}


def import_lines(conn, lines, source_ip: str, actor: str, filename: str = "") -> dict:
    """Importa un archivo de log: una línea = un mensaje. Ignora vacías y comentarios (#)."""
    stats = {"leidas": 0, "nuevas": 0, "duplicadas": 0, "incidentes_nuevos": 0}
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
    audit(conn, actor, "syslog.import", "events", None, f"archivo={filename or '-'} origen={source_ip} {stats}")
    return stats
