"""
Parser de mensajes Syslog (RFC 3164, RFC 5424 y formatos de Cisco, Fortinet y Huawei).

Recibe el texto CRUDO de un mensaje y devuelve un diccionario con sus partes:
facility, severidad, fecha, equipo, aplicación, mensaje y fabricante detectado.

IMPORTANTE (seguridad): este módulo solo LEE y CLASIFICA texto. Nunca ejecuta
ni interpreta el contenido del mensaje como una orden. El mensaje es un dato
no confiable que puede venir de cualquiera.

Estructura de un mensaje Syslog:

    <PRI>  CABECERA                    MENSAJE
    <187>  Oct  5 18:00:00 RTR01       %LINK-3-UPDOWN: Interface Gi0/1, changed state to down

    PRI = facility * 8 + severidad      ->  187 = 23 * 8 + 3
    facility  = PRI // 8  (división entera)  -> 23 = local7
    severidad = PRI %  8  (resto)            ->  3 = Error
"""
import re

# ---------------------------------------------------------------------------
# Catálogos (RFC 5424, sección 6.2.1)
# ---------------------------------------------------------------------------
FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "security", "console", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]
SEVERITY_NAMES = [
    "Emergency", "Alert", "Critical", "Error",
    "Warning", "Notice", "Informational", "Debug",
]

# Fortinet escribe la severidad como palabra en el campo level=
FORTINET_LEVELS = {
    "emergency": 0, "alert": 1, "critical": 2, "error": 3,
    "warning": 4, "notice": 5, "information": 6, "debug": 7,
}

MAX_MESSAGE_LEN = 2000  # límite de longitud: evita mensajes gigantes en la BD

# ---------------------------------------------------------------------------
# Expresiones regulares
# ---------------------------------------------------------------------------
# <PRI> al inicio: 1 a 3 dígitos entre < >
RE_PRI = re.compile(r"^<(\d{1,3})>(.*)$", re.S)

# RFC 5424:  1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
RE_5424 = re.compile(
    r"^1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<proc>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|(?:\[.*?\])+)\s?(?P<msg>.*)$", re.S)

# RFC 3164:  [seq: ][*]Mmm dd [yyyy] hh:mm:ss[.ms] [TZ][:] RESTO
#   - Cisco antepone un número de secuencia ("45: ") y a veces "*"
#   - Huawei incluye el año ("Oct 5 2026 18:00:00")
RE_3164_TS = re.compile(
    r"^(?:\d+:\s*)?\*?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    r"(?:\s+[A-Z]{3,4})?:?\s+(?P<rest>.*)$", re.S)

# Cisco IOS:  %FACILITY-SEVERIDAD-MNEMONICO: texto      ej. %LINK-3-UPDOWN:
RE_CISCO = re.compile(r"%(?P<fac>[A-Z][A-Z0-9_]*)-(?P<sev>[0-7])-(?P<mn>[A-Z0-9_]+)\s*:\s*(?P<msg>.*)", re.S)

# Huawei VRP:  %%01MODULO/SEVERIDAD/NOMBRE(tipo)[n]: texto   ej. %%01SHELL/5/CMDRECORD(s):
RE_HUAWEI = re.compile(
    r"%%\d{2}(?P<mod>[A-Z0-9_]+)/(?P<sev>[0-7])/(?P<mn>[A-Za-z0-9_]+)(?:\([a-z]\))?(?:\[\d+\])?:\s*(?P<msg>.*)", re.S)

# Fortinet FortiOS: pares clave=valor, siempre trae logid=
RE_FORTI_DETECT = re.compile(r'\blogid="?\d+')
RE_KV = re.compile(r'(\w+)=("([^"]*)"|\S+)')

# TAG de aplicación RFC 3164: palabra seguida opcionalmente de [pid] y ":"
RE_TAG = re.compile(r"^(?P<tag>[A-Za-z][\w.\-/]{0,47})(?:\[\d+\])?:\s")

# Caracteres de control (incluye saltos de línea; se conserva solo el tabulador). Se eliminan para que un mensaje no
# pueda "romper" la pantalla o falsificar líneas de log (log injection).
RE_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def sanitize(text: str) -> tuple[str, bool]:
    """Quita caracteres de control y recorta. Devuelve (texto, fue_recortado)."""
    clean = RE_CONTROL.sub(" ", text).strip()
    if len(clean) > MAX_MESSAGE_LEN:
        return clean[:MAX_MESSAGE_LEN] + " [...]", True
    return clean, False


def _detect_vendor(result: dict, text: str):
    """Busca la firma de Cisco, Huawei o Fortinet dentro del texto."""
    m = RE_HUAWEI.search(text)  # se revisa antes que Cisco: "%%" también contiene "%"
    if m:
        result.update(vendor_hint="Huawei", vendor_severity=int(m["sev"]),
                      mnemonic=f'{m["mod"]}/{m["sev"]}/{m["mn"]}', message=m["msg"])
        return
    m = RE_CISCO.search(text)
    if m:
        result.update(vendor_hint="Cisco", vendor_severity=int(m["sev"]),
                      mnemonic=f'{m["fac"]}-{m["sev"]}-{m["mn"]}', message=m["msg"])
        return
    if RE_FORTI_DETECT.search(text):
        kv = {k: (quoted if quoted is not None and val.startswith('"') else val)
              for k, val, quoted in RE_KV.findall(text)}
        level = kv.get("level", "").lower()
        result.update(
            vendor_hint="Fortinet",
            vendor_severity=FORTINET_LEVELS.get(level),
            mnemonic=f'logid={kv.get("logid")}',
            hostname=kv.get("devname") or result.get("hostname"),
            app_name="/".join(x for x in (kv.get("type"), kv.get("subtype")) if x) or result.get("app_name"),
            message=kv.get("msg") or kv.get("logdesc") or text,
        )
        if kv.get("date") and kv.get("time"):
            result["event_time"] = f'{kv["date"]} {kv["time"]}'


def parse(raw: str) -> dict:
    """
    Analiza un mensaje Syslog crudo.

    Devuelve un diccionario con: pri, facility, facility_name, severity,
    severity_name, format, event_time, hostname, app_name, message, mnemonic,
    vendor_hint, vendor_severity y parse_flags (lista de observaciones).
    """
    text = raw.strip("\r\n\x00 ")
    result = {
        "pri": None, "facility": None, "severity": None, "format": "desconocido",
        "event_time": None, "hostname": None, "app_name": None, "message": text,
        "mnemonic": None, "vendor_hint": None, "vendor_severity": None,
        "parse_flags": [],
    }

    # 1) PRI -> facility y severidad
    m = RE_PRI.match(text)
    rest = text
    if m and int(m.group(1)) <= 191:          # 191 = 23*8+7, el máximo válido
        pri = int(m.group(1))
        result.update(pri=pri, facility=pri // 8, severity=pri % 8)
        rest = m.group(2)
    else:
        result["parse_flags"].append("sin_pri")

    # 2) Cabecera: RFC 5424, RFC 3164 o ninguna
    m5424 = RE_5424.match(rest)
    m3164 = RE_3164_TS.match(rest)
    if m5424:
        result["format"] = "rfc5424"
        nil = lambda v: None if v == "-" else v   # en 5424 "-" significa vacío
        result.update(event_time=nil(m5424["ts"]), hostname=nil(m5424["host"]),
                      app_name=nil(m5424["app"]), message=m5424["msg"])
    elif m3164:
        result["format"] = "rfc3164"
        result["event_time"] = re.sub(r"\s+", " ", m3164["ts"])
        body = m3164["rest"]
        # Si la primera palabra no es una firma de fabricante ni clave=valor,
        # es el nombre del equipo (HOSTNAME).
        first, _, remainder = body.partition(" ")
        if remainder and not first.startswith("%") and "=" not in first:
            result["hostname"] = first.rstrip(":")
            body = remainder
        # TAG de la aplicación al estilo RFC 3164: "sshd[123]: texto"
        mtag = RE_TAG.match(body)
        if mtag:
            result["app_name"] = mtag["tag"]
        result["message"] = body
    elif result["pri"] is not None:
        result["format"] = "solo_pri"
        result["message"] = rest

    # 3) Firma del fabricante (Cisco / Huawei / Fortinet)
    _detect_vendor(result, rest)
    if result["vendor_hint"] == "Fortinet" and result["format"] in ("solo_pri", "desconocido"):
        result["format"] = "clave_valor"
    if result["vendor_hint"] in ("Cisco", "Huawei"):
        result["app_name"] = result["app_name"] or result["mnemonic"].split("-")[0].split("/")[0]

    # Integridad: la severidad del PRI y la del fabricante deberían coincidir.
    # Si no coinciden, el mensaje pudo ser alterado o el equipo está mal configurado.
    if (result["pri"] is not None and result["vendor_severity"] is not None
            and result["vendor_severity"] != result["severity"]):
        result["parse_flags"].append("severidad_inconsistente")

    # 4) Severidad final: manda el PRI; si no hay PRI se usa la del fabricante;
    #    si tampoco existe, se asume 6 (Informational).
    if result["severity"] is None:
        if result["vendor_severity"] is not None:
            result["severity"] = result["vendor_severity"]
        else:
            result["severity"] = 6
            result["parse_flags"].append("severidad_asumida")
    if result["facility"] is None:
        result["facility"] = 1  # "user", valor por defecto de la RFC 3164

    # 5) Limpieza del mensaje (caracteres de control y longitud)
    result["message"], truncated = sanitize(result["message"] or "")
    if truncated:
        result["parse_flags"].append("mensaje_recortado")
    if not result["message"]:
        result["message"] = "(mensaje vacío)"

    result["facility_name"] = FACILITIES[result["facility"]]
    result["severity_name"] = SEVERITY_NAMES[result["severity"]]
    return result
