"""
Asistente de IA del NOC - SOLO LECTURA (política P03).

Qué hace:   explica un evento, estima su riesgo, propone posibles causas,
            soluciones y comandos de VERIFICACIÓN, y sugiere mejoras para la red.
Qué NO hace: no ejecuta comandos, no tiene credenciales, no abre SSH, no aprueba
            acciones y no se invoca cuando el motor de políticas decidió BLOCK.

Implementación: base de conocimiento LOCAL y determinista (reglas por mnemónico
y texto). No necesita Internet ni claves de API, así que nunca "se cae": si en
el futuro se conecta un modelo externo, este módulo queda como respaldo
(falla segura: si la IA no responde, las reglas siguen operando).

El texto del log que llega aquí YA pasó por el motor de políticas: viene con los
secretos redactados (P02) y se usa solo para CLASIFICAR, nunca como instrucción (P01).
"""
from __future__ import annotations

import re

from plantillas import ALLOWLIST
from security import policy_engine

SEV_NAMES = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"]
RISK_BY_SEV = ["CRÍTICO", "CRÍTICO", "ALTO", "ALTO", "MEDIO", "BAJO", "BAJO", "BAJO"]

# ---------------------------------------------------------------------------
# Base de conocimiento. Cada regla: patrón -> explicación, causas, soluciones,
# comandos de verificación (claves genéricas que se traducen por fabricante) y
# acciones que REQUIEREN aprobación humana.
# ---------------------------------------------------------------------------
KB = [
    {"id": "enlace_caido",
     "match": r"(UPDOWN|LINK.*down|changed state to down|link (?:is )?down|interface.*down|PORT.*DOWN|ifDown)",
     "title": "Interfaz o enlace caído",
     "what": "Una interfaz del equipo pasó a estado DOWN. Los servicios que dependen de ese enlace pueden quedar sin conectividad.",
     "causes": ["Cable o transceptor (SFP) dañado o desconectado",
                "Equipo vecino apagado o reiniciándose",
                "Interfaz deshabilitada administrativamente (shutdown)",
                "Error de negociación de velocidad/dúplex o err-disable"],
     "solutions": ["Verificar el estado físico: luces del puerto, cable y SFP",
                   "Revisar si el equipo vecino está encendido y su puerto activo",
                   "Correlacionar con eventos UP/DOWN cercanos para detectar flapping",
                   "Si hay redundancia, confirmar que el tráfico conmutó al enlace de respaldo"],
     "verify": ["interfaces", "logging"],
     "proposals": ["Reemplazar cable/SFP del puerto afectado (en sitio)",
                   "Habilitar la interfaz si estaba en shutdown (requiere aprobación)"]},
    {"id": "enlace_activo",
     "match": r"(changed state to up|link (?:is )?up|LINK-\d-CHANGED|ifUp)",
     "title": "Interfaz o enlace activo",
     "what": "La interfaz pasó a estado UP. Hay enlace físico/lógico, pero eso no prueba que IP, gateway, DNS o la aplicación funcionen.",
     "causes": ["Recuperación de una caída previa", "Conexión de un nuevo equipo", "Flapping (sube y baja repetidamente)"],
     "solutions": ["Comprobar que no haya eventos DOWN repetidos en los últimos minutos (flapping)",
                   "Validar conectividad de capa 3 (ping al gateway / servicio)",
                   "Cerrar el incidente relacionado solo con evidencia de servicio restablecido"],
     "verify": ["interfaces", "logging"],
     "proposals": []},
    {"id": "fuerza_bruta",
     "match": r"(LOGIN_?FAIL|AUTH_?FAIL|login failed|authentication fail|intentos fallidos|invalid (?:user|password)|failed password)",
     "title": "Fallo de autenticación / posible fuerza bruta",
     "what": "Se registraron intentos fallidos de acceso al equipo. Puede ser un error humano, una credencial vencida, un escaneo o un ataque de fuerza bruta.",
     "causes": ["Usuario que olvidó o cambió su contraseña",
                "Script o servicio con credenciales viejas",
                "Escaneo automatizado o ataque de diccionario desde Internet"],
     "solutions": ["Correlacionar: misma IP de origen, mismo usuario, ventana de tiempo",
                   "Confirmar si la IP de origen es interna y conocida",
                   "Verificar sesiones activas en el equipo",
                   "Aplicar rate limiting / login block-for y exigir MFA en el acceso de gestión",
                   "Restringir la gestión (SSH) a una lista de IP permitidas (ACL de VTY)"],
     "verify": ["users", "logging"],
     "proposals": ["Bloqueo temporal de la IP de origen en el firewall (requiere aprobación)",
                   "Configurar 'login block-for 120 attempts 5 within 60' en Cisco (requiere aprobación)"]},
    {"id": "acceso_exitoso",
     "match": r"(LOGIN_?SUCCESS|logged in|login success|Accepted password|Admin login successful)",
     "title": "Acceso administrativo exitoso",
     "what": "Un usuario inició sesión en el equipo. Es normal en mantenimiento, pero debe coincidir con un cambio autorizado.",
     "causes": ["Mantenimiento planificado", "Acceso de un operador del NOC", "Credencial comprometida (si nadie lo reconoce)"],
     "solutions": ["Confirmar que el usuario y la IP de origen corresponden a personal autorizado",
                   "Cruzar con una ventana de mantenimiento o ticket de cambio"],
     "verify": ["users"],
     "proposals": []},
    {"id": "cambio_config",
     "match": r"(CONFIG_I|CMDRECORD|Configured from|configuration (?:changed|change)|cfg change)",
     "title": "Cambio o comando registrado en el equipo",
     "what": "Se modificó la configuración o se registró un comando. Todo cambio debe ser trazable a un responsable y a una solicitud.",
     "causes": ["Cambio planificado", "Error operativo", "Acceso no autorizado"],
     "solutions": ["Identificar usuario, terminal (vty) e IP de origen del cambio",
                   "Comparar con la configuración de respaldo (archive / backup)",
                   "Si no hay ticket asociado, escalar como posible acceso no autorizado"],
     "verify": ["users", "logging"],
     "proposals": ["Restaurar la configuración de respaldo si el cambio no fue autorizado (requiere aprobación)"]},
    {"id": "energia",
     "match": r"(power ?supply|PowerRemove|PWR|power module|fuente de poder|POWER)",
     "title": "Falla o retiro de fuente de poder",
     "what": "El equipo reportó una fuente de alimentación fallida o retirada. Si no hay redundancia, el equipo puede apagarse.",
     "causes": ["Fuente averiada", "Corte de energía en un circuito o PDU", "Fuente retirada durante mantenimiento"],
     "solutions": ["Verificar alimentación eléctrica (UPS / PDU / breaker) en sitio",
                   "Confirmar que la fuente redundante está operando",
                   "Abrir caso de garantía (RMA) con el fabricante si la fuente está averiada"],
     "verify": ["version"],
     "proposals": ["Programar ventana de mantenimiento para reemplazar la fuente"]},
    {"id": "temperatura",
     "match": r"(temperature|TEMP|fan|ventilador|overheat|thermal)",
     "title": "Alarma de temperatura o ventilación",
     "what": "El equipo reporta temperatura alta o falla de ventiladores; puede degradarse o apagarse por protección.",
     "causes": ["Ventilador averiado", "Aire acondicionado del cuarto de equipos fallando", "Obstrucción del flujo de aire"],
     "solutions": ["Revisar la climatización del rack / cuarto técnico",
                   "Verificar el estado de los ventiladores", "Despejar el flujo de aire del equipo"],
     "verify": ["version"],
     "proposals": []},
    {"id": "recursos",
     "match": r"(CPU|memory|memoria|MALLOCFAIL|high utilization|utilizaci[oó]n alta)",
     "title": "Uso alto de CPU o memoria",
     "what": "El equipo está con recursos al límite; puede responder lento, perder paquetes o reiniciarse.",
     "causes": ["Tormenta de broadcast o bucle de capa 2", "Proceso o depuración (debug) activa", "Ataque de denegación de servicio"],
     "solutions": ["Identificar el proceso que consume recursos",
                   "Descartar bucles (STP) y tormentas de broadcast",
                   "Desactivar depuraciones activas"],
     "verify": ["performance", "logging"],
     "proposals": []},
    {"id": "enrutamiento",
     "match": r"(BGP|OSPF|EIGRP|ADJCHG|neighbor.*(?:down|Down)|vecino)",
     "title": "Cambio en un vecino de enrutamiento",
     "what": "Una adyacencia de enrutamiento (BGP/OSPF/EIGRP) cambió de estado; puede haber rutas perdidas.",
     "causes": ["Enlace caído hacia el vecino", "Temporizadores o autenticación inconsistentes", "Cambio de configuración"],
     "solutions": ["Verificar el enlace físico hacia el vecino",
                   "Confirmar parámetros (área, AS, temporizadores, autenticación)",
                   "Revisar la tabla de rutas por rutas perdidas"],
     "verify": ["interfaces", "logging"],
     "proposals": []},
    {"id": "ntp",
     "match": r"(NTP|clock|unsynchroni|sincroniz)",
     "title": "Problema de sincronización de hora",
     "what": "Sin hora correcta los eventos no se pueden ordenar ni correlacionar, y la evidencia pierde valor.",
     "causes": ["Servidor NTP inalcanzable", "ACL bloqueando UDP 123", "Zona horaria mal configurada"],
     "solutions": ["Verificar alcance al servidor NTP", "Confirmar zona horaria COT -5"],
     "verify": ["ntp", "clock"],
     "proposals": []},
]
for _rule in KB:
    _rule["re"] = re.compile(_rule["match"], re.I)

# Traducción de verificaciones genéricas a comandos de la LISTA PERMITIDA de cada fabricante
VERIFY_MAP = {
    "Cisco": {"interfaces": "show ip interface brief", "logging": "show logging", "users": "show users",
              "version": "show version", "ntp": "show ntp associations", "clock": "show clock",
              "performance": "show version"},
    "Fortinet": {"interfaces": "get system interface physical", "logging": "get log syslogd setting",
                 "users": "get system status", "version": "get system status", "ntp": "diagnose sys ntp status",
                 "clock": "get system status", "performance": "get system performance status"},
    "Huawei": {"interfaces": "display ip interface brief", "logging": "display info-center",
               "users": "display users", "version": "display version", "ntp": "display ntp-service status",
               "clock": "display clock", "performance": "display version"},
}


def _verify_commands(vendor: str, keys: list[str]) -> list[str]:
    allowed = {c for c, _ in ALLOWLIST.get(vendor, [])}
    out = []
    for k in keys:
        cmd = VERIFY_MAP.get(vendor, {}).get(k)
        if cmd and cmd in allowed and cmd not in out:   # solo comandos de la lista permitida
            out.append(cmd)
    return out


def analyze(event: dict, decision: dict) -> dict:
    """
    Analiza UN evento ya evaluado por el motor de políticas.
    event: severity, vendor, mnemonic, message (redactado), device_name, source_ip
    decision: resultado de policy_engine.evaluate()
    """
    sev = int(event.get("severity", 6))
    vendor = event.get("vendor") or "Otro"
    base = {"modo": "base de conocimiento local (determinista, sin red)",
            "solo_lectura": True, "decision": decision["decision"]}

    if decision["decision"] == "BLOCK":
        # Falla segura: la IA NO analiza contenido bloqueado. Se dan pasos para el analista.
        return {**base, "invocada": False,
                "titulo": "Contenido bloqueado: posible prompt injection",
                "resumen": "El motor de políticas bloqueó este evento ANTES de la IA. El texto intenta dar "
                           "órdenes a un agente (pedir secretos, ignorar reglas o ejecutar comandos).",
                "riesgo": "ALTO",
                "que_paso": "Un mensaje Syslog contiene instrucciones dirigidas a un asistente de IA. "
                            "Es un dato no confiable; no tiene autoridad para activar herramientas.",
                "causas": ["Equipo comprometido que inyecta texto en sus logs",
                           "Atacante que envía Syslog falsificado al colector",
                           "Prueba de seguridad / laboratorio"],
                "soluciones": ["NO copiar el texto en otra herramienta de IA",
                               "Identificar el origen real (IP) y si está en el inventario",
                               "Revisar otros eventos del mismo origen en la ventana de tiempo",
                               "Si el origen es interno: aislar y revisar el equipo",
                               "Endurecer el colector: solo fuentes autorizadas y, a futuro, Syslog sobre TLS (RFC 5425)"],
                "verificacion": _verify_commands(vendor, ["logging", "users"]),
                "acciones_con_aprobacion": ["Bloquear la IP de origen en el firewall (requiere aprobación humana)"],
                "politicas": decision["policies"]}

    text = f"{event.get('mnemonic') or ''} {event.get('message') or ''}"
    rule = next((r for r in KB if r["re"].search(text)), None)
    risk = RISK_BY_SEV[sev]
    if decision["decision"] == "REVIEW" and risk == "BAJO":
        risk = "MEDIO"
    device = event.get("device_name") or event.get("source_ip") or "equipo desconocido"

    if rule is None:
        rule = {"title": f"Evento {SEV_NAMES[sev]} sin patrón conocido",
                "what": f"El equipo reportó un evento de severidad {sev} ({SEV_NAMES[sev]}) que no coincide "
                        "con la base de conocimiento.",
                "causes": ["Evento específico del fabricante", "Mensaje informativo del sistema"],
                "solutions": ["Buscar el mnemónico en la documentación del fabricante",
                              "Correlacionar con otros eventos del mismo equipo",
                              "Si se repite, agregar una regla a la base de conocimiento del NOC"],
                "verify": ["logging"], "proposals": []}

    extra = []
    if decision.get("secrets"):
        extra.append("Se detectaron credenciales en el log: cambiarlas y evitar que el equipo las registre")
    if "fuente no autorizada" in " ".join(decision.get("reasons", [])):
        extra.append("La fuente no está autorizada: registrarla en el inventario o bloquearla")

    return {**base, "invocada": True,
            "titulo": rule["title"],
            "resumen": f"{rule['title']} en {device} (severidad {sev} {SEV_NAMES[sev]}).",
            "riesgo": risk,
            "que_paso": rule["what"],
            "causas": rule["causes"],
            "soluciones": rule["solutions"] + extra,
            "verificacion": _verify_commands(vendor, rule["verify"]),
            "acciones_con_aprobacion": rule["proposals"],
            "politicas": decision["policies"]}


# ---------------------------------------------------------------------------
# Mejoras de la red (a partir de estadísticas del NOC)
# ---------------------------------------------------------------------------
def improvements(conn) -> list[dict]:
    """Recomendaciones priorizadas a partir del estado actual de la base de datos."""
    q = lambda sql, *a: conn.execute(sql, a).fetchone()[0]
    out = []

    def add(prioridad, titulo, detalle, accion):
        out.append({"prioridad": prioridad, "titulo": titulo, "detalle": detalle, "accion": accion})

    blocked = q("SELECT COUNT(*) FROM policy_decisions WHERE decision = 'BLOCK'")
    if blocked:
        add("ALTA", "Intentos de prompt injection detectados",
            f"{blocked} evento(s) bloqueados por P06.",
            "Investigar los orígenes, verificar si están en el inventario y restringir el colector a fuentes autorizadas.")
    unauth = q("SELECT COUNT(DISTINCT source_ip) FROM events WHERE authorized_source = 0")
    if unauth:
        add("ALTA", "Fuentes Syslog no autorizadas",
            f"{unauth} IP(s) enviaron mensajes sin estar autorizadas.",
            "Registrar los equipos legítimos en el Inventario y bloquear en el firewall el UDP 514/5514 del resto.")
    secrets = q("SELECT COUNT(*) FROM policy_decisions WHERE secrets IS NOT NULL AND secrets != ''")
    if secrets:
        add("ALTA", "Credenciales expuestas en logs",
            f"{secrets} evento(s) contenían secretos (fueron redactados por P02).",
            "Cambiar esas credenciales y configurar 'hidekeys' (Cisco) o equivalente para no registrarlas.")
    crit_open = q("SELECT COUNT(*) FROM incidents WHERE status != 'cerrado' AND severity <= 2")
    if crit_open:
        add("ALTA", "Incidentes críticos abiertos",
            f"{crit_open} incidente(s) de severidad 0-2 sin cerrar.",
            "Asignar responsable y atenderlos primero (pestaña Incidentes).")
    unassigned = q("SELECT COUNT(*) FROM incidents WHERE status = 'abierto' AND assigned_to IS NULL")
    if unassigned:
        add("MEDIA", "Incidentes sin responsable",
            f"{unassigned} incidente(s) abiertos sin asignar.", "Asignar un analista a cada incidente.")
    pending = q("SELECT COUNT(*) FROM actions WHERE status = 'pendiente'")
    if pending:
        add("MEDIA", "Acciones esperando aprobación humana",
            f"{pending} acción(es) propuestas sin revisar (P04).", "Revisarlas y aprobar o rechazar con justificación.")
    silent = conn.execute(
        "SELECT name FROM devices d WHERE authorized = 1 AND NOT EXISTS "
        "(SELECT 1 FROM events e WHERE e.device_id = d.id) ORDER BY name").fetchall()
    if silent:
        add("MEDIA", "Equipos autorizados sin eventos",
            "Sin mensajes de: " + ", ".join(r["name"] for r in silent[:6]) + ("…" if len(silent) > 6 else ""),
            "Verificar su configuración Syslog (pestaña Configuraciones) y la conectividad hacia el colector.")
    down = q("SELECT COUNT(*) FROM devices WHERE status IN ('caido', 'alerta')")
    if down:
        add("MEDIA", "Equipos en estado caído o alerta",
            f"{down} equipo(s) requieren atención según el inventario.", "Revisar su estado y actualizar el inventario.")
    dups = q("SELECT COALESCE(SUM(dup_count - 1), 0) FROM events")
    if dups > 20:
        add("BAJA", "Mensajes repetidos",
            f"{dups} mensajes fueron deduplicados.", "Revisar la severidad mínima enviada por los equipos para reducir ruido.")
    add("BAJA", "Syslog cifrado",
        "Hoy el transporte es UDP sin cifrar.",
        "Planear Syslog sobre TLS (RFC 5425) y autenticación de las fuentes.")
    return out


def analysis_for_event(conn, event_id: int):
    """Reconstruye (evento, decisión, análisis) de un evento guardado. (None, None, None) si no existe."""
    e = conn.execute("SELECT e.*, d.name AS device_name FROM events e LEFT JOIN devices d ON d.id = e.device_id "
                     "WHERE e.id = ?", (event_id,)).fetchone()
    if e is None:
        return None, None, None
    pd = conn.execute("SELECT * FROM policy_decisions WHERE event_id = ? ORDER BY id DESC LIMIT 1",
                      (event_id,)).fetchone()
    ev = dict(e)
    # Se reevalúa con el mismo motor (determinista) para reconstruir la decisión completa
    decision = policy_engine.evaluate(
        {"message": e["message"], "raw": e["raw"], "severity": e["severity"],
         "authorized": bool(e["authorized_source"]), "flags": (e["flags"] or "").split(","),
         "mnemonic": e["mnemonic"]})
    if pd is not None:          # la decisión registrada (P05) manda
        decision["decision"] = pd["decision"]
        decision["policies"] = (pd["policies"] or "").split(",")
        decision["reasons"] = [r for r in (pd["reasons"] or "").split(" | ") if r]
        decision["injection"] = [x for x in (pd["injection"] or "").split(",") if x]
    return ev, decision, analyze(ev, decision)
