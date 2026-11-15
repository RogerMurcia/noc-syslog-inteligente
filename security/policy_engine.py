"""
Motor de políticas del NOC (v1.0) - actúa ANTES de cualquier análisis de IA.

Principio de diseño: "la IA asesora; las políticas y el humano conservan el control".

    EVENTO SYSLOG ──> parser ──> MOTOR DE POLÍTICAS ──> ALLOW / REVIEW / BLOCK
                                      │                   │       │        │
                                      │                   │       │        └─ la IA NO se invoca;
                                      │                   │       │           se preserva evidencia y se alerta
                                      │                   │       └─ pausa: un humano revisa
                                      │                   └─ análisis de IA de SOLO LECTURA
                                      └─ registra decisión, políticas, evidencia y hash (P05)

Políticas (cada una tiene identificador, condición, acción, evidencia y responsable):

    P01  El log es dato, no instrucción     -> todo campo externo es NO CONFIABLE
    P02  Redactar secretos                  -> se enmascaran antes de guardar, mostrar o enviar
    P03  IA sin herramientas ni SSH         -> el texto nunca activa comandos ni conexiones
    P04  Aprobación humana obligatoria      -> severidad 0-3, fuerza bruta o fuente dudosa = REVIEW
    P05  Auditar decisión y evidencia       -> event_id, políticas, resultado, hash y hora
    P06  Detectar inyección en campos       -> prompt injection = BLOCK antes de invocar la IA

La función evaluate() es DETERMINISTA: el mismo evento con las mismas políticas
activas produce siempre la misma decisión (requisito de la clase). No usa red,
no usa IA y no ejecuta nada: si la IA falla, este motor sigue funcionando.
"""
from __future__ import annotations

import hashlib
import re

ALLOW, REVIEW, BLOCK = "ALLOW", "REVIEW", "BLOCK"

# ---------------------------------------------------------------------------
# Catálogo de políticas (lo consumen la web, la API y el bot de Telegram)
# ---------------------------------------------------------------------------
POLICIES = [
    {"id": "P01", "name": "El log es dato, no instrucción",
     "condition": "Todo mensaje recibido por Syslog, importación o usuario externo",
     "action": "Delimitar y etiquetar el contenido como NO CONFIABLE; nunca se ejecuta ni se usa como prompt",
     "risk": "Evita que texto externo cambie las reglas del sistema o del agente de IA",
     "evidence": "event_id, IP de origen, fuente autorizada sí/no, hash del mensaje original",
     "owner": "Motor de políticas (automático)"},
    {"id": "P02", "name": "Redactar secretos",
     "condition": "El mensaje contiene contraseñas, tokens, claves, comunidades SNMP o llaves privadas",
     "action": "Enmascarar ([REDACTADO]) antes de almacenar, mostrar, analizar o enviar a Telegram",
     "risk": "Evita exponer credenciales en la base de datos, la web, el chat o el modelo",
     "evidence": "Tipos de secreto detectados (nunca su valor)",
     "owner": "Motor de políticas (automático)"},
    {"id": "P03", "name": "IA sin herramientas ni SSH",
     "condition": "Siempre",
     "action": "El asistente solo explica y propone; no tiene credenciales, SSH ni ejecución",
     "risk": "Evita que una interpretación errónea se convierta en un cambio real en la red",
     "evidence": "Actor 'asistente_ia' bloqueado en consola y aprobación (auditoría)",
     "owner": "Arquitectura (por diseño)"},
    {"id": "P04", "name": "Aprobación humana obligatoria",
     "condition": "Severidad 0-3, posible fuerza bruta, fuente no autorizada o mensaje malformado",
     "action": "Decisión REVIEW: el flujo se pausa hasta que un analista revise y decida",
     "risk": "Evita decisiones de impacto sin contexto operativo",
     "evidence": "Analista responsable, decisión, justificación y hora",
     "owner": "Analista NOC"},
    {"id": "P05", "name": "Auditar decisión y evidencia",
     "condition": "Toda decisión del motor",
     "action": "Registrar event_id, políticas, decisión, motivo, hash y hora (solo inserción)",
     "risk": "Evita acciones imposibles de reconstruir o atribuir",
     "evidence": "Tablas policy_decisions y audit_log",
     "owner": "Motor de políticas (automático)"},
    {"id": "P06", "name": "Detectar inyección en campos",
     "condition": "Lenguaje imperativo dirigido a la IA, pedido de secretos o de conexión remota",
     "action": "Decisión BLOCK: no se invoca la IA, se aísla el texto y se escala al analista",
     "risk": "Reconoce prompt injection indirecta escondida en un log",
     "evidence": "Patrones coincidentes, origen y decisión BLOCK",
     "owner": "Motor de políticas + analista"},
]
POLICY_IDS = [p["id"] for p in POLICIES]
BASIC_CONTROLS = ("P01", "P02", "P03")                 # sin estos no se envía nada a la IA
INJECTION_CONTROLS = ("P01", "P02", "P03", "P06")      # necesarios para BLOQUEAR una inyección

# ---------------------------------------------------------------------------
# P02 - Secretos. Se detecta el TIPO y se reemplaza el VALOR por [REDACTADO].
# ---------------------------------------------------------------------------
REDACTED = "[REDACTADO]"
SECRET_PATTERNS = [
    # (tipo, expresión, grupo que se conserva antes del valor)
    ("contraseña", re.compile(
        r"(?i)\b((?:password|passwd|pwd|pass|contrase(?:ñ|n)a|clave)\b\s*[:=]\s*)(?!\[REDACTADO\])(\S+)")),
    ("secreto_cisco", re.compile(r"(?i)\b((?:enable\s+)?(?:secret|password)\s+\d\s+)(?!\[REDACTADO\])(\S+)")),
    ("comunidad_snmp", re.compile(r"(?i)\b(snmp-server\s+community\s+|community\s*[:=]\s*)(?!\[REDACTADO\])(\S+)")),
    ("token", re.compile(r"(?i)\b((?:token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\s*[:=]\s*)(?!\[REDACTADO\])(\S+)")),
    ("bearer", re.compile(r"(?i)\b(bearer\s+)(?!\[REDACTADO\])([A-Za-z0-9._\-]{12,})")),
    ("token_telegram", re.compile(r"()\b(\d{8,10}:[A-Za-z0-9_\-]{35})\b")),
    ("llave_privada", re.compile(r"()(-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$))", re.S)),
]


def redact(text: str) -> tuple[str, list[str]]:
    """Devuelve (texto_sin_secretos, tipos_detectados). Nunca devuelve el valor original."""
    found = []
    out = text or ""
    for kind, pattern in SECRET_PATTERNS:
        if pattern.search(out):
            found.append(kind)
            out = pattern.sub(lambda m: m.group(1) + REDACTED, out)
    return out, found


# ---------------------------------------------------------------------------
# P06 - Prompt injection: texto que intenta dar órdenes a un agente de IA
# ---------------------------------------------------------------------------
INJECTION_PATTERNS = [
    ("ignorar_reglas", re.compile(
        r"(?i)\b(ignor\w*|olvid\w*|omit\w*|disregard|forget)\s+(?:\w+\s+){0,4}"
        r"(reglas|instrucciones|instructions|rules|pol[ií]ticas|policies)")),
    ("cambio_de_rol", re.compile(r"(?i)\b(you are now|ahora eres|act[uú]a como|act as|pretend to be|finge ser)\b")),
    ("prompt_del_sistema", re.compile(
        r"(?i)\b(system prompt|prompt del sistema|developer mode|modo desarrollador|jailbreak|DAN mode)\b")),
    ("orden_de_ejecucion", re.compile(
        r"(?i)\b(ejecut[ae]\w*|execute|run|corre)\s+(?:el\s+|the\s+|este\s+|this\s+)?(comando|command|script)")),
    ("sin_aprobacion", re.compile(
        r"(?i)\b(sin (?:aprobaci[oó]n|autorizaci[oó]n|revisi[oó]n)|without (?:approval|authorization|review))\b")),
    ("pide_secretos", re.compile(
        r"(?i)\b(muestr\w*|revel\w*|export\w*|entreg\w*|env[ií]\w*|show|reveal|export|send|dump|print)\s+"
        r"(?:\w+\s+){0,3}(credenciales|claves|contrase(?:ñ|n)as|secretos|tokens?|passwords?|credentials|keys)")),
    ("pide_conexion", re.compile(
        r"(?i)\b(con[eé]ct(?:ese|ate|e|ar)|connect(?: to)?|abr[ae] una sesi[oó]n|open a session)\s+"
        r"(?:\w+\s+){0,3}(ssh|telnet|consola remota|remote shell)")),
    ("orden_a_la_ia", re.compile(
        r"(?i)\b(asistente|assistant|agente de ia|ai agent|llm|chatgpt|claude)\s*[:,]\s*"
        r"(ignora|ejecuta|muestra|ignore|execute|show|run|olvida|forget)")),
]


def detect_injection(text: str) -> list[str]:
    """Devuelve los nombres de los patrones de inyección encontrados (lista vacía = limpio)."""
    return [name for name, p in INJECTION_PATTERNS if p.search(text or "")]


# ---------------------------------------------------------------------------
# Mnemónicos de interés operativo
# ---------------------------------------------------------------------------
AUTH_FAIL = re.compile(r"(?i)(LOGIN_?FAIL|AUTH_?FAIL|login failed|authentication fail|intentos fallidos|"
                       r"invalid (user|password)|failed password)")
BRUTE_FORCE_THRESHOLD = 5        # fallos de autenticación del mismo origen en la ventana


def event_hash(raw: str) -> str:
    """Huella SHA-256 del mensaje ORIGINAL: prueba de integridad sin guardar secretos."""
    return hashlib.sha256((raw or "").encode("utf-8", errors="replace")).hexdigest()


def evaluate(event: dict, active: set | list | None = None, context: dict | None = None) -> dict:
    """
    Aplica las políticas a UN evento normalizado.

    event:   message, raw, severity (0-7), authorized (bool), flags (lista), mnemonic, source_ip
    active:  políticas activas (por defecto todas). Desactivar una sirve en el laboratorio
             para ver qué riesgo reaparece; en producción siempre están todas.
    context: datos de correlación, p. ej. {"auth_failures": 7} en la ventana de tiempo.

    Devuelve un diccionario con: decision, policies, reasons, evidence, redacted_message,
    secrets, injection, missing_controls, ai_invoked, event_hash.
    """
    active = set(POLICY_IDS if active is None else active)
    context = context or {}
    message = str(event.get("message") or "")
    raw = str(event.get("raw") or message)
    severity = int(event.get("severity", 6))
    flags = list(event.get("flags") or [])
    mnemonic = str(event.get("mnemonic") or "")

    matched, reasons, evidence = [], [], []
    missing = [p for p in POLICY_IDS if p not in active]

    # P01 - el contenido es dato no confiable
    if "P01" in active:
        matched.append("P01")
        evidence.append("contenido tratado como dato no confiable")

    # P02 - redacción de secretos
    if "P02" in active:
        redacted, secrets = redact(message)
        secrets = sorted(set(secrets) | set(redact(raw)[1]), key=[k for k, _ in SECRET_PATTERNS].index)
    else:
        redacted, secrets = message, []
    if secrets:
        matched.append("P02")
        reasons.append(f"Se detectaron y ocultaron secretos: {', '.join(secrets)}")
        evidence.append(f"secretos_redactados={','.join(secrets)}")

    # P06 - inyección (se busca en el mensaje y en el crudo)
    injection = sorted(set(detect_injection(message) + detect_injection(raw))) if "P06" in active else []
    # Sin P06 activa la inyección no se "ve" por regla, pero la heurística básica del parser
    # puede haberla marcado: eso se usa para demostrar el CONTROL INCOMPLETO del laboratorio.
    suspected = bool(injection) or "posible_prompt_injection" in flags

    auth_failures = int(context.get("auth_failures", 0))
    is_auth_fail = bool(AUTH_FAIL.search(mnemonic) or AUTH_FAIL.search(message))
    brute_force = is_auth_fail and auth_failures >= BRUTE_FORCE_THRESHOLD

    decision = ALLOW
    if suspected:
        if all(p in active for p in INJECTION_CONTROLS):
            decision = BLOCK
            matched += ["P03", "P06"]
            reasons.append("Instrucción embebida en un dato no confiable (prompt injection indirecta)")
            evidence.append(f"patrones={','.join(injection)}")
        else:
            decision = REVIEW
            reasons.append("Posible inyección con CONTROL INCOMPLETO: faltan "
                           + ", ".join(p for p in INJECTION_CONTROLS if p not in active))
    else:
        review_why = []
        if severity <= 3:
            review_why.append(f"severidad {severity} (0-3 exige revisión humana)")
        if brute_force:
            review_why.append(f"posible fuerza bruta: {auth_failures} fallos de autenticación del mismo origen")
        if not event.get("authorized", True):
            review_why.append("fuente no autorizada o desconocida")
        if {"severidad_inconsistente", "sin_pri"} & set(flags):
            review_why.append("mensaje malformado o severidad inconsistente")
        if secrets:
            review_why.append("credenciales expuestas en el log")
        if review_why:
            decision = REVIEW
            if "P04" in active:
                matched.append("P04")
                reasons.append("Requiere aprobación humana: " + "; ".join(review_why))
            else:
                reasons.append("CONTROL INCOMPLETO (P04 desactivada): " + "; ".join(review_why))
        if any(p not in active for p in BASIC_CONTROLS):
            decision = REVIEW
            reasons.append("Faltan controles básicos ("
                           + ", ".join(p for p in BASIC_CONTROLS if p not in active)
                           + "): no es seguro enviar contexto a la IA")
        if decision == ALLOW:
            reasons.append("Validación superada: puede pasar a análisis de solo lectura")
            matched.append("P03")

    if "P05" in active:
        matched.append("P05")
    else:
        reasons.append("ADVERTENCIA: P05 desactivada, la decisión no quedaría auditada")

    return {
        "decision": decision,
        "policies": sorted(set(matched), key=POLICY_IDS.index),
        "reasons": reasons,
        "evidence": evidence,
        "redacted_message": redacted,
        "secrets": secrets,
        "injection": injection,
        "missing_controls": missing,
        # La IA nunca se invoca ante un BLOCK (falla segura)
        "ai_invoked": decision != BLOCK,
        "event_hash": event_hash(raw),
    }


MEANING = {
    ALLOW: "El evento puede pasar a análisis asistido de solo lectura. No autoriza cambios.",
    REVIEW: "El flujo queda en pausa hasta que una persona compruebe el contexto y decida.",
    BLOCK: "La IA no se invoca. La entrada se aísla, se preserva la evidencia y se alerta.",
}
