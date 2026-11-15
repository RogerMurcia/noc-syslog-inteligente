"""
Integración del NOC con Telegram (Bot API) - envío de alertas.

Qué se envía (y cuándo):
  * BLOCK  -> siempre (posible prompt injection; la IA no fue invocada).
  * REVIEW -> si la severidad es <= TELEGRAM_ALERT_MAX_SEVERITY (por defecto 3),
              si es posible fuerza bruta o si hay credenciales expuestas.
  * Incidente NUEVO -> siempre.
  Cada alerta trae: qué pasó, riesgo, políticas aplicadas, posibles soluciones y
  comandos de verificación (del asistente de solo lectura).

Seguridad:
  * El token y los chat_id se leen del .env (nunca en el código ni en GitHub).
  * El texto ya viene REDACTADO por P02 y se escapa como HTML: un log no puede
    inyectar formato ni enlaces en el mensaje (P01).
  * Límite de alertas por minuto para no inundar el chat durante una tormenta.
  * Si Telegram falla o no hay Internet, el NOC sigue funcionando (falla segura);
    el intento queda en la tabla 'notifications'.
  * Solo usa la biblioteca estándar (urllib): no hay dependencias nuevas.
"""
from __future__ import annotations

import html
import json
import os
import time
import urllib.error
import urllib.request

API_URL = "https://api.telegram.org/bot{token}/{method}"
MAX_LEN = 3900          # Telegram admite 4096 caracteres por mensaje
SEV_NAMES = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"]
DECISION_ICON = {"ALLOW": "🟢", "REVIEW": "🟠", "BLOCK": "🔴"}
RISK_ICON = {"CRÍTICO": "🚨", "ALTO": "🔴", "MEDIO": "🟠", "BAJO": "🟢"}


def _bool(value: str | None, default=False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "si", "sí", "yes", "on")


class Config:
    """Configuración leída del entorno en cada uso (permite cambiar el .env sin tocar código)."""

    @property
    def token(self) -> str:
        return os.getenv("TELEGRAM_BOT_TOKEN", "").strip()

    @property
    def chat_ids(self) -> list[str]:
        return [c.strip() for c in os.getenv("TELEGRAM_CHAT_IDS", "").split(",") if c.strip()]

    @property
    def enabled(self) -> bool:
        return _bool(os.getenv("TELEGRAM_ENABLED"), False) and bool(self.token) and bool(self.chat_ids)

    @property
    def max_severity(self) -> int:
        try:
            return int(os.getenv("TELEGRAM_ALERT_MAX_SEVERITY", "3"))
        except ValueError:
            return 3

    @property
    def rate_per_minute(self) -> int:
        try:
            return int(os.getenv("TELEGRAM_MAX_ALERTS_PER_MINUTE", "20"))
        except ValueError:
            return 20


CONFIG = Config()
_sent_times: list[float] = []      # marcas de tiempo de envíos recientes (límite por minuto)


def esc(text) -> str:
    """Escapa texto no confiable para parse_mode=HTML."""
    return html.escape(str(text if text is not None else ""), quote=False)


def api_call(method: str, payload: dict, timeout: float = 8.0) -> dict:
    """Llama a la Bot API. Lanza RuntimeError con un mensaje sin el token si falla."""
    url = API_URL.format(token=CONFIG.token, method=method)
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            desc = json.loads(e.read().decode("utf-8")).get("description", "")
        except Exception:
            desc = ""
        raise RuntimeError(f"HTTP {e.code} {desc}".strip()) from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RuntimeError(f"sin conexión con Telegram ({type(e).__name__})") from None
    if not body.get("ok"):
        raise RuntimeError(body.get("description", "respuesta no válida"))
    return body


def send_text(text: str, chat_id: str | None = None, timeout: float = 8.0) -> tuple[bool, str]:
    """Envía un mensaje (HTML) a un chat o a todos los autorizados. Devuelve (ok, detalle)."""
    if not CONFIG.token:
        return False, "TELEGRAM_BOT_TOKEN no configurado"
    targets = [chat_id] if chat_id else CONFIG.chat_ids
    if not targets:
        return False, "TELEGRAM_CHAT_IDS no configurado"
    if len(text) > MAX_LEN:
        text = text[:MAX_LEN] + "\n…(recortado)"
    errors = []
    for cid in targets:
        try:
            api_call("sendMessage", {"chat_id": cid, "text": text, "parse_mode": "HTML",
                                     "disable_web_page_preview": True}, timeout=timeout)
        except RuntimeError as e:
            errors.append(f"chat {cid}: {e}")
    return (not errors), ("; ".join(errors) or f"enviado a {len(targets)} chat(s)")


def _rate_ok() -> bool:
    now = time.monotonic()
    while _sent_times and now - _sent_times[0] > 60:
        _sent_times.pop(0)
    if len(_sent_times) >= CONFIG.rate_per_minute:
        return False
    _sent_times.append(now)
    return True


# ---------------------------------------------------------------------------
# Formato de mensajes
# ---------------------------------------------------------------------------
def format_alert(event: dict, decision: dict, analysis: dict, incident: dict | None = None) -> str:
    sev = int(event.get("severity", 6))
    d = decision["decision"]
    lines = [
        f"{DECISION_ICON.get(d, '⚪')} <b>NOC Syslog · {esc(d)}</b>  {RISK_ICON.get(analysis.get('riesgo'), '')} "
        f"Riesgo {esc(analysis.get('riesgo', '-'))}",
        f"<b>{esc(analysis.get('titulo', 'Evento'))}</b>",
        "",
        f"🖥 <b>Equipo:</b> {esc(event.get('device_name') or 'desconocido')} ({esc(event.get('source_ip'))})",
        f"🏷 <b>Fabricante:</b> {esc(event.get('vendor') or '-')} · <b>Severidad:</b> {sev} {SEV_NAMES[sev]}",
        f"🆔 <b>Evento:</b> #{esc(event.get('id'))}" + (f" · <b>Incidente:</b> #{incident['id']}" if incident else ""),
        f"🛡 <b>Políticas:</b> {esc(', '.join(decision['policies']))}",
    ]
    if d == "BLOCK":
        lines += ["", "⛔ <b>La IA NO fue invocada.</b> El mensaje contenía instrucciones dirigidas a un agente "
                      "y se trató como dato no confiable (P01 + P06)."]
        if decision.get("injection"):
            lines.append(f"🔎 <b>Patrones:</b> {esc(', '.join(decision['injection']))}")
    else:
        lines += ["", f"📄 <b>Mensaje</b> (redactado):", f"<code>{esc(decision['redacted_message'][:300])}</code>"]
    if decision.get("reasons"):
        lines += ["", "<b>Motivo:</b>"] + [f"• {esc(r)}" for r in decision["reasons"][:3]]
    if analysis.get("que_paso"):
        lines += ["", f"<b>¿Qué pasó?</b> {esc(analysis['que_paso'])}"]
    if analysis.get("soluciones"):
        lines += ["", "<b>🔧 Posibles soluciones:</b>"] + [f"{i}. {esc(s)}" for i, s in
                                                         enumerate(analysis["soluciones"][:5], 1)]
    if analysis.get("verificacion"):
        lines += ["", "<b>🔍 Verificar (solo lectura):</b>"] + [f"<code>{esc(c)}</code>" for c in
                                                              analysis["verificacion"]]
    if analysis.get("acciones_con_aprobacion"):
        lines += ["", "<b>✋ Requieren aprobación humana:</b>"] + [f"• {esc(a)}" for a in
                                                                analysis["acciones_con_aprobacion"][:3]]
    lines += ["", f"<i>Detalle: /analizar {esc(event.get('id'))}"
                  + (f" · /incidente {incident['id']}" if incident else "") + "</i>"]
    return "\n".join(lines)


def should_alert(event: dict, decision: dict, incident: dict | None) -> str | None:
    """Devuelve el tipo de alerta o None si no corresponde avisar."""
    if decision["decision"] == "BLOCK":
        return "bloqueo"
    if incident and not incident.get("correlated"):
        return "incidente_nuevo"
    if decision["decision"] == "REVIEW":
        reasons = " ".join(decision.get("reasons", []))
        if int(event.get("severity", 6)) <= CONFIG.max_severity or "fuerza bruta" in reasons or decision.get("secrets"):
            return "revision"
    return None


def notify(conn, event: dict, decision: dict, analysis: dict, incident: dict | None, now_iso) -> dict | None:
    """Decide, formatea, envía y registra. Nunca lanza excepciones hacia el receptor."""
    kind = should_alert(event, decision, incident)
    if kind is None:
        return None
    text = format_alert(event, decision, analysis, incident)
    if not CONFIG.enabled:
        status, detail = "desactivada", "TELEGRAM_ENABLED=0 o faltan token/chat_id"
    elif not _rate_ok():
        status, detail = "fallida", f"límite de {CONFIG.rate_per_minute} alertas/min alcanzado"
    else:
        try:
            ok, detail = send_text(text)
        except Exception as e:          # falla segura: jamás detener el NOC
            ok, detail = False, f"error inesperado: {type(e).__name__}"
        status = "enviada" if ok else "fallida"
    try:
        conn.execute("INSERT INTO notifications (channel, kind, event_id, incident_id, text, status, detail, "
                     "created_at) VALUES ('telegram', ?, ?, ?, ?, ?, ?, ?)",
                     (kind, event.get("id"), incident["id"] if incident else None, text, status, detail, now_iso()))
        conn.commit()
    except Exception:
        pass
    return {"kind": kind, "status": status, "detail": detail}
