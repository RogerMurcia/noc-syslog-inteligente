"""
Consola de EQUIPOS REALES: puerto serial (cable de consola) y Telnet/TCP (GNS3).

A diferencia de la consola simulada (plantillas.py), aquí los comandos SÍ llegan
al equipo. Por eso se aplican estas reglas:

  * Solo personas: el actor 'asistente_ia' no puede abrir sesiones ni enviar
    comandos (política P03). La IA sigue limitada a proponer en Incidentes.
  * Dos modos:
      - lectura: solo pasan los comandos de la lista permitida del fabricante
        (los mismos de la consola simulada). Todo lo demás se bloquea.
      - administrador: permite configurar el equipo. Los comandos destructivos
        (reload, erase, delete, format, reset de fábrica...) exigen confirmación
        explícita en cada envío.
  * Auditoría de cada comando con las contraseñas ocultas (P02/P05). La salida
    del equipo se muestra al operador pero NO se guarda en la base de datos.

Conexiones admitidas:
  serial   COM3, COM4... (Windows) o /dev/ttyUSB0 (Linux). Por defecto 9600 8N1.
  tcp      host:puerto, p. ej. 127.0.0.1:5000 para la consola de un nodo de GNS3.
  loop     loop:// (eco local) solo para pruebas automáticas.

Requiere el paquete pyserial (pip install -r requirements.txt).
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time

try:
    import serial
    import serial.tools.list_ports
    HAVE_SERIAL = True
except ImportError:          # el NOC funciona igual; solo esta función queda deshabilitada
    serial = None
    HAVE_SERIAL = False

from security import policy_engine
import plantillas

BAUDRATES = (1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200)
MAX_BUFFER_CHUNKS = 3000
MAX_COMMAND_LEN = 400

# Comandos que borran, reinician o restauran el equipo: siempre piden confirmación
DESTRUCTIVE = re.compile(
    r"(?i)^\s*(reload|reboot|write\s+erase|erase\b|delete\b|del\b|format\b|rmdir\b|"
    r"execute\s+(reboot|shutdown|factoryreset|formatlogdisk)|reset\s+saved-configuration|"
    r"reset\s+factory|factory-?reset|startup\s+saved-configuration|crypto\s+key\s+zeroize)")

# Ocultar secretos en lo que se audita (además de los patrones del motor de políticas)
RE_CLI_SECRET = re.compile(r"(?i)\b(secret|password|passwd|key-string|pre-shared-key|psksecret|"
                           r"set\s+password|cipher)(\s+\d)?(\s+)(\S+)")


def redact_command(cmd: str) -> str:
    text, _ = policy_engine.redact(cmd)
    return RE_CLI_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2) or ''}{m.group(3)}[REDACTADO]", text)


# Telnet: se descartan las negociaciones IAC; ANSI: se quitan secuencias de color/cursor
RE_IAC = re.compile(rb"\xff[\xfb-\xfe].|\xff\xfa.*?\xff\xf0|\xff[\xf0-\xfa]", re.S)
RE_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\x1b[=>]")


def clean_output(data: bytes) -> str:
    text = RE_IAC.sub(b"", data).decode("utf-8", errors="replace")
    return RE_ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "")


def list_ports() -> list[dict]:
    if not HAVE_SERIAL:
        return []
    out = []
    for p in serial.tools.list_ports.comports():
        out.append({"device": p.device, "description": p.description or "", "hwid": p.hwid or "",
                    "manufacturer": getattr(p, "manufacturer", None) or ""})
    return sorted(out, key=lambda x: x["device"])


def check_command(command: str, mode: str, vendor: str, confirm: bool) -> tuple[bool, str, bool]:
    """Devuelve (permitido, motivo, requiere_confirmacion)."""
    if len(command) > MAX_COMMAND_LEN:
        return False, f"Comando demasiado largo (máx. {MAX_COMMAND_LEN} caracteres)", False
    if "\n" in command or "\r" in command:
        return False, "Envíe un comando por línea", False
    if mode == "lectura":
        ok, reason = plantillas.check(vendor, command, "humano")
        return ok, reason, False
    if DESTRUCTIVE.match(command) and not confirm:
        return False, "Comando destructivo: confirme que desea ejecutarlo en el equipo real", True
    return True, "Permitido (modo administrador)", False


class Session:
    """Una conexión abierta con un hilo que lee continuamente la salida del equipo."""

    def __init__(self, kind: str, target: str, baudrate: int, operator: str, device: dict | None):
        if not HAVE_SERIAL:
            raise RuntimeError("Falta el paquete pyserial: ejecute  pip install -r requirements.txt")
        self.kind, self.target, self.baudrate = kind, target, baudrate
        self.operator, self.device = operator, device
        self.mode = "lectura"
        self.opened_at = time.time()
        self.commands = 0
        url = {"serial": target, "tcp": f"socket://{target}", "loop": "loop://"}[kind]
        self.port = serial.serial_for_url(url, baudrate=baudrate, bytesize=8, parity="N",
                                          stopbits=1, timeout=0.2, write_timeout=2)
        self._chunks: list[tuple[int, str]] = []
        self._seq = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    # ---------------------------------------------------------------- lectura
    def _reader(self):
        while not self._stop.is_set():
            try:
                data = self.port.read(4096)
            except Exception as e:            # cable desconectado, puerto cerrado...
                self._push(f"\n[NOC] Conexión interrumpida: {type(e).__name__}\n")
                self._stop.set()
                break
            if data:
                text = clean_output(data)
                if text:
                    self._push(text)

    def _push(self, text: str):
        with self._lock:
            self._seq += 1
            self._chunks.append((self._seq, text))
            if len(self._chunks) > MAX_BUFFER_CHUNKS:
                self._chunks = self._chunks[-MAX_BUFFER_CHUNKS:]

    def read_since(self, seq: int) -> tuple[int, str]:
        with self._lock:
            text = "".join(t for s, t in self._chunks if s > seq)
            return self._seq, text

    @property
    def alive(self) -> bool:
        return not self._stop.is_set()

    # ---------------------------------------------------------------- escritura
    def write_line(self, command: str, eol: str = "\r\n"):
        self.port.write((command + eol).encode("utf-8"))
        self.commands += 1

    def write_raw(self, data: bytes):
        self.port.write(data)

    def send_break(self):
        if self.kind == "serial":
            self.port.send_break(0.5)
        else:
            self.port.write(b"\x1b")      # sin línea serial no hay BREAK real

    def close(self):
        self._stop.set()
        try:
            self.port.close()
        except Exception:
            pass

    def info(self) -> dict:
        return {"kind": self.kind, "target": self.target, "baudrate": self.baudrate, "mode": self.mode,
                "operator": self.operator, "commands": self.commands, "alive": self.alive,
                "opened_at": self.opened_at,
                "device": {k: self.device[k] for k in ("id", "name", "ip", "vendor")} if self.device else None}


# Teclas especiales del terminal (las que no se pueden escribir en un campo de texto)
SPECIAL_KEYS = {
    "enter": b"\r\n", "space": b" ", "tab": b"\t", "help": b"?", "ctrl_c": b"\x03",
    "ctrl_z": b"\x1a", "ctrl_shift_6": b"\x1e", "esc": b"\x1b", "q": b"q",
}


def validate_target(kind: str, target: str) -> str | None:
    """Devuelve un mensaje de error o None si el destino es válido."""
    if kind == "serial":
        if not re.fullmatch(r"(COM\d{1,3}|/dev/tty[A-Za-z0-9_]{1,20})", target or ""):
            return "Puerto serial inválido (ej. COM3 o /dev/ttyUSB0)"
    elif kind == "tcp":
        m = re.fullmatch(r"([A-Za-z0-9.\-]{1,253}):(\d{1,5})", target or "")
        if not m or not 1 <= int(m.group(2)) <= 65535:
            return "Destino TCP inválido (ej. 127.0.0.1:5000)"
        host = m.group(1)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*", host):
                return "Nombre de host inválido"
    elif kind != "loop":
        return "Tipo de conexión inválido (serial | tcp)"
    return None


# Comandos que hacen que el propio equipo genere un mensaje Syslog de prueba
DEVICE_TEST_COMMANDS = {
    "Cisco": lambda sev, text: [f'send log {sev} "{text}"'],
    "Fortinet": lambda sev, text: ["diagnose log test"],
    "Huawei": lambda sev, text: [],   # VRP no tiene un comando estándar; use la prueba directa
}
