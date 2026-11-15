"""
Doble factor de autenticación (2FA/MFA) con TOTP - RFC 6238, basado en HOTP - RFC 4226.

Solo usa la biblioteca estándar de Python (hmac, hashlib, base64, struct, time):
compatible con Google Authenticator, Microsoft Authenticator, Authy, 2FAS, etc.

    HOTP(K, C) = Truncar(HMAC-SHA1(K, C)) mod 10^6        (RFC 4226)
    TOTP(K)    = HOTP(K, floor(tiempo_unix / 30))          (RFC 6238)

- Secreto de 160 bits (20 bytes) en Base32, como recomienda la RFC 4226.
- Se aceptan ±1 intervalo (±30 s) de diferencia de reloj.
- Protección contra repetición: un código ya usado (mismo intervalo o anterior) se rechaza.
- Códigos de recuperación de un solo uso, guardados solo como hash.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

DIGITS = 6
PERIOD = 30          # segundos por intervalo
WINDOW = 1           # intervalos de tolerancia hacia atrás y hacia adelante
ISSUER = "NOC Syslog Inteligente"


def generate_secret(nbytes: int = 20) -> str:
    """Secreto aleatorio en Base32 sin relleno (lo que se escanea en el QR)."""
    return base64.b32encode(secrets.token_bytes(nbytes)).decode("ascii").rstrip("=")


def _key(secret_b32: str) -> bytes:
    s = secret_b32.replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(secret_b32: str, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226, sección 5.3: HMAC-SHA1 + truncamiento dinámico."""
    mac = hmac.new(_key(secret_b32), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def counter_at(ts: float | None = None) -> int:
    return int((time.time() if ts is None else ts) // PERIOD)


def totp(secret_b32: str, ts: float | None = None, digits: int = DIGITS) -> str:
    """RFC 6238: HOTP con el contador de tiempo T = floor(t / 30)."""
    return hotp(secret_b32, counter_at(ts), digits)


def verify(secret_b32: str, code: str, last_counter: int | None = None, ts: float | None = None):
    """Devuelve el contador que coincidió, o None.

    Rechaza códigos de otro largo, no numéricos o ya usados (contador <= last_counter)."""
    code = (code or "").replace(" ", "").strip()
    if len(code) != DIGITS or not code.isdigit() or not secret_b32:
        return None
    now = counter_at(ts)
    for c in range(now - WINDOW, now + WINDOW + 1):
        if last_counter is not None and c <= last_counter:
            continue
        if hmac.compare_digest(hotp(secret_b32, c), code):
            return c
    return None


def provisioning_uri(username: str, secret_b32: str, issuer: str = ISSUER) -> str:
    """URI otpauth:// (formato de Google Authenticator) que se codifica en el QR."""
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?" + urlencode({"secret": secret_b32, "issuer": issuer, "algorithm": "SHA1",
                                                    "digits": DIGITS, "period": PERIOD})


def qr_data_uri(data: str) -> str | None:
    """QR como imagen SVG (data URI) con 'segno', pura Python. Sin segno, la interfaz muestra la clave para teclearla."""
    try:
        import segno
    except ImportError:
        return None
    return segno.make(data, error="m").svg_data_uri(scale=5, dark="#0b1220", light="#ffffff", border=2)


def format_secret(secret_b32: str) -> str:
    """'JBSW Y3DP EHPK 3PXP' - más fácil de teclear en la app."""
    return " ".join(secret_b32[i:i + 4] for i in range(0, len(secret_b32), 4))


def generate_recovery_codes(n: int = 8) -> list[str]:
    """Códigos de recuperación 'xxxx-xxxx' (sin caracteres ambiguos)."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return ["".join(secrets.choice(alphabet) for _ in range(4)) + "-" +
            "".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(n)]
