# NOC Syslog Inteligente v1.0.0 — Entrega final (Corte 3)

**Principio de diseño:** la IA asesora; las políticas y el humano conservan el control.

## Novedades
- Motor de políticas P01–P06 con decisión determinista ALLOW / REVIEW / BLOCK antes de la IA.
- Redacción de secretos (P02) y bloqueo de prompt injection indirecta (P06).
- Detección de fuerza bruta por correlación.
- Asistente de IA de solo lectura: causas, posibles soluciones, verificación y mejoras.
- Alertas y bot de consulta en Telegram.
- Consola de equipos reales por puerto serial y Telnet/GNS3 (modos lectura y administrador).
- Simulador de pruebas automáticas cada 2 minutos.
- Nueva interfaz web oscura con 13 secciones.
- Inicio de sesión con tres roles: administrador, operador y monitoreo (solo lectura); contraseñas con hash,
  bloqueo tras 5 intentos fallidos, protección CSRF y gestión de usuarios desde la web.
- Doble factor TOTP (RFC 6238): QR, códigos de recuperación, protección contra repetición.
- Observabilidad: disponibilidad, latencia, salud, mapa de dependencias, impacto y causa raíz.
- Inicio con doble clic: `iniciar_noc.bat` (Windows) o `iniciar_noc.sh` (Linux/macOS).

## Usuarios de demostración
| Usuario | Contraseña | Rol |
|---|---|---|
| `admin` | `Admin.NOC2026` + código TOTP (QR en el README) | Administrador |
| `operador` | `Operador.NOC2026` | Operador |
| `monitoreo` | `Monitoreo.NOC2026` | Monitoreo (solo lectura) |

Se crean solos la primera vez. El administrador puede cambiarlas en la sección Usuarios.

## Instalación
Con doble clic: descomprima y ejecute `iniciar_noc.bat` (requiere Python 3.10+). O manualmente:
```bat
git clone https://github.com/RogerMurcia/noc-syslog-inteligente.git
cd noc-syslog-inteligente
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

## Pruebas
`python -m pytest -q` → 116 pruebas: 92 nuevas de v1.0.0 + 24 de regresión de v0.2.0.

## Actualizar desde v0.2.0
La base de datos existente se conserva: las tablas nuevas se crean solas al iniciar.
Rollback: `git checkout v0.2.0` (las tablas nuevas no afectan a la versión anterior).

Todos los equipos y eventos de prueba son simulados (nombres SIM-*, IP de documentación RFC 5737).
