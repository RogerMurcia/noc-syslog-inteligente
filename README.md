# NOC Syslog Inteligente — v1.0.0 (Proyecto final)

Aplicación web para recibir, clasificar y gestionar eventos **Syslog** de equipos Cisco, Fortinet y Huawei,
con un **motor de políticas que actúa antes de la IA**, un **asistente de solo lectura** que explica eventos y
propone soluciones, y **alertas por Telegram**.

> **Principio de diseño:** la IA asesora; las políticas y el humano conservan el control.

**Autor:** Roger Fabian Murcia Fino · Administración y Gestión de Redes · UCompensar · 2026-2
**Repositorio:** https://github.com/RogerMurcia/noc-syslog-inteligente

> Todos los equipos y eventos de prueba son **DATOS SIMULADOS** (nombres `SIM-*`, IP de documentación RFC 5737).
> La consola simulada y la ejecución de acciones desde Incidentes no tocan ningún equipo; solo la
> **Consola → Equipo real** se conecta a un equipo (serial o Telnet/GNS3), con modo lectura y modo administrador.

---

## Revisión rápida (docente)

1. Instale **Python 3.10 o superior** desde [python.org](https://www.python.org/downloads/) marcando *Add python.exe to PATH*.
2. Descargue el repositorio (**Code → Download ZIP**) o `git clone https://github.com/RogerMurcia/noc-syslog-inteligente.git`.
3. Doble clic en **`iniciar_noc.bat`** (Windows) o `./iniciar_noc.sh` (Linux/macOS): instala lo necesario la primera vez,
   abre la aplicación, el receptor Syslog y el simulador (eventos cada 2 minutos) y el navegador en **http://127.0.0.1:5000**.
4. Ingrese con cualquiera de estas cuentas de demostración:

| Usuario | Contraseña | Rol | Puede |
|---|---|---|---|
| `admin` | `Admin.NOC2026` + código TOTP | Administrador | Todo: usuarios, inventario, dependencias, consola real en modo administrador |
| `operador` | `Operador.NOC2026` | Operador | Eventos, incidentes, acciones (propone y aprueba las de otros), revisiones, consola en lectura |
| `monitoreo` | `Monitoreo.NOC2026` | Monitoreo | Solo lectura: paneles, eventos, incidentes, políticas y auditoría |

**Doble factor de `admin` (TOTP, RFC 6238).** Después de la contraseña se pide un código de 6 dígitos:

1. Instale en el celular Google Authenticator, Microsoft Authenticator o Authy.
2. Escanee este QR (o escriba la clave `R4PW XMW3 OGAM 3BS6 TE42 32EK SNMB REEI`, tipo «basada en tiempo»):

   <img src="docs/mfa_admin_demo.png" alt="QR del doble factor de la cuenta admin de demostración" width="180">

3. Escriba el código que muestra la app. El reloj del computador debe estar en hora (±30 s).

¿Sin celular? Use un **código de recuperación** (cada uno sirve una sola vez):
`y32x-hzgs` · `smpy-rz66` · `tvx7-6ndb` · `za8c-ek8g` · `cc5e-hev7` · `z3mf-c6cf` · `yn4g-abut` · `cbmk-xtgr`,
o ingrese con `operador` / `monitoreo`, que no tienen el doble factor activo (cada usuario puede activarlo en **Mi cuenta**).

Las cuentas se crean solas la primera vez (contraseñas guardadas solo como hash). El administrador puede cambiarlas
en **Usuarios**; cada usuario puede cambiar la suya con **Cambiar clave**. Cinco intentos fallidos bloquean la cuenta 5 minutos.
¿Olvidó una contraseña? `python usuarios.py clave admin NuevaClave2026` (también `listar`, `desbloquear <usuario>`
y `sin2fa <usuario>` para quitar el doble factor si se perdió el celular).
No se necesita Internet ni Telegram para revisar el proyecto. La documentación completa está en [`docs/`](docs/).

## Qué hay de nuevo en la v1.0.0

| Mejora | Dónde |
|---|---|
| **Motor de políticas P01–P06** con decisión determinista **ALLOW / REVIEW / BLOCK** antes de la IA | `security/policy_engine.py` |
| **Redacción de secretos** (contraseñas, tokens, comunidades SNMP, llaves) antes de guardar, mostrar o enviar | P02 |
| **Detección de prompt injection** indirecta en logs → BLOCK, la IA no se invoca, incidente y alerta | P06 |
| **Fuerza bruta**: correlación de fallos de acceso del mismo origen (5 en 5 min) aunque se dedupliquen | P04 |
| **Asistente IA de solo lectura**: qué pasó, riesgo, causas, posibles soluciones y comandos de verificación de la lista permitida | `asistente_ia.py` |
| **Mejoras recomendadas** para la red calculadas con el estado del NOC | `asistente_ia.improvements()` |
| **Alertas a Telegram** (BLOCK, REVIEW crítico, incidentes nuevos) con límite por minuto y falla segura | `telegram_noc.py` |
| **Bot de Telegram** de consulta: `/estado` `/alertas` `/incidentes` `/analizar N` `/mejoras`… | `bot_telegram.py` |
| **Interfaz oscura nueva** con 13 secciones y Políticas IA en el menú (también en `/politicas`) | `templates/index.html`, `static/` |
| **Inicio de sesión con 3 roles** (administrador, operador, monitoreo), hash de contraseñas, bloqueo por intentos, CSRF y gestión de usuarios | `auth.py`, `templates/login.html` |
| **Doble factor TOTP (RFC 6238 / RFC 4226)**: QR de activación, códigos de recuperación de un solo uso, protección contra repetición, sin dependencias externas para el cálculo | `totp.py`, `auth.py` |
| **Observabilidad**: sondeo de disponibilidad (ICMP real o simulado), salud 0–100, disponibilidad y latencia de 24 h, **mapa de dependencias**, análisis de impacto y **causa raíz**, aviso a Telegram cuando un equipo cae o se recupera, comando `/salud` | `observabilidad.py`, vista *Observabilidad* |
| **Auditoría de cada decisión** con hash SHA-256 del mensaje original | tabla `policy_decisions` |
| **92 pruebas nuevas** (casos de aceptación, consola real, usuarios y roles, doble factor, observabilidad) + 24 de regresión = **116** | `tests/` |

## Interfaz

Aplicación web oscura de una sola página (sin librerías externas) con menú lateral:

| Sección | Qué permite |
|---|---|
| **Panel** | Compuerta de políticas en vivo (permitidos / en revisión / bloqueados), tráfico de 24 h, anillo de severidades, estado de cada equipo, flujo de eventos, incidentes abiertos y mejoras prioritarias. Se actualiza cada 10 s |
| **Eventos** | Filtros por fecha, fabricante, equipo, severidad y decisión; importación de archivos; clic en un evento = análisis completo, evidencia y revisión humana |
| **Incidentes** | Tablero por estado; detalle con análisis del asistente, asignación, cambio de estado, cierre con resolución, bitácora y acciones con aprobación (doble control) |
| **Inventario** | Tarjetas por equipo con alta, edición, baja y acceso directo a su consola |
| **Políticas IA** | Laboratorio interactivo, decisiones con revisión, catálogo P01–P06 y definición de terminado ejecutable |
| **Asistente** | Mejoras recomendadas y análisis de cualquier evento por número |
| **Telegram** | Estado, mensaje de prueba, vista previa de la última alerta tal como llega al chat, historial y comandos del bot |
| **Configuraciones** · **Consola** · **Auditoría** · **Proyecto** | Plantillas por fabricante con copiar; terminal simulada con lista permitida; registro con búsqueda; ficha del proyecto |
| **Observabilidad** | Estado (operativo, degradado, caído, afectado), salud, disponibilidad y latencia de cada equipo; mapa de dependencias con la causa raíz resaltada; sondeo a demanda; edición de dependencias (administrador) |
| **Usuarios** (solo administrador) | Crear cuentas, cambiar rol, activar/desactivar, desbloquear, restablecer contraseñas y reiniciar el doble factor; tabla de permisos por rol |

La dirección `/politicas` abre la misma aplicación directamente en Políticas IA.

## Consola de equipos reales

En **Consola → Equipo real** el NOC se conecta a un equipo físico o virtual y los comandos **sí llegan al equipo**.

| Conexión | Uso |
|---|---|
| **Puerto serial** | Cable de consola USB-RJ45 (CH340, FTDI, Prolific, CP210x). Lista los puertos COM detectados; 9600 bps 8N1 por defecto (configurable hasta 115200) |
| **Telnet / GNS3** | `host:puerto` de la consola de un nodo de GNS3 (p. ej. `127.0.0.1:5000`) |

- **Solo lectura**: solo pasan los comandos de consulta de la lista permitida del fabricante.
- **Administrador**: configuración completa del equipo; exige aceptar la responsabilidad, envía un aviso a Telegram y pide confirmación en cada comando destructivo (`reload`, `erase`, `delete`, `format`, reset de fábrica…).
- Teclas especiales: Enter, Espacio (`--More--`), Tab, `?`, Ctrl+C, Ctrl+Z, Ctrl+Shift+6, Esc y Break.
- **Aplicar en el equipo**: envía línea por línea la configuración Syslog del NOC (modo administrador).
- **Prueba hacia Telegram**: *Desde el equipo* (`send log` en Cisco, `diagnose log test` en Fortinet; llega si el Syslog del equipo apunta al NOC) o *Directa al NOC* (registra un evento con la IP del equipo y alerta de inmediato).
- Cada comando queda en la auditoría con las contraseñas ocultas; la salida del equipo no se guarda. El asistente IA no puede usar esta consola (P03).

Para que un equipo externo envíe Syslog al NOC: `SYSLOG_HOST=0.0.0.0` en el `.env`, registrar la IP del equipo en el Inventario y permitir el puerto en el firewall de Windows (terminal como administrador):

```bat
netsh advfirewall firewall add rule name="NOC Syslog UDP 5514" dir=in action=allow protocol=UDP localport=5514
```

## Arquitectura

```
EQUIPO ──UDP──> COLECTOR ──> NORMALIZADOR ──> MOTOR DE POLÍTICAS ──┬─ ALLOW  ─> ASISTENTE IA (solo lectura)
Cisco/Forti/     receptor.py   syslog_parser.py   P01..P06           ├─ REVIEW ─> pausa: decide un ANALISTA
Huawei           tormentas     RFC 3164/5424      redacción (P02)    └─ BLOCK  ─> IA NO invocada, se aísla
                                                   │
                         policy_decisions + audit_log (P05) ──> INCIDENTE ──> ALERTA TELEGRAM
```

## Políticas

| ID | Política | Condición | Acción |
|---|---|---|---|
| P01 | El log es dato, no instrucción | Todo mensaje externo | Se trata como NO confiable; nunca se ejecuta ni se usa como prompt |
| P02 | Redactar secretos | Contraseñas, tokens, SNMP, llaves | `[REDACTADO]` antes de guardar, mostrar, analizar o enviar |
| P03 | IA sin herramientas ni SSH | Siempre | El asistente solo explica y propone; no ejecuta ni aprueba |
| P04 | Aprobación humana obligatoria | Severidad 0-3, fuerza bruta, fuente dudosa, mensaje malformado, secretos | **REVIEW** |
| P05 | Auditar decisión y evidencia | Toda decisión | `event_id`, políticas, decisión, motivo, hash y hora |
| P06 | Detectar inyección en campos | Órdenes a la IA, pedido de secretos o de SSH | **BLOCK** + incidente + alerta |

Si se desactiva un control esencial en el laboratorio, el motor nunca devuelve ALLOW: responde
**REVIEW – CONTROL INCOMPLETO** (falla segura).

## Requisitos

- Python 3.10 o superior · navegador web moderno
- (Opcional) cuenta de Telegram para las alertas

## Instalación (Windows)

```bat
git clone https://github.com/RogerMurcia/noc-syslog-inteligente.git
cd noc-syslog-inteligente
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Telegram usa la biblioteca estándar de Python. La consola de equipos reales usa `pyserial` (incluido en `requirements.txt`).

## Ejecución

**Opción rápida:** doble clic en `iniciar_noc.bat` (abre las ventanas de la app, el receptor y el simulador continuo, y el bot si `TELEGRAM_ENABLED=1`).

**Manual:** cada terminal en la carpeta del proyecto y con `.venv\Scripts\activate`:

| Terminal | Comando | Para qué |
|---|---|---|
| 1 | `python app.py` | Web: **http://127.0.0.1:5000** y **http://127.0.0.1:5000/politicas** |
| 2 | `python receptor.py` | Receptor Syslog UDP 127.0.0.1:5514; muestra la decisión de cada evento |
| 3 | `python simulador.py` | Envía 20 mensajes: los 11 originales + enlace activo, credencial en el log, inyección al agente y ráfaga de fuerza bruta |
| 4 (opcional) | `python bot_telegram.py` | Bot de Telegram para consultar el NOC |
| 5 (opcional) | `python simulador.py --continuo` | **Pruebas automáticas**: cada 2 minutos envía tráfico normal y un escenario de alerta al azar (interfaz caída, energía, temperatura, CPU, BGP, fuerza bruta, inyección, credencial expuesta…). Opciones: `--intervalo 60`, `--alertas 2`, `--ciclos 10` |

Si la base de datos es de la versión anterior, las tablas nuevas se crean solas. Para empezar de cero, borre `data\noc.db`.

## Telegram

1. En Telegram abra **@BotFather**, envíe `/newbot` y copie el **token**.
2. En el `.env`: `TELEGRAM_ENABLED=1` y `TELEGRAM_BOT_TOKEN=<token>`.
3. Ejecute `python bot_telegram.py`, abra su bot y envíe `/id`.
4. Copie el número en `TELEGRAM_CHAT_IDS=<chat_id>` (varios separados por coma; un grupo empieza por `-`).
5. Reinicie `app.py`, `receptor.py` y el bot. En **/politicas → Telegram** pulse *Enviar mensaje de prueba*.

**Alertas automáticas** (las envía el receptor): BLOCK, incidente nuevo y REVIEW con severidad ≤ 3,
fuerza bruta o secretos. Cada alerta trae equipo, severidad, decisión, políticas, motivo, qué pasó,
**posibles soluciones**, comandos de verificación y acciones que requieren aprobación.

**Comandos del bot:**

| Comando | Respuesta |
|---|---|
| `/estado` | Equipos, eventos 24 h, decisiones ALLOW/REVIEW/BLOCK, incidentes y acciones pendientes |
| `/alertas` | Últimas 10 decisiones REVIEW y BLOCK |
| `/eventos` | Últimos 10 eventos |
| `/incidentes` · `/incidente N` | Incidentes abiertos · detalle, bitácora, causas y soluciones |
| `/analizar N` | Análisis del evento N |
| `/mejoras` | Mejoras recomendadas para la red, priorizadas |
| `/equipos` · `/politicas` · `/id` · `/ayuda` | Inventario · políticas · chat_id · ayuda |

**Seguridad de la integración:** el token vive solo en `.env` (excluido de Git) y nunca se muestra en la web;
solo los chats autorizados reciben datos (los demás quedan en la auditoría); el texto va redactado y escapado;
el contenido bloqueado no se reenvía; el bot no aprueba ni ejecuta acciones; si Telegram falla, el NOC sigue
funcionando y el intento queda en la tabla `notifications`.

## Pruebas

```bat
python -m pytest -q
```

**116 pruebas**: `test_noc.py` (24, regresión de v0.2.0), `test_politicas.py` (41), `test_consola_real.py` (12),
`test_usuarios.py` (13: login, bloqueo, CSRF, permisos por rol, doble control, gestión de usuarios) y
`test_mfa_observabilidad.py` (26: vectores oficiales de la RFC 4226 y la RFC 6238, ingreso en dos pasos,
recuperación, migración, causa raíz, impacto, sondeos, ciclos de dependencias y permisos).

`tests/test_politicas.py` cubre los casos de aceptación de la clase:

| Caso | Resultado esperado |
|---|---|
| Evento normal | ALLOW y recomendación sustentada |
| Secreto en el log | Dato redactado en la BD, la web y Telegram |
| Prompt injection | BLOCK, IA no invocada, incidente y alerta |
| IA caída | Las reglas siguen operando (se simula una falla del asistente) |
| Determinismo | Mismo evento + mismas políticas = misma decisión |

Además: fuerza bruta con mensajes deduplicados, falsos positivos de inyección, control incompleto,
comandos del asistente dentro de la lista permitida, escape HTML y límite por minuto de Telegram,
falla de red, chat no autorizado, revisión humana (la IA no puede revisar) y que la API no expone el token.

## API nueva

Todas las rutas exigen sesión iniciada (salvo `/login` y `/api/health`); las que modifican datos exigen el
encabezado `X-CSRF-Token` de la sesión y un rol con permiso.

| Método | Ruta | Descripción |
|---|---|---|
| GET · POST | `/login` · POST `/logout` | Inicio y cierre de sesión |
| GET · POST | `/api/me` · `/api/me/password` | Usuario actual · cambiar la propia contraseña |
| GET · POST · PUT | `/api/users` · `/api/users/<id>` | Gestión de usuarios (administrador) |
| POST | `/login/mfa` | Segundo paso del ingreso: código TOTP o de recuperación |
| POST | `/api/me/mfa/setup` · `/enable` · `/disable` | Activar o desactivar el doble factor propio |
| GET | `/api/topology` | Estado, salud, dependencias, impacto y causa raíz |
| GET · POST | `/api/devices/<id>/health` · `/probe` | Detalle con serie de latencia · sondear ahora |
| PUT | `/api/devices/<id>/dependencies` | De qué equipos depende (administrador) |
| GET | `/politicas` | Página de políticas, laboratorio, decisiones, mejoras, Telegram y evidencia |
| GET | `/api/policies` | Catálogo P01–P06 |
| POST | `/api/policies/evaluate` | Laboratorio: evalúa un mensaje con las políticas elegidas (no se guarda) |
| GET | `/api/decisions` | Decisiones registradas (`?decision=BLOCK`, `?pendientes=1`) |
| POST | `/api/decisions/<id>/review` | Revisión humana: `confirmado` o `falso_positivo` + justificación |
| GET | `/api/events/<id>/analysis` | Análisis del asistente |
| GET | `/api/improvements` | Mejoras recomendadas |
| GET | `/api/telegram/status` · POST `/api/telegram/test` | Estado (sin token) · mensaje de prueba |
| GET | `/api/notifications` | Historial de alertas |

## Estructura

```
noc-syslog-inteligente/
├── app.py                 Aplicación web Flask y API REST
├── noc.py                 Base de datos, auditoría, ingesta y orquestación de políticas
├── security/
│   └── policy_engine.py   Motor de políticas P01-P06 (determinista, sin red)
├── asistente_ia.py        Asistente de solo lectura: análisis, soluciones y mejoras
├── telegram_noc.py        Envío de alertas a Telegram
├── bot_telegram.py        Bot de consulta
├── consola_real.py        Consola de equipos reales (serial y Telnet/GNS3)
├── auth.py                Usuarios, contraseñas (hash) y permisos por rol
├── totp.py                Doble factor TOTP (RFC 6238 / RFC 4226)
├── observabilidad.py      Sondeos, salud, dependencias, impacto y causa raíz
├── usuarios.py            Listar usuarios y restablecer contraseñas desde la terminal
├── syslog_parser.py       Parser Syslog (RFC 3164/5424, Cisco, Fortinet, Huawei)
├── plantillas.py          Configuraciones multivendor y consola simulada
├── receptor.py            Receptor Syslog UDP
├── simulador.py           Generador de eventos simulados
├── schema.sql             Modelo de datos
├── templates/             index.html (interfaz) y login.html (ingreso)
├── static/app.js          Lógica de la interfaz
├── static/styles.css      Estilos (modo oscuro)
├── tests/                 test_noc.py, test_politicas.py, test_consola_real.py y test_usuarios.py
├── muestras/              eventos_simulados.log (v0.2.0) y eventos_multivendor.log
├── iniciar_noc.bat / .sh  Inicio con doble clic
├── docs/                  Informe final, manuales, bitácora, guion y notas del release
├── scripts/               publicar_github.bat (publica ramas, commits y etiquetas)
├── CHANGELOG.md           Historial de cambios
└── data/                  Base de datos local (no se versiona)
```

## Documentación (Corte 3)

| Documento | Archivo |
|---|---|
| Informe final | `docs/Informe_Final_NOC_v1.0.0.pdf` (y `.docx` editable) |
| Manual técnico | `docs/Manual_Tecnico_NOC_v1.0.0.pdf` |
| Manual de usuario | `docs/Manual_Usuario_NOC_v1.0.0.pdf` |
| Bitácora de marcha blanca, pruebas, despliegue y rollback | `docs/Bitacora_Marcha_Blanca_NOC_v1.0.0.pdf` |
| Guion de sustentación | `docs/Guion_Sustentacion_NOC_v1.0.0.pdf` |
| Notas del release | `docs/RELEASE_NOTES_v1.0.0.md` · `CHANGELOG.md` |

## Versiones y rollback

`main` contiene las versiones publicadas (etiquetas `v0.2.0` y `v1.0.0`); el desarrollo se integra en `develop`
desde ramas `feature/*`. Para volver a la versión anterior: detener los procesos, respaldar `data\noc.db` y
`git checkout v0.2.0` (v1.0.0 solo agregó tablas). Detalle en la bitácora.

Para publicar el historial preparado en GitHub: `scripts\publicar_github.bat` (sube `main`, `develop`, las ramas
`feature/*` y las etiquetas `v0.2.0` y `v1.0.0`).

## Modelo de datos

`devices` → `events` → `incidents` (+ `incident_notes`, `actions`), `audit_log`,
**`policy_decisions`** (decisión, políticas, motivo, evidencia, tipos de secreto, patrones, hash SHA-256,
revisión humana), **`notifications`** (alertas de Telegram), **`users`** (cuentas, rol, hash de contraseña, bloqueo,
doble factor), **`device_links`** (dependencias entre equipos) y **`device_checks`** (sondeos de disponibilidad).

## Limitaciones

- Las cuentas de demostración tienen contraseñas publicadas para la revisión; en un despliegue real deben cambiarse.
- La ejecución de acciones desde Incidentes es simulada; los cambios reales solo se hacen en Consola → Equipo real
  (modo administrador). El asistente IA nunca tiene acceso a los equipos (P03).
- Consola real validada con un CLI Telnet de laboratorio; falta validarla con un equipo físico.
- El asistente usa una base de conocimiento local; un modelo externo podría agregarse detrás del mismo
  motor de políticas, que seguiría decidiendo primero.
- Syslog por UDP sin TLS (RFC 5425 queda como mejora).
- Fechas en UTC; la web y el bot las muestran en hora de Colombia (UTC-5).
