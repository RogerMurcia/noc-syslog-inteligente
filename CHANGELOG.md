# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y
[Versionado Semántico 2.0.0](https://semver.org/lang/es/).

## [1.0.0] - 2026-11-14 · Corte 3 (entrega final)

### Agregado
- **Motor de políticas P01–P06** (`security/policy_engine.py`): cada evento recibe una decisión
  determinista **ALLOW / REVIEW / BLOCK** antes de cualquier análisis de IA.
- **P02 · Redacción de secretos**: contraseñas, tokens, comunidades SNMP y llaves privadas se
  reemplazan por `[REDACTADO]` antes de guardar, mostrar o enviar; se conserva el hash SHA-256 del original.
- **P06 · Detección de prompt injection** indirecta en los logs: BLOCK, la IA no se invoca, incidente y alerta.
- **Correlación de fuerza bruta**: 5 fallos de acceso del mismo origen en 5 minutos abren un incidente,
  aunque los mensajes se dedupliquen.
- **Asistente de IA de solo lectura** (`asistente_ia.py`): qué pasó, riesgo, causas, posibles soluciones,
  comandos de verificación de la lista permitida y mejoras recomendadas para la red.
- **Alertas a Telegram** (`telegram_noc.py`) con límite por minuto y falla segura, y **bot de consulta**
  (`bot_telegram.py`) con `/estado`, `/alertas`, `/incidentes`, `/analizar N`, `/mejoras`…
- **Consola de equipos reales** (`consola_real.py`): puerto serial (COM) y Telnet/GNS3, modos solo lectura y
  administrador, confirmación de comandos destructivos, aplicación de la configuración Syslog y pruebas hacia Telegram.
- **Simulador continuo**: `python simulador.py --continuo` envía cada 2 minutos tráfico normal y un escenario de alerta.
- **Inicio de sesión con roles** (`auth.py`, `templates/login.html`): administrador, operador y monitoreo
  (solo lectura); contraseñas con hash y sal, bloqueo de 5 minutos tras 5 intentos fallidos (con aviso a
  Telegram), token CSRF, sesión de 8 horas, gestión de usuarios y cambio de contraseña desde la web.
  El responsable de cada acción es el usuario con sesión iniciada (no se puede suplantar).
- **Doble factor de autenticación TOTP** (`totp.py`, RFC 6238 sobre RFC 4226, verificado con los vectores
  oficiales): activación con código QR desde «Mi cuenta», 8 códigos de recuperación de un solo uso (con hash),
  protección contra repetición, tolerancia de ±30 s, bloqueo tras 5 códigos errados y reinicio por el administrador.
  La cuenta admin de demostración lo trae activo (QR y códigos en el README).
- **Observabilidad y mapa de dependencias** (`observabilidad.py`, vista *Observabilidad*): sondeo de disponibilidad
  cada 60 s (ICMP para equipos reales, simulado para los SIM-), salud 0–100, disponibilidad y latencia de 24 h,
  dependencias entre equipos, análisis de impacto y causa raíz, aviso a Telegram al caer o recuperarse un equipo,
  comando `/salud` del bot. Tablas `device_links` y `device_checks`.
- **Inicio con doble clic**: `iniciar_noc.bat` (Windows) e `iniciar_noc.sh` (Linux/macOS).
- Tablas `policy_decisions`, `notifications` y `users`; revisión humana de decisiones (P04).
- Interfaz web oscura de una sola página con 13 secciones (Panel, Eventos, Incidentes, Inventario,
  Observabilidad, Políticas IA, Asistente, Telegram, Configuraciones, Consola, Auditoría, Usuarios y Proyecto).
- 92 pruebas automáticas nuevas (`test_politicas.py`, `test_consola_real.py`, `test_usuarios.py`,
  `test_mfa_observabilidad.py`); con las 24 de regresión de v0.2.0 suman 116.
- Documentación del Corte 3 en `docs/` (informe, manuales, bitácora, guion) y script `scripts/publicar_github.bat`.
- Archivo de prueba multivendor `muestras/eventos_multivendor.log` (Cisco, Fortinet y Huawei).

### Cambiado
- La ingesta (`noc.ingest`) orquesta motor de políticas → incidente → asistente → Telegram.
- El receptor muestra la decisión de cada evento y el estado de la alerta.
- `/politicas` abre la misma aplicación directamente en Políticas IA.

### Seguridad
- El actor `asistente_ia` no puede ejecutar comandos, aprobar acciones, revisar decisiones ni usar la consola real.
- El token de Telegram solo vive en `.env` y nunca se expone por la API.
- La auditoría de la consola real oculta contraseñas y no guarda la salida del equipo.

## [0.2.0] - 2026-10-14 · Corte 2 (MVP)

### Agregado
- Recepción Syslog UDP, parser RFC 3164/5424 y formatos Cisco, Fortinet y Huawei.
- Inventario, dashboard, filtros, importación de registros.
- Incidentes con ciclo de vida y acciones con aprobación humana.
- Plantillas de configuración Syslog por fabricante y consola simulada de solo lectura.
- Política inicial de defensa frente a agentes de IA, auditoría y 24 pruebas funcionales.
