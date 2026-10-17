# NOC Syslog Inteligente

Aplicación web en **Python/Flask** con **SQLite** para la recepción, clasificación y gestión de eventos **Syslog** en un Centro de Operaciones de Red (NOC).

Proyecto académico del curso *Administración y Gestión de Redes* — Fundación Universitaria Compensar (UCompensar), Bogotá, 2026-2.

**Autor:** Erick Santiago Castro Linares · [@Erick12-hub](https://github.com/Erick12-hub)
**Versión:** 0.2.0 (MVP – Corte 2)

---

## Funcionalidades

| Módulo | Descripción |
|---|---|
| **Dashboard** | Estado de los dispositivos, eventos por severidad, eventos críticos y recientes, incidentes abiertos (actualización cada 15 s) |
| **Inventario** | CRUD de equipos: nombre, IP, marca, modelo, versión, ubicación, estado y fuente autorizada |
| **Eventos** | Recepción UDP e importación de logs (archivo o texto); clasificación por equipo, fabricante, facility y severidad; filtros |
| **Incidentes** | Creación automática (severidad 0-3) o manual; ciclo de vida *abierto → asignado → en progreso → cerrado*; notas y acciones con aprobación humana |
| **Configuraciones** | Plantillas Syslog comentadas para **Cisco**, **Fortinet** y **Huawei** |
| **Consola** | Consola tipo PuTTY **simulada**, de solo lectura, con lista de comandos permitidos |
| **Política IA** | Controles de defensa frente a agentes de IA e indicadores en vivo |
| **Auditoría** | Registro de todas las acciones: fecha, responsable, acción, detalle y resultado |

Formatos soportados por el parser: RFC 3164, RFC 5424, Cisco IOS, Fortinet y Huawei VRP.

## Tecnologías

- Python 3 · Flask · SQLite
- HTML, CSS y JavaScript (interfaz de una sola página)
- pytest (24 pruebas funcionales)

## Instalación (Windows)

```bat
git clone https://github.com/Erick12-hub/noc-syslog-inteligente.git
cd noc-syslog-inteligente
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

## Ejecución

Se usan tres terminales (todas con el entorno virtual activado):

```bat
:: Terminal 1 - aplicación web  ->  http://127.0.0.1:5000
python app.py

:: Terminal 2 - receptor Syslog UDP (puerto 5514)
python receptor.py

:: Terminal 3 - generador de eventos de prueba
python simulador.py
```

También se pueden importar eventos desde la pestaña **Eventos** usando el archivo `muestras/eventos_simulados.log`.

Para reiniciar los datos basta con borrar `data/noc.db` (se vuelve a crear sola).

## Pruebas

```bat
python -m pytest -q
```

## Estructura

```
noc-syslog-inteligente/
├── app.py              Aplicación web Flask y API REST
├── noc.py              Configuración, base de datos, auditoría e ingesta
├── syslog_parser.py    Parser Syslog multivendor
├── plantillas.py       Configuraciones por fabricante y consola simulada
├── receptor.py         Receptor Syslog UDP
├── simulador.py        Generador de eventos simulados
├── schema.sql          Modelo de datos
├── templates/          Interfaz HTML
├── static/             JavaScript y CSS
├── muestras/           Logs de prueba
├── tests/              Pruebas funcionales
└── data/               Base de datos local (no se versiona)
```

## Modelo de datos

`devices` → `events` → `incidents` (+ `incident_notes`, `actions`) y `audit_log`.

## Seguridad

- Solo las **fuentes autorizadas** del inventario generan incidentes.
- Los logs se tratan como **datos no confiables**: nunca se ejecutan y se marcan los intentos de *prompt injection*.
- Consultas SQL parametrizadas (sin inyección SQL) y salida web sin XSS.
- Deduplicación de eventos repetidos y control de tormentas por IP.
- Las acciones propuestas por IA requieren **aprobación humana**; su ejecución es simulada.
- La aplicación escucha solo en `127.0.0.1`.

## Limitaciones conocidas

- Sin alertas por Telegram ni acceso SSH real (previstos para el Corte 3).
- Sin TLS para Syslog (RFC 5425).
- Las fechas se guardan en UTC; los filtros usan la hora de Colombia (UTC-5).
