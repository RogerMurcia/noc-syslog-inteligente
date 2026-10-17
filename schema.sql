-- =====================================================================
-- NOC Syslog Inteligente v0.2.0 (MVP) - Modelo de datos (SQLite)
--
--  devices ──< events            un equipo genera muchos eventos
--  devices ──< incidents >── events   un incidente nace de un evento/equipo
--  incidents ──< incident_notes  bitácora de seguimiento
--  incidents ──< actions         comandos PROPUESTOS con aprobación humana
--  audit_log                     quién hizo qué, cuándo y con qué resultado
--
-- Convenciones:
--   * Fechas en ISO 8601 UTC (texto): 2026-10-14T19:30:00Z
--   * is_simulated = 1 identifica TODO dato de prueba (exigencia de la guía).
--   * CREATE TABLE IF NOT EXISTS: se puede ejecutar varias veces sin perder datos.
-- =====================================================================
PRAGMA foreign_keys = ON;

-- Inventario. 'authorized' = lista permitida de FUENTES Syslog.
CREATE TABLE IF NOT EXISTS devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,
    ip           TEXT NOT NULL UNIQUE,
    vendor       TEXT NOT NULL CHECK (vendor IN ('Cisco', 'Fortinet', 'Huawei', 'Otro')),
    model        TEXT,
    version      TEXT,
    location     TEXT,
    status       TEXT NOT NULL DEFAULT 'desconocido'
                 CHECK (status IN ('activo', 'alerta', 'caido', 'mantenimiento', 'desconocido')),
    authorized   INTEGER NOT NULL DEFAULT 1 CHECK (authorized IN (0, 1)),
    is_simulated INTEGER NOT NULL DEFAULT 1 CHECK (is_simulated IN (0, 1)),
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

-- Eventos Syslog. 'raw' es el mensaje original: DATO NO CONFIABLE, nunca se ejecuta.
CREATE TABLE IF NOT EXISTS events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at       TEXT NOT NULL,
    event_time        TEXT,
    source_ip         TEXT NOT NULL,
    device_id         INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    vendor            TEXT,
    facility          INTEGER CHECK (facility BETWEEN 0 AND 23),
    severity          INTEGER NOT NULL CHECK (severity BETWEEN 0 AND 7),
    hostname          TEXT,
    app_name          TEXT,
    mnemonic          TEXT,
    message           TEXT NOT NULL,
    raw               TEXT NOT NULL,
    origin            TEXT NOT NULL CHECK (origin IN ('udp', 'importacion')),
    authorized_source INTEGER NOT NULL DEFAULT 0,
    flags             TEXT,
    fingerprint       TEXT,
    dup_count         INTEGER NOT NULL DEFAULT 1,
    is_simulated      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_fp       ON events(fingerprint);

-- Incidentes: abierto -> asignado -> en_progreso -> cerrado
CREATE TABLE IF NOT EXISTS incidents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    title           TEXT NOT NULL,
    description     TEXT,
    severity        INTEGER NOT NULL CHECK (severity BETWEEN 0 AND 7),
    status          TEXT NOT NULL DEFAULT 'abierto'
                    CHECK (status IN ('abierto', 'asignado', 'en_progreso', 'cerrado')),
    assigned_to     TEXT,
    device_id       INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    event_id        INTEGER REFERENCES events(id) ON DELETE SET NULL,
    correlation_key TEXT,
    event_count     INTEGER NOT NULL DEFAULT 1,
    resolution      TEXT,
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    closed_at       TEXT,
    is_simulated    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS incident_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author      TEXT NOT NULL,
    note        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

-- Flujo seguro: propuesta -> revisión humana -> aprobación -> ejecución (SIMULADA) -> auditoría
CREATE TABLE IF NOT EXISTS actions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id   INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    command       TEXT NOT NULL,
    justification TEXT,
    proposed_by   TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pendiente'
                  CHECK (status IN ('pendiente', 'aprobada', 'rechazada', 'ejecutada')),
    reviewed_by   TEXT,
    reviewed_at   TEXT,
    result        TEXT,
    created_at    TEXT NOT NULL
);

-- Auditoría: solo se inserta; la aplicación nunca la modifica ni la borra.
CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    entity    TEXT,
    entity_id INTEGER,
    detail    TEXT,
    result    TEXT NOT NULL DEFAULT 'ok'
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
