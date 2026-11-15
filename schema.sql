-- =====================================================================
-- NOC Syslog Inteligente v1.0.0 - Modelo de datos (SQLite)
--
--  devices ──< events            un equipo genera muchos eventos
--  devices ──< incidents >── events   un incidente nace de un evento/equipo
--  incidents ──< incident_notes  bitácora de seguimiento
--  incidents ──< actions         comandos PROPUESTOS con aprobación humana
--  audit_log                     quién hizo qué, cuándo y con qué resultado
--  events ──< policy_decisions   decisión del motor de políticas (ALLOW/REVIEW/BLOCK)
--  notifications                 alertas enviadas (o no) a Telegram
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

-- =====================================================================
-- v1.0.0 - Motor de políticas antes de la IA (P01-P06) y Telegram
-- =====================================================================

-- Una fila por evento evaluado (P05: decisión y evidencia auditables).
-- 'secrets' guarda SOLO el tipo de secreto detectado, nunca su valor (P02).
-- 'event_hash' es el SHA-256 del mensaje ORIGINAL: prueba de integridad.
CREATE TABLE IF NOT EXISTS policy_decisions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     INTEGER REFERENCES events(id) ON DELETE CASCADE,
    decision     TEXT NOT NULL CHECK (decision IN ('ALLOW', 'REVIEW', 'BLOCK')),
    policies     TEXT NOT NULL,
    reasons      TEXT,
    evidence     TEXT,
    secrets      TEXT,
    injection    TEXT,
    ai_invoked   INTEGER NOT NULL DEFAULT 0,
    event_hash   TEXT NOT NULL,
    reviewed_by  TEXT,
    review_note  TEXT,
    reviewed_at  TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_event    ON policy_decisions(event_id);
CREATE INDEX IF NOT EXISTS idx_decisions_decision ON policy_decisions(decision);

-- Historial de notificaciones a Telegram (el texto ya va redactado).
CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    channel    TEXT NOT NULL DEFAULT 'telegram',
    kind       TEXT NOT NULL,
    event_id   INTEGER,
    incident_id INTEGER,
    text       TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('enviada', 'fallida', 'desactivada')),
    detail     TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_ts ON notifications(created_at);

-- ---------------------------------------------------------------------------
-- v1.0.0 - Usuarios del NOC (inicio de sesión con roles).
-- La contraseña NUNCA se guarda: solo su hash (scrypt/pbkdf2 de Werkzeug con sal).
-- Roles: administrador (todo), operador (opera, no administra), monitoreo (solo lectura).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    full_name       TEXT    NOT NULL,
    role            TEXT    NOT NULL CHECK (role IN ('administrador', 'operador', 'monitoreo')),
    password_hash   TEXT    NOT NULL,
    active          INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,                 -- bloqueo temporal tras 5 intentos fallidos
    last_login      TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    -- Doble factor TOTP (RFC 6238). Las bases de v1.0.0 anteriores reciben estas columnas
    -- con ALTER TABLE al iniciar (auth.migrate).
    totp_secret       TEXT,               -- Base32; solo cuando totp_enabled = 1
    totp_enabled      INTEGER NOT NULL DEFAULT 0,
    totp_last_counter INTEGER,            -- último intervalo usado: impide repetir un código
    recovery_codes    TEXT                -- JSON con los HASH de los códigos de recuperación no usados
);

-- ---------------------------------------------------------------------------
-- Observabilidad: dependencias entre equipos y sondeos de disponibilidad.
-- ---------------------------------------------------------------------------
-- child depende de parent (p. ej. el AP depende del switch, el switch del router).
CREATE TABLE IF NOT EXISTS device_links (
    child_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    parent_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL,
    PRIMARY KEY (child_id, parent_id),
    CHECK (child_id <> parent_id)
);

-- Resultado de cada sondeo: ICMP real para equipos reales, simulado para los SIM-.
CREATE TABLE IF NOT EXISTS device_checks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts         TEXT    NOT NULL,
    ok         INTEGER NOT NULL CHECK (ok IN (0, 1)),
    latency_ms REAL,
    method     TEXT    NOT NULL CHECK (method IN ('icmp', 'simulado', 'manual'))
);
CREATE INDEX IF NOT EXISTS idx_checks_device_ts ON device_checks (device_id, ts);
