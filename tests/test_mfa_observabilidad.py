"""
Pruebas del doble factor TOTP (RFC 6238 / RFC 4226) y de la observabilidad con mapa de dependencias.

Ejecutar:  python -m pytest tests/test_mfa_observabilidad.py -v
"""
import base64
import random
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import auth                    # noqa: E402
import noc                     # noqa: E402
import observabilidad as obs   # noqa: E402
import telegram_noc            # noqa: E402
import totp                    # noqa: E402
from app import create_app     # noqa: E402

PW = {"admin": "Admin.NOC2026", "operador": "Operador.NOC2026", "monitoreo": "Monitoreo.NOC2026"}
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


@pytest.fixture(autouse=True)
def sin_red(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ENABLED", "0")
    for env in ("NOC_ADMIN_PASSWORD", "NOC_ADMIN_TOTP_SECRET", "NOC_ADMIN_MFA", "SECRET_KEY"):
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setattr(telegram_noc, "api_call", lambda *a, **k: (_ for _ in ()).throw(AssertionError("red")))
    monkeypatch.setattr(obs, "icmp_probe", lambda ip, timeout_s=1.0: (_ for _ in ()).throw(AssertionError("ping")))


@pytest.fixture
def app(tmp_path):
    a = create_app(tmp_path / "t.db")
    a.config.update(TESTING=True, AUTH_REQUIRED=True)
    return a


@pytest.fixture
def conn(app):
    c = noc.connect(app.config["DATABASE_PATH"])
    yield c
    c.close()


def session_of(c):
    with c.session_transaction() as s:
        return s.get("csrf")


def login(app, user, code=None):
    c = app.test_client()
    r = c.post("/login", json={"username": user, "password": PW[user]})
    if r.get_json().get("mfa_required"):
        r = c.post("/login/mfa", json={"code": code or totp.totp(auth.DEMO_ADMIN_TOTP_SECRET)})
    return c, r, (session_of(c) if r.status_code == 200 else None)


def put(c, csrf, url, payload):
    return c.put(url, json=payload, headers={"X-CSRF-Token": csrf})


def post(c, csrf, url, payload=None):
    return c.post(url, json=payload or {}, headers={"X-CSRF-Token": csrf})


# =========================================================================== TOTP
def test_vectores_rfc_4226_hotp():
    esperados = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
    assert [totp.hotp(RFC_SECRET, i) for i in range(10)] == esperados


@pytest.mark.parametrize("t,code", [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                                    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")])
def test_vectores_rfc_6238_totp(t, code):
    assert totp.totp(RFC_SECRET, t, digits=8) == code


def test_ventana_y_repeticion():
    s = totp.generate_secret()
    t = 1_800_000_000
    assert totp.verify(s, totp.totp(s, t - 30), ts=t) is not None        # 30 s de desfase: aceptado
    assert totp.verify(s, totp.totp(s, t - 90), ts=t) is None            # 90 s: rechazado
    c = totp.verify(s, totp.totp(s, t), ts=t)
    assert totp.verify(s, totp.totp(s, t), last_counter=c, ts=t) is None  # mismo código dos veces: rechazado
    assert totp.verify(s, "12345", ts=t) is None and totp.verify(s, "abcdef", ts=t) is None
    assert totp.provisioning_uri("admin", s).startswith("otpauth://totp/NOC%20Syslog%20Inteligente%3Aadmin?secret=")


def test_admin_exige_segundo_factor(app):
    c = app.test_client()
    r = c.post("/login", json={"username": "admin", "password": PW["admin"]})
    assert r.status_code == 200 and r.get_json()["mfa_required"] is True
    assert c.get("/api/events").status_code == 401                   # la contraseña sola no abre sesión
    assert c.post("/login/mfa", json={"code": "000000"}).status_code == 401
    code = totp.totp(auth.DEMO_ADMIN_TOTP_SECRET)
    assert c.post("/login/mfa", json={"code": code}).status_code == 200
    assert c.get("/api/me").get_json()["user"]["mfa"] is True
    # el mismo código no sirve para un segundo ingreso
    c2 = app.test_client()
    c2.post("/login", json={"username": "admin", "password": PW["admin"]})
    assert c2.post("/login/mfa", json={"code": code}).status_code == 401


def test_segundo_factor_sin_contrasena_previa(app):
    c = app.test_client()
    assert c.post("/login/mfa", json={"code": totp.totp(auth.DEMO_ADMIN_TOTP_SECRET)}).status_code == 401


def test_codigo_de_recuperacion_un_solo_uso(app):
    rc = auth.DEMO_ADMIN_RECOVERY[0]
    _, r, _ = login(app, "admin", code=rc)
    assert r.status_code == 200
    _, r2, _ = login(app, "admin", code=rc)
    assert r2.status_code == 401
    c, _, csrf = login(app, "admin", code=auth.DEMO_ADMIN_RECOVERY[1])
    me = next(u for u in c.get("/api/users").get_json() if u["username"] == "admin")
    assert me["recovery_left"] == len(auth.DEMO_ADMIN_RECOVERY) - 2


def test_bloqueo_por_segundo_factor(app):
    c = app.test_client()
    for i in range(auth.MAX_FAILED):
        c.post("/login", json={"username": "admin", "password": PW["admin"]})
        r = c.post("/login/mfa", json={"code": "111111"})
    assert r.status_code == 423
    r = app.test_client().post("/login", json={"username": "admin", "password": PW["admin"]})
    assert r.status_code == 423


def test_activar_y_desactivar_doble_factor_propio(app):
    c, _, csrf = login(app, "operador")
    s = post(c, csrf, "/api/me/mfa/setup").get_json()
    assert s["qr"].startswith("data:image/svg+xml") and len(s["secret"].replace(" ", "")) == 32
    secret = s["secret"].replace(" ", "")
    assert post(c, csrf, "/api/me/mfa/enable", {"code": "000000"}).status_code == 400
    r = post(c, csrf, "/api/me/mfa/enable", {"code": totp.totp(secret)})
    codes = r.get_json()["recovery_codes"]
    assert r.status_code == 200 and len(codes) == 8
    # ahora el ingreso del operador pide el código
    c2 = app.test_client()
    assert c2.post("/login", json={"username": "operador", "password": PW["operador"]}).get_json()["mfa_required"]
    assert c2.post("/login/mfa", json={"code": codes[0]}).status_code == 200
    # desactivar exige contraseña y un código válido
    assert post(c, csrf, "/api/me/mfa/disable", {"password": "mala-1234", "code": codes[1]}).status_code == 403
    assert post(c, csrf, "/api/me/mfa/disable", {"password": PW["operador"], "code": codes[1]}).status_code == 200


def test_administrador_reinicia_doble_factor_y_no_se_expone_el_secreto(app):
    c, _, csrf = login(app, "operador")
    secret = post(c, csrf, "/api/me/mfa/setup").get_json()["secret"].replace(" ", "")
    post(c, csrf, "/api/me/mfa/enable", {"code": totp.totp(secret)})
    adm, _, acsrf = login(app, "admin")
    users = adm.get("/api/users").get_json()
    assert all("totp_secret" not in u and "recovery_codes" not in u for u in users)
    uid = next(u["id"] for u in users if u["username"] == "operador")
    assert put(adm, acsrf, f"/api/users/{uid}", {"reset_mfa": True}).status_code == 200
    r = app.test_client().post("/login", json={"username": "operador", "password": PW["operador"]})
    assert r.status_code == 200 and not r.get_json().get("mfa_required")


def test_migracion_desde_tabla_de_usuarios_anterior(tmp_path):
    conn = noc.connect(tmp_path / "vieja.db")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, "
                 "full_name TEXT NOT NULL, role TEXT NOT NULL, password_hash TEXT NOT NULL, active INTEGER NOT NULL "
                 "DEFAULT 1, failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT, last_login TEXT, "
                 "created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
    conn.execute("INSERT INTO users (username, full_name, role, password_hash, created_at, updated_at) VALUES "
                 "('admin', 'A', 'administrador', ?, 'x', 'x')", (auth.hash_password(PW["admin"]),))
    conn.commit()
    added = auth.migrate(conn)
    assert set(added) == set(auth.MFA_COLUMNS)
    row = conn.execute("SELECT totp_enabled, totp_secret FROM users WHERE username = 'admin'").fetchone()
    assert row["totp_enabled"] == 1 and row["totp_secret"] == auth.DEMO_ADMIN_TOTP_SECRET
    assert auth.migrate(conn) == []                                      # idempotente


# =========================================================================== observabilidad
def test_dependencias_de_demostracion(conn):
    names = {r["id"]: r["name"] for r in conn.execute("SELECT id, name FROM devices")}
    got = {(names[c], names[p]) for c, p in obs.links(conn)}
    assert got == set(obs.DEMO_LINKS)


def test_causa_raiz_e_impacto(conn):
    topo = obs.topology(conn)
    by = {n["name"]: n for n in topo["nodes"]}
    assert by["SIM-BR-SW02"]["state"] == "caido" and by["SIM-BR-SW02"]["impact"] == ["SIM-LAB-AP01"]
    ap = by["SIM-LAB-AP01"]
    assert ap["state"] == "afectado" and ap["root_cause"] == ["SIM-BR-SW02"]
    assert topo["summary"]["root_causes"] == ["SIM-BR-SW02"]
    assert by["SIM-CORE-RTR01"]["layer"] == 1 and by["SIM-EDGE-FW01"]["layer"] == 0
    assert all(n["health"] is None or 0 <= n["health"] <= 100 for n in topo["nodes"])


def test_sondeos_simulados_coherentes(conn):
    rnd = random.Random(7)
    for _ in range(6):
        obs.run_probes(conn, rnd=rnd)
    by = {n["name"]: n for n in obs.topology(conn)["nodes"]}
    assert by["SIM-BR-SW02"]["availability"] == 0.0
    assert by["SIM-LAB-AP01"]["availability"] == 0.0 and by["SIM-LAB-AP01"]["state"] == "afectado"
    assert by["SIM-CORE-RTR01"]["availability"] == 100.0 and by["SIM-CORE-RTR01"]["state"] in ("operativo", "degradado")
    assert by["SIM-EDGE-FW01"]["latency_avg_ms"] > by["SIM-CORE-RTR01"]["latency_avg_ms"]   # en alerta: más lento
    assert by["SIM-EDGE-FW01"]["state"] == "degradado"
    assert {c["method"] for c in conn.execute("SELECT DISTINCT method FROM device_checks")} == {"simulado"}


def test_equipo_real_caido_por_sondeo_y_dependientes_afectados(conn, monkeypatch):
    conn.execute("UPDATE devices SET is_simulated = 0 WHERE name = 'SIM-CORE-RTR01'")
    conn.commit()
    monkeypatch.setattr(obs, "icmp_probe", lambda ip, timeout_s=1.0: (False, None))
    for _ in range(obs.DOWN_AFTER):
        obs.run_probes(conn, rnd=random.Random(1))
    by = {n["name"]: n for n in obs.topology(conn)["nodes"]}
    assert by["SIM-CORE-RTR01"]["state"] == "caido"
    for dep in ("SIM-DIST-SW01", "SIM-BR-RTR02"):
        assert by[dep]["state"] == "afectado" and by[dep]["root_cause"] == ["SIM-CORE-RTR01"]
    assert "SIM-LAB-AP01" in by["SIM-CORE-RTR01"]["impact"]
    # SIM-LAB-AP01 cuelga de dos equipos caídos: la causa raíz es el más alto
    assert by["SIM-LAB-AP01"]["root_cause"] == ["SIM-CORE-RTR01"]


def test_ping_valida_la_ip():
    import importlib
    real = importlib.reload(obs)
    with pytest.raises(ValueError):
        real.icmp_probe("127.0.0.1; del /q *")


def test_avisos_de_caida_y_recuperacion(conn):
    obs._last_own.clear(); obs._notified_down.clear()
    sent = []
    obs.check_transitions(conn, sent.append)                             # primer estado: no avisa
    conn.execute("UPDATE devices SET status = 'caido' WHERE name = 'SIM-DIST-SW01'")
    conn.commit()
    ch = obs.check_transitions(conn, sent.append)
    assert ch == [{"device": "SIM-DIST-SW01", "event": "caido", "impact": []}] and "Equipo caído" in sent[-1]
    conn.execute("UPDATE devices SET status = 'activo' WHERE name = 'SIM-DIST-SW01'")
    conn.commit()
    assert obs.check_transitions(conn, sent.append)[0]["event"] == "recuperado"
    assert any(a["action"] == "obs.down" for a in conn.execute("SELECT action FROM audit_log"))


def test_solo_avisa_la_causa_raiz(conn):
    """Si cae el núcleo, SIM-BR-SW02 (ya caído) pasa a «afectado» sin anunciarse como recuperado."""
    obs._last_own.clear(); obs._notified_down.clear()
    sent = []
    obs.check_transitions(conn, sent.append)
    conn.execute("UPDATE devices SET status = 'caido' WHERE name = 'SIM-CORE-RTR01'")
    conn.commit()
    ch = obs.check_transitions(conn, sent.append)
    assert [c["device"] for c in ch] == ["SIM-CORE-RTR01"] and ch[0]["event"] == "caido"
    assert set(ch[0]["impact"]) == {"SIM-DIST-SW01", "SIM-BR-RTR02", "SIM-BR-SW02", "SIM-LAB-AP01"}
    conn.execute("UPDATE devices SET status = 'activo' WHERE name = 'SIM-CORE-RTR01'")
    conn.commit()
    ch = obs.check_transitions(conn, sent.append)
    assert ch == [{"device": "SIM-CORE-RTR01", "event": "recuperado"}]
    assert not any("SIM-BR-SW02</b> vuelve" in m for m in sent)


def test_api_topologia_y_permisos(app, conn):
    mon, _, mcsrf = login(app, "monitoreo")
    topo = mon.get("/api/topology").get_json()
    assert topo["summary"]["total"] == 7 and len(topo["edges"]) == 5
    ids = {n["name"]: n["id"] for n in topo["nodes"]}
    assert post(mon, mcsrf, f"/api/devices/{ids['SIM-CORE-RTR01']}/probe").status_code == 403
    op, _, ocsrf = login(app, "operador")
    r = post(op, ocsrf, f"/api/devices/{ids['SIM-CORE-RTR01']}/probe")
    assert r.status_code == 200 and r.get_json()["method"] == "simulado"
    assert put(op, ocsrf, f"/api/devices/{ids['SIM-CORE-RTR01']}/dependencies", {"parents": []}).status_code == 403
    h = op.get(f"/api/devices/{ids['SIM-LAB-AP01']}/health").get_json()
    assert h["parent_names"] == ["SIM-BR-SW02"] and h["state"] == "afectado"


def test_api_dependencias_valida_ciclos(app):
    adm, _, csrf = login(app, "admin")
    ids = {n["name"]: n["id"] for n in adm.get("/api/topology").get_json()["nodes"]}
    core, dist = ids["SIM-CORE-RTR01"], ids["SIM-DIST-SW01"]
    assert put(adm, csrf, f"/api/devices/{core}/dependencies", {"parents": [dist]}).status_code == 409   # ciclo
    assert put(adm, csrf, f"/api/devices/{core}/dependencies", {"parents": [core]}).status_code == 400   # sí mismo
    assert put(adm, csrf, f"/api/devices/{core}/dependencies", {"parents": [999]}).status_code == 400
    r = put(adm, csrf, f"/api/devices/{ids['SIM-GEN-LOCAL']}/dependencies", {"parents": [core]})
    assert r.status_code == 200
    topo = adm.get("/api/topology").get_json()
    assert {"child": ids["SIM-GEN-LOCAL"], "parent": core} in topo["edges"]


def test_equipo_en_mantenimiento_no_se_sondea(app, conn):
    conn.execute("UPDATE devices SET status = 'mantenimiento' WHERE name = 'SIM-BR-RTR02'")
    conn.commit()
    op, _, csrf = login(app, "operador")
    did = conn.execute("SELECT id FROM devices WHERE name = 'SIM-BR-RTR02'").fetchone()[0]
    assert post(op, csrf, f"/api/devices/{did}/probe").status_code == 409
    by = {n["name"]: n for n in op.get("/api/topology").get_json()["nodes"]}
    assert by["SIM-BR-RTR02"]["state"] == "mantenimiento"


def test_bot_salud_indica_causa_raiz(conn):
    import bot_telegram
    txt = bot_telegram.handle(conn, "/salud", "1", True)
    assert "Revisar primero: <b>SIM-BR-SW02</b>" in txt and "causa raíz: SIM-BR-SW02" in txt
