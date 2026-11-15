"""
Pruebas del inicio de sesión y los roles (administrador, operador, monitoreo).

Ejecutar:  python -m pytest tests/test_usuarios.py -v
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import auth                    # noqa: E402
import telegram_noc            # noqa: E402
import totp                    # noqa: E402
from app import create_app     # noqa: E402

PW = {"admin": "Admin.NOC2026", "operador": "Operador.NOC2026", "monitoreo": "Monitoreo.NOC2026"}


@pytest.fixture(autouse=True)
def sin_red(monkeypatch):
    monkeypatch.setenv("TELEGRAM_ENABLED", "0")
    for env in ("NOC_ADMIN_PASSWORD", "NOC_OPERADOR_PASSWORD", "NOC_MONITOREO_PASSWORD", "SECRET_KEY"):
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setattr(telegram_noc, "api_call", lambda *a, **k: (_ for _ in ()).throw(AssertionError("red")))


@pytest.fixture
def app(tmp_path):
    a = create_app(tmp_path / "auth.db")
    a.config.update(TESTING=True, AUTH_REQUIRED=True)
    return a


def login(app, user, pw=None, code=None):
    """Ingreso completo. La cuenta admin de demostración trae doble factor: se responde con su TOTP."""
    c = app.test_client()
    r = c.post("/login", json={"username": user, "password": pw or PW[user]})
    if r.status_code == 200 and r.get_json().get("mfa_required"):
        r = c.post("/login/mfa", json={"code": code or totp.totp(auth.DEMO_ADMIN_TOTP_SECRET)})
    csrf = None
    if r.status_code == 200:
        with c.session_transaction() as s:
            csrf = s["csrf"]
    return c, r, csrf


def post(c, csrf, url, payload=None, method="post"):
    return getattr(c, method)(url, json=payload or {}, headers={"X-CSRF-Token": csrf or ""})


def test_se_crean_los_tres_usuarios_con_hash(app):
    import noc
    conn = noc.connect(app.config["DATABASE_PATH"])
    rows = {r["username"]: r for r in conn.execute("SELECT * FROM users")}
    assert set(rows) == {"admin", "operador", "monitoreo"}
    assert [rows[u]["role"] for u in ("admin", "operador", "monitoreo")] == ["administrador", "operador", "monitoreo"]
    for u, r in rows.items():
        assert PW[u] not in r["password_hash"] and r["password_hash"].startswith(("scrypt:", "pbkdf2:"))
    conn.close()


def test_sin_sesion_no_hay_acceso(app):
    c = app.test_client()
    assert c.get("/api/events").status_code == 401
    r = c.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert c.get("/login").status_code == 200
    assert c.get("/api/health").status_code == 200


def test_login_correcto_e_incorrecto(app):
    c, r, _ = login(app, "admin")
    assert r.status_code == 200 and r.get_json()["user"]["role"] == "administrador"
    assert "password_hash" not in r.get_json()["user"]
    assert c.get("/api/me").get_json()["user"]["username"] == "admin"
    _, bad, _ = login(app, "admin", "otra-clave1")
    _, nouser, _ = login(app, "fantasma", "otra-clave1")
    # mismo mensaje: no revela si el usuario existe
    assert bad.status_code == nouser.status_code == 401
    assert bad.get_json() == nouser.get_json()


def test_bloqueo_tras_cinco_intentos(app):
    for _ in range(auth.MAX_FAILED - 1):
        assert login(app, "operador", "mala-clave1")[1].status_code == 401
    assert login(app, "operador", "mala-clave1")[1].status_code == 423
    # bloqueada aunque ahora la clave sea correcta
    assert login(app, "operador")[1].status_code == 423
    c, _, csrf = login(app, "admin")
    audit = c.get("/api/audit?limit=50").get_json()
    assert any(a["action"] == "login.lock" for a in audit)
    uid = next(u["id"] for u in c.get("/api/users").get_json() if u["username"] == "operador")
    assert post(c, csrf, f"/api/users/{uid}", {"unlock": True}, "put").status_code == 200
    assert login(app, "operador")[1].status_code == 200


def test_csrf_obligatorio(app):
    c, _, csrf = login(app, "operador")
    assert c.post("/api/incidents", json={"title": "Sin token", "severity": 3}).status_code == 403
    assert post(c, csrf, "/api/incidents", {"title": "Con token", "severity": 3}).status_code == 201


def test_monitoreo_solo_lectura(app):
    c, _, csrf = login(app, "monitoreo")
    assert c.get("/api/dashboard").status_code == 200
    assert c.get("/api/audit").status_code == 200
    assert post(c, csrf, "/api/incidents", {"title": "x", "severity": 3}).status_code == 403
    assert post(c, csrf, "/api/console", {"device_id": 1, "command": "show version"}).status_code == 403
    assert post(c, csrf, "/api/policies/evaluate", {"message": "Interface up", "severity": 5}).status_code == 200
    assert c.get("/api/users").status_code == 403


def test_operador_no_administra(app):
    c, _, csrf = login(app, "operador")
    assert post(c, csrf, "/api/devices", {"name": "SIM-NUEVO", "ip": "192.0.2.77", "vendor": "Cisco"}).status_code == 403
    assert post(c, csrf, "/api/users", {"username": "x1", "full_name": "Equis", "role": "administrador",
                                        "password": "Clave1234"}).status_code == 403
    assert post(c, csrf, "/api/incidents", {"title": "Caída de enlace", "severity": 2}).status_code == 201


def test_doble_control_entre_usuarios(app):
    op, _, csrf_op = login(app, "operador")
    inc = post(op, csrf_op, "/api/incidents", {"title": "Interfaz caída", "severity": 3}).get_json()["id"]
    act = post(op, csrf_op, f"/api/incidents/{inc}/actions",
               {"command": "show interfaces Gi0/0/1", "justification": "Verificar"}).get_json()["id"]
    # quien propone no puede aprobar, aunque escriba otro nombre en el formulario
    assert post(op, csrf_op, f"/api/actions/{act}/review", {"decision": "aprobar", "operador": "admin"}).status_code in (400, 403)
    adm, _, csrf_adm = login(app, "admin")
    r = post(adm, csrf_adm, f"/api/actions/{act}/review", {"decision": "aprobar"})
    assert r.status_code == 200 and r.get_json()["reviewed_by"] == "admin"


def test_responsable_es_el_usuario_de_la_sesion(app):
    c, _, csrf = login(app, "operador")
    i = post(c, csrf, "/api/incidents", {"title": "Prueba de autoría", "severity": 4, "operador": "admin"}).get_json()["id"]
    audit = c.get("/api/audit?limit=20").get_json()
    entry = next(a for a in audit if a["action"] == "incident.create" and a["entity_id"] == i)
    assert entry["actor"] == "operador"


def test_administrador_gestiona_usuarios(app):
    c, _, csrf = login(app, "admin")
    r = post(c, csrf, "/api/users", {"username": "analista2", "full_name": "Analista dos", "role": "operador",
                                     "password": "corta"})
    assert r.status_code == 400
    r = post(c, csrf, "/api/users", {"username": "analista2", "full_name": "Analista dos", "role": "operador",
                                     "password": "Analista2026"})
    assert r.status_code == 201
    assert login(app, "analista2", "Analista2026")[1].status_code == 200
    uid = r.get_json()["id"]
    assert post(c, csrf, f"/api/users/{uid}", {"active": False}, "put").status_code == 200
    assert login(app, "analista2", "Analista2026")[1].status_code == 401
    # no se puede dejar el NOC sin administradores
    me = next(u["id"] for u in c.get("/api/users").get_json() if u["username"] == "admin")
    assert post(c, csrf, f"/api/users/{me}", {"role": "operador"}, "put").status_code == 409


def test_cambio_de_contrasena_propia(app):
    c, _, csrf = login(app, "monitoreo")
    assert post(c, csrf, "/api/me/password", {"current": "equivocada1", "new": "Nueva.Clave2026"}).status_code == 403
    assert post(c, csrf, "/api/me/password", {"current": PW["monitoreo"], "new": "Nueva.Clave2026"}).status_code == 200
    assert login(app, "monitoreo")[1].status_code == 401
    assert login(app, "monitoreo", "Nueva.Clave2026")[1].status_code == 200


def test_consola_real_modo_administrador_solo_rol_admin(app):
    c, _, csrf = login(app, "operador")
    assert post(c, csrf, "/api/real/open", {"kind": "loop", "target": "loop://"}).status_code == 200
    r = post(c, csrf, "/api/real/mode", {"mode": "administrador", "ack": True})
    assert r.status_code == 403
    post(c, csrf, "/api/real/close")


def test_cerrar_sesion(app):
    c, _, csrf = login(app, "admin")
    assert post(c, csrf, "/logout").status_code == 200
    assert c.get("/api/events").status_code == 401
