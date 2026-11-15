"""
Pruebas de la consola de EQUIPOS REALES sin hardware:
  * loop://  -> eco local de pyserial (lo que se escribe vuelve como salida)
  * TCP      -> un "router" falso que escucha en 127.0.0.1 y responde como un CLI
Telegram se simula; ninguna prueba usa Internet.
"""
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import consola_real          # noqa: E402
import telegram_noc          # noqa: E402
from app import create_app   # noqa: E402

pytestmark = pytest.mark.skipif(not consola_real.HAVE_SERIAL, reason="pyserial no instalado")


@pytest.fixture(autouse=True)
def telegram_capture(monkeypatch):
    sent = []
    monkeypatch.setenv("TELEGRAM_ENABLED", "1")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:TEST_TOKEN_NO_REAL_xxxxxxxxxxxxxxxxxxx")
    monkeypatch.setenv("TELEGRAM_CHAT_IDS", "111")
    monkeypatch.setattr(telegram_noc, "api_call", lambda m, p, timeout=8: sent.append(p) or {"ok": True})
    telegram_noc._sent_times.clear()
    return sent


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "real.db")
    app.config["TESTING"] = True
    c = app.test_client()
    yield c
    c.post("/api/real/close", json={})


def read_until(client, needle, timeout=3):
    seq, buf, end = 0, "", time.time() + timeout
    while time.time() < end:
        r = client.get(f"/api/real/read?since={seq}").json
        seq, buf = r["seq"], buf + r["text"]
        if needle in buf:
            return buf
        time.sleep(0.05)
    return buf


@pytest.fixture
def fake_router():
    """CLI mínimo: responde a 'show version' y hace eco del resto con un prompt."""
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    received = []

    def serve():
        conn, _ = srv.accept()
        conn.sendall(b"\xff\xfb\x01\xff\xfb\x03\r\nRouter>")      # negociación Telnet + prompt
        buf = b""
        while True:
            try:
                data = conn.recv(1024)
            except OSError:
                break
            if not data:
                break
            buf += data
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                received.append(line.decode())
                reply = b"Cisco IOS XE Software, Version 17.9.4" if line == b"show version" else b"% ok " + line
                conn.sendall(b"\r\n" + reply + b"\r\nRouter>")
        conn.close()
    threading.Thread(target=serve, daemon=True).start()
    yield f"127.0.0.1:{port}", received
    srv.close()


def test_status_y_puertos(client):
    s = client.get("/api/real/status").json
    assert s["available"] is True and s["session"] is None and 9600 in s["baudrates"]
    assert isinstance(client.get("/api/real/ports").json, list)


def test_validacion_de_destino(client):
    assert client.post("/api/real/open", json={"kind": "serial", "target": "COM3; del *"}).status_code == 400
    assert client.post("/api/real/open", json={"kind": "tcp", "target": "127.0.0.1:99999"}).status_code == 400
    assert client.post("/api/real/open", json={"kind": "ssh", "target": "x"}).status_code == 400


def test_ia_no_puede_usar_la_consola_real(client):
    r = client.post("/api/real/open", json={"kind": "loop", "target": "loop", "actor": "asistente_ia"})
    assert r.status_code == 403


def test_eco_loop_y_modo_lectura(client):
    assert client.post("/api/real/open", json={"kind": "loop", "target": "loop", "device_id": 1}).status_code == 200
    assert client.post("/api/real/open", json={"kind": "loop", "target": "loop"}).status_code == 409   # una sola sesión
    ok = client.post("/api/real/send", json={"command": "show version"})
    assert ok.json["allowed"] is True and "show version" in read_until(client, "show version")
    bloq = client.post("/api/real/send", json={"command": "configure terminal"})
    assert bloq.status_code == 403 and bloq.json["allowed"] is False


def test_modo_administrador_requiere_aceptar_y_avisa_telegram(client, telegram_capture):
    client.post("/api/real/open", json={"kind": "loop", "target": "loop", "device_id": 1})
    assert client.post("/api/real/mode", json={"mode": "administrador"}).status_code == 400
    assert client.post("/api/real/mode", json={"mode": "administrador", "ack": True}).json["mode"] == "administrador"
    assert any("Sesión de administración" in p["text"] for p in telegram_capture)
    assert client.post("/api/real/send", json={"command": "configure terminal"}).json["allowed"] is True


def test_destructivo_pide_confirmacion(client, telegram_capture):
    client.post("/api/real/open", json={"kind": "loop", "target": "loop", "device_id": 1})
    client.post("/api/real/mode", json={"mode": "administrador", "ack": True})
    r = client.post("/api/real/send", json={"command": "reload"})
    assert r.status_code == 403 and r.json["needs_confirm"] is True
    assert client.post("/api/real/send", json={"command": "reload", "confirm": True}).json["allowed"] is True
    assert any("destructivo" in p["text"] for p in telegram_capture)


def test_auditoria_oculta_contrasenas(client):
    client.post("/api/real/open", json={"kind": "loop", "target": "loop", "device_id": 1})
    client.post("/api/real/mode", json={"mode": "administrador", "ack": True})
    client.post("/api/real/send", json={"command": "enable secret MiClave2026"})
    client.post("/api/real/send", json={"command": "username admin privilege 15 password 0 Otra123"})
    audit = client.get("/api/audit").get_data(as_text=True)
    assert "MiClave2026" not in audit and "Otra123" not in audit and "[REDACTADO]" in audit


def test_teclas_especiales(client):
    client.post("/api/real/open", json={"kind": "loop", "target": "loop"})
    assert client.post("/api/real/key", json={"key": "ctrl_c"}).status_code == 200
    assert client.post("/api/real/key", json={"key": "rm"}).status_code == 400


def test_tcp_tipo_gns3(client, fake_router):
    target, received = fake_router
    assert client.post("/api/real/open", json={"kind": "tcp", "target": target, "device_id": 1}).status_code == 200
    out = read_until(client, "Router>")
    assert "\xff" not in out and "Router>" in out              # negociación Telnet filtrada
    client.post("/api/real/send", json={"command": "show version"})
    assert "Version 17.9.4" in read_until(client, "Version 17.9.4")
    assert received == ["show version"]


def test_aplicar_syslog_envia_configuracion(client, fake_router):
    target, received = fake_router
    client.post("/api/real/open", json={"kind": "tcp", "target": target, "device_id": 1})
    cfg = {"server_ip": "192.0.2.250", "port": 5514, "severity": 6, "ntp": "192.0.2.123",
           "source": "GigabitEthernet0/0/0"}
    assert client.post("/api/real/apply-syslog", json={**cfg, "confirm": True}).status_code == 409   # falta admin
    client.post("/api/real/mode", json={"mode": "administrador", "ack": True})
    r = client.post("/api/real/apply-syslog", json={**cfg, "confirm": True})
    assert r.status_code == 200
    time.sleep(0.4)
    assert "logging host 192.0.2.250 transport udp port 5514" in received


def test_prueba_desde_el_equipo_cisco(client, fake_router):
    target, received = fake_router
    client.post("/api/real/open", json={"kind": "tcp", "target": target, "device_id": 1})   # SIM-CORE-RTR01 (Cisco)
    r = client.post("/api/real/test", json={"via": "equipo", "severity": 2, "text": "Prueba NOC"})
    assert r.status_code == 200 and r.json["commands"] == ['send log 2 "Prueba NOC"']
    time.sleep(0.3)
    assert received == ['send log 2 "Prueba NOC"']


def test_prueba_directa_llega_a_telegram(client, telegram_capture):
    r = client.post("/api/real/test", json={"via": "directa", "device_id": 1, "severity": 2, "text": "Prueba <script>"})
    assert r.status_code == 200 and r.json["decision"] == "REVIEW"
    assert r.json["notification"]["status"] == "enviada"
    assert "<script>" not in telegram_capture[-1]["text"]
    # dos pruebas seguidas no se deduplican
    r2 = client.post("/api/real/test", json={"via": "directa", "device_id": 1, "severity": 2})
    assert r2.json["event_id"] != r.json["event_id"]
