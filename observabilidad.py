"""
Observabilidad de los equipos y mapa de dependencias.

Tres fuentes de datos por equipo:
  1. Sondeos de disponibilidad cada OBS_PROBE_SECONDS (60 s por defecto):
       - equipo real (is_simulated = 0): ping ICMP del sistema operativo, sin shell y con la IP validada;
       - equipo simulado (SIM-*): sondeo SIMULADO coherente con su estado y su ubicación (latencia típica
         de la sede, pérdida si está en alerta, sin respuesta si está caído o si cayó un equipo del que depende).
  2. Telemetría Syslog: eventos y críticos de las últimas 24 h, último evento, incidentes abiertos.
  3. Dependencias (tabla device_links): «el AP depende del switch», «el switch del router».

Con eso se calcula, sin intervención humana:
  - estado: operativo · degradado · caído · afectado (cae por una dependencia) · mantenimiento · desconocido
  - salud de 0 a 100, disponibilidad de 24 h y latencia media
  - análisis de impacto y CAUSA RAÍZ: si cae un equipo, los que dependen de él se marcan «afectado» y no
    se cuentan como fallas propias (se evita la tormenta de alarmas).

Solo lectura sobre los equipos: nunca se conecta a ellos ni ejecuta nada en ellos.
"""
import ipaddress
import os
import platform
import random
import re
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone

import noc

PROBE_SECONDS = max(5, int(os.getenv("OBS_PROBE_SECONDS", "60")))
LATENCY_WARN_MS = float(os.getenv("OBS_LATENCY_WARN_MS", "150"))
DOWN_AFTER = 3                    # sondeos fallidos seguidos para declarar «caído» (evita falsos positivos por pérdida)
KEEP_HOURS = 24

STATES = {
    "operativo": "Operativo", "degradado": "Degradado", "caido": "Caído", "afectado": "Afectado",
    "mantenimiento": "Mantenimiento", "desconocido": "Sin datos",
}

# Dependencias de la red de demostración (solo si el inventario tiene esos equipos y aún no hay enlaces)
DEMO_LINKS = [
    ("SIM-CORE-RTR01", "SIM-EDGE-FW01"),    # el núcleo sale a Internet por el firewall de borde
    ("SIM-DIST-SW01", "SIM-CORE-RTR01"),    # distribución Bogotá
    ("SIM-BR-RTR02", "SIM-CORE-RTR01"),     # sede Medellín por WAN
    ("SIM-BR-SW02", "SIM-CORE-RTR01"),      # sede Cali por WAN
    ("SIM-LAB-AP01", "SIM-BR-SW02"),        # AP del laboratorio conectado al switch de Cali
]

# Latencia típica simulada por sede (ms)
SITE_LATENCY = [("este pc", 0.2), ("bogot", 2.0), ("medell", 14.0), ("cali", 19.0), ("laboratorio", 21.0)]


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- dependencias
def seed_links(conn) -> int:
    if conn.execute("SELECT COUNT(*) FROM device_links").fetchone()[0]:
        return 0
    ids = {r["name"]: r["id"] for r in conn.execute("SELECT id, name FROM devices")}
    n = 0
    for child, parent in DEMO_LINKS:
        if child in ids and parent in ids:
            conn.execute("INSERT OR IGNORE INTO device_links (child_id, parent_id, created_at) VALUES (?, ?, ?)",
                         (ids[child], ids[parent], noc.now_iso()))
            n += 1
    conn.commit()
    return n


def links(conn) -> list[tuple[int, int]]:
    return [(r["child_id"], r["parent_id"]) for r in conn.execute("SELECT child_id, parent_id FROM device_links")]


def ancestors(device_id: int, parent_map: dict) -> set:
    seen, stack = set(), list(parent_map.get(device_id, ()))
    while stack:
        p = stack.pop()
        if p not in seen:
            seen.add(p)
            stack.extend(parent_map.get(p, ()))
    return seen


def creates_cycle(conn, child_id: int, parent_ids: list[int]) -> bool:
    """¿Hacer que child dependa de parent_ids formaría un ciclo (A→B→A)?"""
    pm = {}
    for c, p in links(conn):
        if c != child_id:
            pm.setdefault(c, set()).add(p)
    pm[child_id] = set(parent_ids)
    return child_id in ancestors(child_id, pm)


def set_parents(conn, child_id: int, parent_ids: list[int]):
    conn.execute("DELETE FROM device_links WHERE child_id = ?", (child_id,))
    for p in parent_ids:
        conn.execute("INSERT INTO device_links (child_id, parent_id, created_at) VALUES (?, ?, ?)",
                     (child_id, p, noc.now_iso()))
    conn.commit()


# --------------------------------------------------------------------------- sondeos
RE_LAT = re.compile(r"(?:time|tiempo)\s*([=<])\s*([\d.,]+)\s*ms", re.I)


def icmp_probe(ip: str, timeout_s: float = 1.0):
    """Ping del sistema operativo a una IP validada (sin shell). Devuelve (ok, latencia_ms)."""
    ipaddress.ip_address(ip)                                   # ValueError si no es una IP
    win = platform.system().lower().startswith("win")
    cmd = ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), ip] if win else ["ping", "-c", "1", "-W", "1", ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 3,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if win else 0)
    except (OSError, subprocess.TimeoutExpired):
        return False, None
    text = (out.stdout or "") + (out.stderr or "")
    ok = out.returncode == 0 and "ttl=" in text.lower()       # Windows devuelve 0 en «host inaccesible»
    m = RE_LAT.search(text)
    lat = None
    if ok and m:
        lat = 0.5 if m.group(1) == "<" else float(m.group(2).replace(",", "."))
    return ok, lat


def simulated_probe(dev, down_ancestor: bool, rnd: random.Random):
    """Sondeo simulado y coherente para los equipos SIM- (no existen en la red)."""
    if dev["status"] == "caido" or down_ancestor:
        return False, None
    loc = (dev["location"] or "").lower()
    base = next((ms for key, ms in SITE_LATENCY if key in loc), 5.0)
    if dev["status"] == "alerta":
        if rnd.random() < 0.08:                                # pérdida de paquetes
            return False, None
        base *= 9                                              # enlace congestionado
    return True, round(max(0.1, rnd.gauss(base, base * 0.18)), 1)


def run_probes(conn, only_id: int | None = None, rnd: random.Random | None = None) -> list[dict]:
    """Sondea los equipos (o solo uno) y guarda el resultado. Devuelve [{device_id, ok, latency_ms, method}]."""
    rnd = rnd or random.Random()
    devs = conn.execute("SELECT * FROM devices" + (" WHERE id = ?" if only_id else ""),
                        ((only_id,) if only_id else ())).fetchall()
    pm = {}
    for c, p in links(conn):
        pm.setdefault(c, set()).add(p)
    status = {r["id"]: r["status"] for r in conn.execute("SELECT id, status FROM devices")}
    results = []
    ts = noc.now_iso()
    for d in devs:
        if d["status"] == "mantenimiento":
            continue
        if d["is_simulated"]:
            down_anc = any(status.get(a) == "caido" for a in ancestors(d["id"], pm))
            ok, lat = simulated_probe(d, down_anc, rnd)
            method = "simulado"
        else:
            ok, lat = icmp_probe(d["ip"])
            method = "icmp"
        conn.execute("INSERT INTO device_checks (device_id, ts, ok, latency_ms, method) VALUES (?, ?, ?, ?, ?)",
                     (d["id"], ts, int(ok), lat, method))
        results.append({"device_id": d["id"], "ok": ok, "latency_ms": lat, "method": method})
    conn.execute("DELETE FROM device_checks WHERE ts < ?", (_iso(_now() - timedelta(hours=KEEP_HOURS)),))
    conn.commit()
    return results


# --------------------------------------------------------------------------- estado y topología
def _metrics(conn, dev_id: int, since: str):
    ev = conn.execute("SELECT COUNT(*) n, SUM(CASE WHEN severity <= 3 THEN 1 ELSE 0 END) crit, MAX(received_at) last "
                      "FROM events WHERE device_id = ? AND received_at >= ?", (dev_id, since)).fetchone()
    last_any = conn.execute("SELECT MAX(received_at) FROM events WHERE device_id = ?", (dev_id,)).fetchone()[0]
    inc = conn.execute("SELECT COUNT(*) FROM incidents WHERE device_id = ? AND status != 'cerrado'", (dev_id,)).fetchone()[0]
    chk = conn.execute("SELECT COUNT(*) n, SUM(ok) ok, AVG(CASE WHEN ok = 1 THEN latency_ms END) lat "
                       "FROM device_checks WHERE device_id = ? AND ts >= ?", (dev_id, since)).fetchone()
    recent = conn.execute("SELECT ts, ok, latency_ms, method FROM device_checks WHERE device_id = ? "
                          "ORDER BY id DESC LIMIT 40", (dev_id,)).fetchall()
    fails = 0
    for r in recent:
        if r["ok"]:
            break
        fails += 1
    return {
        "events_24h": ev["n"] or 0, "critical_24h": ev["crit"] or 0, "last_event_at": last_any,
        "open_incidents": inc, "checks_24h": chk["n"] or 0,
        "availability": round(100.0 * (chk["ok"] or 0) / chk["n"], 2) if chk["n"] else None,
        "latency_avg_ms": round(chk["lat"], 1) if chk["lat"] is not None else None,
        "last_check": dict(recent[0]) if recent else None, "consecutive_failures": fails,
        "series": [{"ts": r["ts"], "ok": bool(r["ok"]), "latency_ms": r["latency_ms"]} for r in reversed(recent)],
    }


def topology(conn) -> dict:
    """Nodos con estado y salud, aristas de dependencia, impacto y resumen."""
    since = _iso(_now() - timedelta(hours=24))
    devs = conn.execute("SELECT * FROM devices ORDER BY id").fetchall()
    lk = links(conn)
    pm, cm = {}, {}
    for c, p in lk:
        pm.setdefault(c, set()).add(p)
        cm.setdefault(p, set()).add(c)
    nodes = {}
    for d in devs:
        m = _metrics(conn, d["id"], since)
        if d["status"] == "mantenimiento":
            own = "mantenimiento"
        elif d["status"] == "caido" or m["consecutive_failures"] >= DOWN_AFTER:
            own = "caido"
        elif m["checks_24h"] == 0 and m["events_24h"] == 0:
            own = "desconocido"
        else:
            own = "operativo"
        nodes[d["id"]] = {"id": d["id"], "name": d["name"], "ip": d["ip"], "vendor": d["vendor"], "model": d["model"],
                          "location": d["location"], "inventory_status": d["status"], "authorized": bool(d["authorized"]),
                          "is_simulated": bool(d["is_simulated"]), "own_state": own, **m}
    down = {i for i, n in nodes.items() if n["own_state"] == "caido"}
    for i, n in nodes.items():
        anc = ancestors(i, pm)
        roots = sorted(a for a in anc if a in down and not (ancestors(a, pm) & down))   # causa raíz más alta
        state, reasons, score = n["own_state"], [], 100
        if roots and state != "mantenimiento":
            state = "afectado"                                     # su falla se explica por la dependencia
            reasons.append("depende de " + ", ".join(nodes[r]["name"] for r in roots) + ", que está caído")
            score -= 50
        elif state == "caido":
            reasons.append("marcado caído en el inventario" if n["inventory_status"] == "caido"
                           else f"{n['consecutive_failures']} sondeos seguidos sin respuesta")
            score = 0
        elif state == "operativo":
            if n["critical_24h"]:
                reasons.append(f"{n['critical_24h']} eventos críticos en 24 h"); score -= min(40, 10 * n["critical_24h"])
            if n["open_incidents"]:
                reasons.append(f"{n['open_incidents']} incidentes abiertos"); score -= min(30, 10 * n["open_incidents"])
            if n["inventory_status"] == "alerta":
                reasons.append("en alerta en el inventario"); score -= 15
            if n["availability"] is not None and n["availability"] < 99:
                reasons.append(f"disponibilidad {n['availability']} %"); score -= 15
            if n["latency_avg_ms"] is not None and n["latency_avg_ms"] > LATENCY_WARN_MS:
                reasons.append(f"latencia media {n['latency_avg_ms']} ms"); score -= 10
            if n["consecutive_failures"] == 1:
                reasons.append("el último sondeo no respondió"); score -= 10
            if reasons:
                state = "degradado"
        elif state == "desconocido":
            reasons.append("aún no hay sondeos ni eventos"); score = None
        n.update(state=state, state_name=STATES[state], reasons=reasons, root_cause=[nodes[r]["name"] for r in roots],
                 health=max(0, score) if score is not None else None,
                 parents=sorted(pm.get(i, ())), children=sorted(cm.get(i, ())),
                 impact=sorted(nodes[x]["name"] for x in _descendants(i, cm)) if state == "caido" else [])
    # capas para el dibujo: profundidad = camino más largo desde un equipo sin dependencias
    depth = {}

    def lvl(i, trail=()):
        if i in depth:
            return depth[i]
        ps = [p for p in pm.get(i, ()) if p not in trail and p in nodes]
        depth[i] = 0 if not ps else 1 + max(lvl(p, trail + (i,)) for p in ps)
        return depth[i]
    for i in nodes:
        nodes[i]["layer"] = lvl(i)
    vals = list(nodes.values())
    avail = [n["availability"] for n in vals if n["availability"] is not None]
    summary = {s: sum(1 for n in vals if n["state"] == s) for s in STATES}
    summary.update(total=len(vals), availability_avg=round(sum(avail) / len(avail), 2) if avail else None,
                   probe_seconds=PROBE_SECONDS,
                   root_causes=sorted({rc for n in vals for rc in n["root_cause"]}))
    return {"nodes": vals, "edges": [{"child": c, "parent": p} for c, p in lk if c in nodes and p in nodes],
            "summary": summary, "generated_at": noc.now_iso()}


def _descendants(i, cm) -> set:
    seen, stack = set(), list(cm.get(i, ()))
    while stack:
        c = stack.pop()
        if c not in seen:
            seen.add(c)
            stack.extend(cm.get(c, ()))
    return seen


# --------------------------------------------------------------------------- sondeo periódico
_last_own: dict[int, str] = {}
_notified_down: set[int] = set()
_started = threading.Event()


def check_transitions(conn, notify=None) -> list[dict]:
    """Avisa (auditoría + Telegram) cuando un equipo cae POR SÍ MISMO o se recupera.

    - Solo avisa la caída de la causa raíz: un equipo que deja de responder porque cayó otro del que
      depende queda «afectado» y no genera aviso propio (se evita la tormenta de alarmas).
    - El primer estado observado al iniciar no se anuncia; su recuperación posterior sí."""
    topo = topology(conn)
    changes = []
    for n in topo["nodes"]:
        prev = _last_own.get(n["id"])
        own = n["own_state"]
        _last_own[n["id"]] = own
        is_root_down = own == "caido" and n["state"] == "caido"
        if prev is None:
            if is_root_down:
                _notified_down.add(n["id"])
            continue
        if is_root_down and n["id"] not in _notified_down:
            _notified_down.add(n["id"])
            changes.append({"device": n["name"], "event": "caido", "impact": n["impact"]})
            noc.audit(conn, "sistema", "obs.down", "devices", n["id"],
                      f"{n['name']} caído; afectados: {', '.join(n['impact']) or 'ninguno'}", "alerta")
            if notify:
                notify(f"🔴 <b>NOC · Equipo caído</b>\n<b>{n['name']}</b> ({n['ip']}) no responde.\n"
                       f"Afectados por dependencia: {', '.join(n['impact']) or 'ninguno'}.\n"
                       f"Causa raíz probable: {n['name']}.")
        elif own != "caido" and n["id"] in _notified_down:
            _notified_down.discard(n["id"])
            changes.append({"device": n["name"], "event": "recuperado"})
            noc.audit(conn, "sistema", "obs.up", "devices", n["id"], f"{n['name']} vuelve a responder")
            if notify:
                notify(f"🟢 <b>NOC · Equipo recuperado</b>\n<b>{n['name']}</b> vuelve a responder.")
    return changes


def start_poller(db_path, notify=None):
    """Hilo en segundo plano que sondea cada PROBE_SECONDS. Se inicia una sola vez por proceso."""
    if _started.is_set() or os.getenv("OBS_POLLER", "1") == "0":
        return False
    _started.set()

    def loop():
        while True:
            try:
                conn = noc.connect(db_path)
                run_probes(conn)
                check_transitions(conn, notify)
                conn.close()
            except Exception as exc:                   # el NOC sigue aunque un sondeo falle
                print(f"[OBS] error en el sondeo: {exc}")
            time.sleep(PROBE_SECONDS)
    threading.Thread(target=loop, name="obs-poller", daemon=True).start()
    return True
