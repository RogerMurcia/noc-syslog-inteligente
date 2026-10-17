"""
Receptor Syslog por UDP.

Uso:  python receptor.py        (se detiene con Ctrl+C)

Escucha en SYSLOG_HOST:SYSLOG_PORT (por defecto 127.0.0.1:5514). Cada paquete
UDP es un mensaje Syslog: se procesa con noc.ingest() y queda en la base de datos.

  - Syslog estándar usa UDP 514; aquí se usa 5514 para no requerir permisos
    de administrador. En los equipos se configura el puerto destino.
  - La IP de ORIGEN del paquete (addr[0]) es la que se compara con el inventario.
  - Control de tormentas: si una IP envía más de STORM_MAX_PER_MINUTE mensajes
    en un minuto, el exceso se descarta (y se audita una vez).
"""
import os
import socket
import time

import noc

MAX_PACKET = 8192
STORM_MAX_PER_MINUTE = int(os.getenv("STORM_MAX_PER_MINUTE", "100"))


def main():
    conn = noc.connect()
    noc.init_db(conn)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((noc.SYSLOG_HOST, noc.SYSLOG_PORT))
    sock.settimeout(1.0)    # permite salir con Ctrl+C en Windows
    noc.audit(conn, "sistema", "receiver.start", detail=f"udp://{noc.SYSLOG_HOST}:{noc.SYSLOG_PORT}")
    print(f"[NOC] Receptor Syslog en udp://{noc.SYSLOG_HOST}:{noc.SYSLOG_PORT}  (Ctrl+C para detener)")

    window = {}             # ip -> [inicio_ventana, contador]
    received = 0
    try:
        while True:
            try:
                data, addr = sock.recvfrom(MAX_PACKET)
            except socket.timeout:
                continue
            ip, now = addr[0], time.monotonic()
            start, count = window.get(ip, (now, 0))
            if now - start >= 60:
                start, count = now, 0
            count += 1
            window[ip] = (start, count)
            if count > STORM_MAX_PER_MINUTE:
                if count == STORM_MAX_PER_MINUTE + 1:
                    noc.audit(conn, "sistema", "syslog.tormenta", detail=f"origen={ip} supera "
                              f"{STORM_MAX_PER_MINUTE} msg/min; se descarta el exceso", result="alerta")
                    print(f"[TORMENTA] {ip}: límite superado, se descarta el exceso")
                continue

            r = noc.ingest(conn, data.decode("utf-8", errors="replace"), ip, "udp")
            received += 1
            extra = f"  [{', '.join(r['flags'])}]" if r["flags"] else ""
            if r["incident"]:
                extra += f"  -> incidente #{r['incident']['id']}"
            tag = "DUP" if r["duplicate"] else f"#{r['id']}"
            print(f"[UDP] {ip:<15} {tag:<6} sev {r['severity']} {r['severity_name']:<13} "
                  f"{r['vendor']:<9} {r['message'][:60]}{extra}")
    except KeyboardInterrupt:
        print(f"\n[NOC] Receptor detenido. Mensajes procesados: {received}")
    finally:
        noc.audit(conn, "sistema", "receiver.stop", detail=f"mensajes={received}")
        sock.close()
        conn.close()


if __name__ == "__main__":
    main()
