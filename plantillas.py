"""
Plantillas del NOC: configuraciones Syslog comentadas y consola simulada.

1) GENERADOR DE CONFIGURACIONES (Cisco, Fortinet, Huawei)
   Cada plantilla aplica la MISMA política en la sintaxis de cada fabricante:
   NTP, marca de tiempo, servidor Syslog y puerto, severidad mínima, interfaz
   de origen fija (su IP debe estar AUTORIZADA en el inventario), registro de
   cambios/accesos y comandos de verificación.
   Los parámetros se validan antes de entrar a la plantilla: una interfaz como
   "Gi0/0\\nreload" se rechaza para que nadie "cuele" comandos en la configuración.

2) CONSOLA TIPO PuTTY SIMULADA, de solo lectura
   NO se conecta a ningún equipo: las salidas se arman con los datos del
   inventario y de los eventos. Política (la primera regla que falla bloquea):
     a. El actor 'asistente_ia' NUNCA ejecuta comandos; solo puede proponer.
     b. Se bloquean caracteres de encadenamiento: ; | & ` $ > < \\ y saltos de línea.
     c. Se bloquean comandos peligrosos (configure, reload, delete, erase...).
     d. LISTA PERMITIDA: solo pasa lo que coincide EXACTAMENTE con un comando
        de solo lectura del fabricante. Todo lo demás se bloquea por defecto.
"""
import ipaddress
import re
from datetime import datetime, timedelta, timezone

from noc import LOCAL_UTC_OFFSET

# =====================================================================
# 1) Generador de configuraciones
# =====================================================================
# Palabra clave de cada severidad (0-7) en cada sistema operativo
CISCO_LEVELS = ["emergencies", "alerts", "critical", "errors",
                "warnings", "notifications", "informational", "debugging"]
FORTI_LEVELS = ["emergency", "alert", "critical", "error",
                "warning", "notification", "information", "debug"]
HUAWEI_LEVELS = ["emergencies", "alert", "critical", "error",
                 "warning", "notification", "informational", "debugging"]
SEV_NAMES = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"]

# Interfaz: letras, números, "/", ".", "-" y ":" (Gi0/0/0, Vlanif10, wan1, port1)
RE_IFACE = re.compile(r"^[A-Za-z][A-Za-z0-9/.:\-]{0,39}$")


def _validate(args) -> tuple[dict, list]:
    errors, v = [], {}
    v["vendor"] = args.get("vendor", "")
    if v["vendor"] not in ("Cisco", "Fortinet", "Huawei"):
        errors.append("Marca inválida. Opciones: Cisco, Fortinet, Huawei")
    for field, label in (("server_ip", "IP del servidor Syslog"), ("ntp", "IP del servidor NTP")):
        try:
            v[field] = str(ipaddress.ip_address(args.get(field, "").strip()))
        except ValueError:
            errors.append(f"{label} inválida")
    try:
        v["port"] = int(args.get("port", "5514"))
        if not 1 <= v["port"] <= 65535:
            raise ValueError
    except ValueError:
        errors.append("Puerto inválido (1-65535)")
    try:
        v["severity"] = int(args.get("severity", "6"))
        if not 0 <= v["severity"] <= 7:
            raise ValueError
    except ValueError:
        errors.append("Severidad inválida (0-7)")
    v["source"] = args.get("source", "").strip()
    if not RE_IFACE.match(v["source"]):
        errors.append("Interfaz de origen inválida (ej. GigabitEthernet0/0/0, wan1, Vlanif10)")
    return v, errors


def _header(v, device, comment):
    c = comment
    lines = [
        f"{c} ======================================================================",
        f"{c} NOC Syslog Inteligente - Configuración Syslog para {v['vendor']}",
        f"{c} Equipo destino : {device['name'] + ' (' + device['ip'] + ')' if device else '(no especificado)'}",
        f"{c} Servidor Syslog: {v['server_ip']} puerto UDP {v['port']}",
        f"{c} Severidad      : {v['severity']} ({SEV_NAMES[v['severity']]}) y más graves",
        f"{c} PLANTILLA DE LABORATORIO: verifique la sintaxis según la versión del",
        f"{c} equipo y aplíquela SOLO en equipos autorizados.",
    ]
    if device and device["is_simulated"]:
        lines.append(f"{c} EQUIPO SIMULADO: esta configuración es de ejemplo.")
    lines.append(f"{c} ======================================================================")
    return lines


def cisco(v, device):
    lvl = CISCO_LEVELS[v["severity"]]
    return "\n".join(_header(v, device, "!") + [
        "configure terminal",
        "!",
        "! --- 1. Hora sincronizada (NTP) -------------------------------------",
        "! Sin la hora correcta no se pueden ordenar ni correlacionar eventos.",
        f"ntp server {v['ntp']}",
        "clock timezone COT -5 0",
        "!",
        "! --- 2. Marca de tiempo precisa en cada mensaje ---------------------",
        "service timestamps log datetime msec localtime show-timezone",
        "service sequence-numbers",
        "!",
        "! --- 3. Servidor Syslog del NOC -------------------------------------",
        f"logging host {v['server_ip']} transport udp port {v['port']}",
        "logging facility local7",
        "!",
        f"! --- 4. Severidad mínima enviada: {v['severity']} ({SEV_NAMES[v['severity']]}) ---",
        f"logging trap {lvl}",
        "!",
        "! --- 5. Interfaz de origen fija -------------------------------------",
        "! Su IP debe estar registrada como fuente AUTORIZADA en el inventario del NOC.",
        f"logging source-interface {v['source']}",
        "!",
        "! --- 6. Registro de cambios de configuración y de accesos -----------",
        "archive",
        " log config",
        "  logging enable",
        "  notify syslog contenttype plaintext",
        "  hidekeys",
        " exit",
        "exit",
        "login on-failure log",
        "login on-success log",
        "!",
        "end",
        "write memory",
        "!",
        "! --- 7. Verificación ------------------------------------------------",
        "! show logging              -> debe listar el host y el nivel configurados",
        "! show ntp associations     -> el servidor NTP debe aparecer sincronizado (*)",
        "! show clock                -> hora y zona correctas",
        "! send log 6 \"Prueba NOC\"    -> el mensaje debe llegar al NOC",
    ])


def fortinet(v, device):
    lvl = FORTI_LEVELS[v["severity"]]
    return "\n".join(_header(v, device, "#") + [
        "# --- 1. Hora sincronizada (NTP) -------------------------------------",
        "config system ntp",
        "    set ntpsync enable",
        "    set type custom",
        "    config ntpserver",
        "        edit 1",
        f"            set server \"{v['ntp']}\"",
        "        next",
        "    end",
        "end",
        "",
        "# --- 2 y 3. Servidor Syslog del NOC ---------------------------------",
        "config log syslogd setting",
        "    set status enable",
        f"    set server \"{v['server_ip']}\"",
        "    set mode udp",
        f"    set port {v['port']}",
        "    set facility local7",
        "    set format default",
        "    # 5. Interfaz de origen fija (su IP debe estar AUTORIZADA en el NOC)",
        "    set interface-select-method specify",
        f"    set interface \"{v['source']}\"",
        "end",
        "",
        f"# --- 4. Severidad mínima enviada: {v['severity']} ({SEV_NAMES[v['severity']]}) ---",
        "config log syslogd filter",
        f"    set severity {lvl}",
        "    # 6. Incluir eventos del sistema (accesos y cambios de configuración)",
        "    set forward-traffic disable",
        "    set local-traffic disable",
        "end",
        "",
        "# --- 7. Verificación ------------------------------------------------",
        "# get log syslogd setting      -> estado enable, servidor y puerto",
        "# diagnose sys ntp status      -> sincronizado con el servidor NTP",
        "# diagnose log test            -> genera mensajes de prueba hacia el NOC",
    ])


def huawei(v, device):
    lvl = HUAWEI_LEVELS[v["severity"]]
    return "\n".join(_header(v, device, "#") + [
        "system-view",
        "#",
        "# --- 1. Hora sincronizada (NTP) -------------------------------------",
        f"ntp-service unicast-server {v['ntp']}",
        "clock timezone COT minus 05:00:00",
        "#",
        "# --- 2. Centro de información y marca de tiempo precisa -------------",
        "info-center enable",
        "info-center timestamp log date precision-time millisecond",
        "#",
        "# --- 3 y 5. Servidor Syslog del NOC e interfaz de origen fija -------",
        "# La IP de la interfaz de origen debe estar AUTORIZADA en el NOC.",
        f"info-center loghost source {v['source']}",
        f"info-center loghost {v['server_ip']} port {v['port']} facility local7",
        "#",
        f"# --- 4. Severidad mínima enviada: {v['severity']} ({SEV_NAMES[v['severity']]}) ---",
        f"info-center source default channel loghost log level {lvl}",
        "#",
        "# --- 6. Registro de comandos (quién ejecutó qué) --------------------",
        "# VRP registra cada comando con SHELL/5/CMDRECORD; se envía al NOC con el canal loghost.",
        "info-center source SHELL channel loghost log level notification",
        "#",
        "return",
        "save",
        "#",
        "# --- 7. Verificación ------------------------------------------------",
        "# display info-center          -> loghost, puerto y nivel configurados",
        "# display ntp-service status   -> clock status: synchronized",
        "# display clock                -> hora y zona correctas",
    ])


GENERATORS = {"Cisco": cisco, "Fortinet": fortinet, "Huawei": huawei}


# =====================================================================
# 2) Consola simulada
# =====================================================================
MAX_COMMAND_LEN = 120
RE_META = re.compile(r"[;|&`$><\n\r\\]")

# Lista permitida: (patrón exacto, descripción). Solo lectura.
ALLOWLIST = {
    "Cisco": [
        (r"show version", "Versión de software y hardware"),
        (r"show clock", "Fecha y hora del equipo"),
        (r"show ip interface brief", "Estado resumido de interfaces"),
        (r"show logging", "Configuración de logging y últimos mensajes"),
        (r"show ntp associations", "Estado de sincronización NTP"),
        (r"show users", "Sesiones abiertas"),
    ],
    "Fortinet": [
        (r"get system status", "Versión y estado del sistema"),
        (r"get system performance status", "CPU y memoria"),
        (r"get log syslogd setting", "Configuración Syslog"),
        (r"diagnose sys ntp status", "Estado de sincronización NTP"),
        (r"get system interface physical", "Estado de interfaces"),
    ],
    "Huawei": [
        (r"display version", "Versión de software y hardware"),
        (r"display clock", "Fecha y hora del equipo"),
        (r"display ip interface brief", "Estado resumido de interfaces"),
        (r"display info-center", "Configuración del centro de información (Syslog)"),
        (r"display ntp-service status", "Estado de sincronización NTP"),
        (r"display users", "Sesiones abiertas"),
    ],
}
ALLOWLIST["Otro"] = []

# Comandos que modifican, reinician, borran o exponen secretos
DANGEROUS = [
    (r"^(conf(igure)?( t(erminal)?)?|system-view|config\b)", "entra a modo de configuración"),
    (r"^(reload|reboot|reset|execute (reboot|shutdown|factoryreset))", "reinicia el equipo"),
    (r"^(write erase|erase|delete|format|del\b|rmdir)", "borra información del equipo"),
    (r"^(copy|tftp|scp|ftp|execute (backup|restore))", "copia o transfiere archivos"),
    (r"^(shutdown|no |undo |set |unset |clear )", "modifica la configuración o el estado"),
    (r"^(debug|terminal monitor|tclsh|diagnose debug)", "consume recursos o abre un intérprete"),
    (r"^(username|password|enable secret|crypto key)", "maneja credenciales"),
    (r"^(show run(ning)?(-config)?|show startup|display current-configuration|show full-configuration)",
     "expone la configuración completa (con secretos); requiere aprobación"),
]


def _normalize(cmd: str) -> str:
    return re.sub(r"\s+", " ", cmd.strip()).lower()


def check(vendor: str, command: str, actor: str) -> tuple[bool, str]:
    """Aplica la política. Devuelve (permitido, motivo)."""
    if actor == "asistente_ia":
        return False, ("Un agente de IA no ejecuta comandos. Debe crear una PROPUESTA "
                       "que un operador humano revise y apruebe (pestaña Incidentes).")
    if not command.strip():
        return False, "Comando vacío"
    if len(command) > MAX_COMMAND_LEN:
        return False, f"Comando demasiado largo (máx. {MAX_COMMAND_LEN} caracteres)"
    if RE_META.search(command):
        return False, "Contiene caracteres de encadenamiento o redirección (; | & ` $ > <)"
    cmd = _normalize(command)
    for pattern, why in DANGEROUS:
        if re.match(pattern, cmd):
            return False, f"Comando peligroso: {why}"
    for pattern, _desc in ALLOWLIST.get(vendor, []):
        if re.fullmatch(pattern, cmd):
            return True, "Permitido (solo lectura)"
    return False, f"No está en la lista permitida de {vendor} (bloqueado por defecto)"


# ---------------------------------------------------------------------------
# Salidas SIMULADAS (construidas con datos del inventario y de los eventos)
# ---------------------------------------------------------------------------
def _local_now():
    return datetime.now(timezone.utc) + timedelta(hours=LOCAL_UTC_OFFSET)


def simulate(conn, dev, cmd: str) -> str:
    cmd = _normalize(cmd)
    now = _local_now()
    name, ip, model, ver = dev["name"], dev["ip"], dev["model"] or "-", dev["version"] or "-"
    events = conn.execute(
        "SELECT received_at, severity, mnemonic, message FROM events WHERE device_id = ? "
        "ORDER BY id DESC LIMIT 5", (dev["id"],)).fetchall()
    ev_lines = [f"  {e['received_at']} sev{e['severity']} {e['mnemonic'] or ''} {e['message'][:70]}"
                for e in events] or ["  (sin eventos registrados para este equipo)"]
    clock = now.strftime("%H:%M:%S.000 COT %a %b %d %Y")
    up = "Up" if dev["status"] == "activo" else "down"

    out = {
        "show version": [f"Cisco IOS XE Software, Version {ver.split()[-1]}", f"{name} uptime is 12 days, 4 hours",
                         f"cisco {model} processor with 3.7G bytes of memory", "Configuration register is 0x2102"],
        "show clock": [f"*{clock}"],
        "show ip interface brief": ["Interface              IP-Address      OK? Method Status   Protocol",
                                    f"GigabitEthernet0/0/0   {ip:<15} YES NVRAM  up       {up}",
                                    "GigabitEthernet0/0/2   unassigned      YES unset  down     down"],
        "show logging": ["Syslog logging: enabled", "    Trap logging: level informational",
                         "        Logging to 192.0.2.250 (udp port 5514, audit disabled, link up)",
                         "Log Buffer (últimos eventos registrados en el NOC):"] + ev_lines,
        "show ntp associations": ["  address         ref clock       st   when   poll reach  delay  offset   disp",
                                  "*~192.0.2.123     .GNSS.           1     35     64   377  1.204   0.311  0.142",
                                  " * sys.peer, # selected, + candidate, - outlyer, x falseticker"],
        "show users": ["    Line       User       Host(s)              Idle       Location",
                       "*  2 vty 0     noc_admin  idle                 00:00:00 192.0.2.50"],
        "get system status": [f"Version: {model} {ver}", f"Hostname: {name}", "Operation Mode: NAT",
                              f"System time: {now:%a %b %d %H:%M:%S %Y}"],
        "get system performance status": ["CPU states: 3% user 1% system 0% nice 96% idle",
                                          "Memory: 1943604k total, 712040k used (36.6%)"],
        "get log syslogd setting": ["status              : enable", "server              : \"192.0.2.250\"",
                                    "mode                : udp", "port                : 5514",
                                    "facility            : local7"],
        "diagnose sys ntp status": ["synchronized: yes, ntpsync: enabled, server-mode: disabled",
                                    "ipv4 server(192.0.2.123) -- reachable(0xff) S:1 T:32 selected"],
        "get system interface physical": [f"    ==[wan1]  mode: static  ip: {ip} 255.255.255.0  status: {up}",
                                          "    ==[internal1]  mode: static  ip: 192.0.2.254 255.255.255.0  status: up"],
        "display version": [f"Huawei Versatile Routing Platform Software", f"VRP (R) software, {ver}",
                            f"HUAWEI {model} uptime is 12 days, 4 hours"],
        "display clock": [now.strftime("%Y-%m-%d %H:%M:%S-05:00"), "Time Zone(COT) : UTC-05:00"],
        "display ip interface brief": ["Interface                 IP Address/Mask    Physical  Protocol",
                                       f"GigabitEthernet0/0/0      {ip}/24{'':<4} {up:<9} {up}",
                                       "GigabitEthernet0/0/1      unassigned         down      down"],
        "display info-center": ["Information Center: enabled", "Log host:",
                                "  192.0.2.250 port 5514, channel number 2, channel name loghost,",
                                "  language english, facility local7, with source interface"] + ev_lines,
        "display ntp-service status": [" clock status: synchronized", " clock stratum: 2",
                                       " reference clock ID: 192.0.2.123"],
        "display users": ["  User-Intf    Delay    Type   Network Address     AuthenStatus",
                          "+ 129 VTY 0   00:00:00  SSH    192.0.2.50           pass"],
    }
    return "\n".join(["[SALIDA SIMULADA - no hay conexión con ningún equipo]"] + out.get(cmd, ["(sin salida)"]))
