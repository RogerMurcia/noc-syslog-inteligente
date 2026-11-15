"""
Administración de usuarios desde la terminal (por si se olvida la contraseña del administrador).

Uso (con la aplicación detenida o en marcha, en la carpeta del proyecto):
    python usuarios.py listar
    python usuarios.py clave <usuario> <contraseña_nueva>     restablece y desbloquea la cuenta
    python usuarios.py desbloquear <usuario>
    python usuarios.py sin2fa <usuario>                       quita el doble factor (celular perdido)
"""
import sys

import auth
import noc


def main(argv):
    conn = noc.connect(noc.DB_PATH)
    noc.init_db(conn)
    auth.seed_users(conn)
    if len(argv) >= 1 and argv[0] == "listar":
        for u in conn.execute("SELECT username, full_name, role, active, locked_until, last_login, totp_enabled FROM users ORDER BY id"):
            print(f"{u['username']:<14} {auth.ROLES[u['role']]:<26} {'activo' if u['active'] else 'inactivo':<9} "
                  f"2FA={'sí' if u['totp_enabled'] else 'no':<3} "
                  f"bloqueo={u['locked_until'] or '-'}  último ingreso={u['last_login'] or '-'}  ({u['full_name']})")
        return 0
    if len(argv) == 3 and argv[0] == "clave":
        if (probs := auth.password_problems(argv[2])):
            print("Error:", "; ".join(probs)); return 1
        cur = conn.execute("UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL, updated_at = ? "
                           "WHERE username = ?", (auth.hash_password(argv[2]), noc.now_iso(), argv[1].lower()))
        conn.commit()
        if not cur.rowcount:
            print("No existe el usuario", argv[1]); return 1
        noc.audit(conn, "sistema", "user.password", "users", None, f"{argv[1]}: restablecida desde la terminal")
        print(f"Contraseña de {argv[1]} restablecida."); return 0
    if len(argv) == 2 and argv[0] == "desbloquear":
        cur = conn.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?", (argv[1].lower(),))
        conn.commit()
        print("Cuenta desbloqueada." if cur.rowcount else f"No existe el usuario {argv[1]}"); return 0 if cur.rowcount else 1
    if len(argv) == 2 and argv[0] == "sin2fa":
        cur = conn.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_counter = NULL, "
                           "recovery_codes = NULL WHERE username = ?", (argv[1].lower(),))
        conn.commit()
        if cur.rowcount:
            noc.audit(conn, "sistema", "user.mfa_reset", "users", None, f"{argv[1]}: doble factor quitado desde la terminal", "alerta")
        print("Doble factor quitado: ingresará solo con contraseña." if cur.rowcount else f"No existe el usuario {argv[1]}")
        return 0 if cur.rowcount else 1
    print(__doc__); return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
