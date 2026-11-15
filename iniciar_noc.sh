#!/usr/bin/env bash
# NOC Syslog Inteligente v1.0.0 - inicio en Linux / macOS
# Crea el entorno virtual, instala dependencias y arranca app, receptor y simulador continuo.
set -e
cd "$(dirname "$0")"
[ -x .venv/bin/python ] || python3 -m venv .venv
.venv/bin/python -m pip install -q -r requirements.txt
[ -f .env ] || cp .env.example .env
.venv/bin/python app.py & APP=$!
sleep 2
.venv/bin/python receptor.py & REC=$!
sleep 1
(.venv/bin/python simulador.py && .venv/bin/python simulador.py --continuo) & SIM=$!
trap 'kill $APP $REC $SIM 2>/dev/null' EXIT INT TERM
echo "NOC en http://127.0.0.1:5000  (admin / Admin.NOC2026 + código TOTP del README · operador / Operador.NOC2026 · monitoreo / Monitoreo.NOC2026)"
echo "Ctrl+C para detener."
(command -v xdg-open >/dev/null && xdg-open http://127.0.0.1:5000) || (command -v open >/dev/null && open http://127.0.0.1:5000) || true
wait
