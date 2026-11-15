@echo off
REM ===========================================================================
REM  NOC Syslog Inteligente v1.0.0 - inicio con doble clic (Windows)
REM  1. Crea el entorno virtual e instala dependencias (solo la primera vez)
REM  2. Abre 3 ventanas: aplicacion web, receptor Syslog y simulador continuo
REM     (y el bot de Telegram si TELEGRAM_ENABLED=1 en .env)
REM  3. Abre el navegador en http://127.0.0.1:5000
REM  Requisito: Python 3.10 o superior (python.org, marcar "Add python.exe to PATH")
REM ===========================================================================
setlocal
cd /d "%~dp0"
title NOC Syslog Inteligente

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] No se encontro Python. Instalelo desde https://www.python.org/downloads/
  echo         y marque la casilla "Add python.exe to PATH". Luego ejecute de nuevo este archivo.
  pause & exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo [1/3] Creando el entorno virtual...
  python -m venv .venv || (echo [ERROR] No se pudo crear .venv & pause & exit /b 1)
)
echo [2/3] Verificando dependencias...
".venv\Scripts\python.exe" -m pip install -q -r requirements.txt || (echo [ERROR] Fallo pip install & pause & exit /b 1)
if not exist ".env" copy ".env.example" ".env" >nul

netstat -ano | findstr ":5514 " >nul && echo [AVISO] El puerto 5514 ya esta en uso: puede haber un receptor abierto.

echo [3/3] Iniciando el NOC...
start "NOC - Aplicacion web" cmd /k ".venv\Scripts\python.exe app.py"
timeout /t 3 /nobreak >nul
start "NOC - Receptor Syslog" cmd /k ".venv\Scripts\python.exe receptor.py"
timeout /t 2 /nobreak >nul
REM Primero 20 eventos de demostracion (panel con datos de inmediato) y luego un lote cada 2 minutos
start "NOC - Simulador (cada 2 min)" cmd /k ".venv\Scripts\python.exe simulador.py && .venv\Scripts\python.exe simulador.py --continuo"
findstr /b /c:"TELEGRAM_ENABLED=1" .env >nul && start "NOC - Bot Telegram" cmd /k ".venv\Scripts\python.exe bot_telegram.py"
start "" http://127.0.0.1:5000

echo.
echo  NOC en http://127.0.0.1:5000
echo  Usuarios:  admin / Admin.NOC2026      (administrador, pide codigo TOTP: ver README)
echo             operador / Operador.NOC2026  (operador)
echo             monitoreo / Monitoreo.NOC2026 (solo lectura)
echo  Para detener: cierre las ventanas abiertas o pulse Ctrl+C en cada una.
echo.
pause
