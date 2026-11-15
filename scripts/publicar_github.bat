@echo off
REM ===========================================================================
REM  Publica en GitHub el repositorio YA PREPARADO (historial del Corte 2 al Corte 3)
REM
REM  El ZIP del proyecto trae la carpeta .git con:
REM    - los 2 commits que ya estan en GitHub (version del Corte 2)
REM    - etiqueta v0.2.0, rama develop, 9 ramas feature/* y el merge release v1.0.0
REM    - etiqueta v1.0.0
REM  Este script solo comprueba y sube (push). No borra nada en GitHub.
REM
REM  Uso: doble clic, o desde la carpeta del proyecto:  scripts\publicar_github.bat
REM  La primera vez Git pedira iniciar sesion en GitHub con la cuenta RogerMurcia.
REM ===========================================================================
setlocal
cd /d "%~dp0\.."

where git >nul 2>nul || (echo [ERROR] Instale Git: https://git-scm.com/download/win & pause & exit /b 1)
if not exist ".git" (echo [ERROR] Esta carpeta no tiene el historial .git. Descomprima de nuevo el ZIP completo. & pause & exit /b 1)

echo [1/4] Repositorio remoto:
git remote -v
git remote get-url origin >nul 2>nul || git remote add origin https://github.com/RogerMurcia/noc-syslog-inteligente.git

echo [2/4] Consultando GitHub...
git fetch origin || (echo [ERROR] No se pudo conectar con GitHub. Revise Internet o su inicio de sesion. & pause & exit /b 1)

git merge-base --is-ancestor origin/main main
if errorlevel 1 (
  echo [ERROR] GitHub tiene commits que no estan en esta copia ^(alguien subio cambios despues^).
  echo         No se sobrescribe nada. Pida ayuda antes de continuar.
  pause & exit /b 1
)

echo [3/4] Subiendo ramas y etiquetas...
git push -u origin main || (pause & exit /b 1)
git push origin develop feature/policy-engine feature/asistente-ia feature/telegram feature/interfaz-oscura feature/simulador-continuo feature/consola-real feature/usuarios-roles feature/mfa-totp feature/observabilidad
git push origin v0.2.0 v1.0.0

echo [4/4] Historial publicado:
git log --graph --oneline --decorate --all -n 30
echo.
echo Listo: https://github.com/RogerMurcia/noc-syslog-inteligente
echo Opcional: en GitHub ^> Releases ^> "Draft a new release", elija la etiqueta v1.0.0
echo y pegue el texto de docs\RELEASE_NOTES_v1.0.0.md
pause
