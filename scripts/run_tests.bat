@echo off
rem Full automated suite: every case spins up a fresh IdP + 2-4 RP child
rem processes and talks to them over real HTTP.
setlocal

cd /d "%~dp0\.."

if "%PY%"=="" set "PY=python"

"%PY%" -m tests.run_all %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%
