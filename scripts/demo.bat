@echo off
rem Latency/ordering demo. Starts an IdP and 4 RP child processes over real HTTP,
rem drives out-of-order/duplicate/crash scenarios, then tears everything down.
setlocal

cd /d "%~dp0\.."

if "%PY%"=="" set "PY=python"

"%PY%" demo.py
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%
