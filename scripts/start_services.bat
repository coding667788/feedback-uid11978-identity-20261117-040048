@echo off
rem Start one IdP + four RP processes on fixed ports for manual poking.
rem Ports: IdP 8081, RP 8082..8085. Each console window stays open.
setlocal

cd /d "%~dp0\.."

if "%PY%"=="" set "PY=python"

if not exist "data" mkdir "data"

"%PY%" -m sso_local init --db data\rp.db || goto :error

start "IDP 8081" cmd /k ""%PY%" -m sso_local idp --config config\local.json --state data\idp-state.json --port 8081"
timeout /t 1 /nobreak >nul

for %%P in (8082 8083 8084 8085) do (
    start "RP %%P" cmd /k ""%PY%" -m sso_local rp --db data\rp.db --config config\local.json --port %%P"
)

echo.
echo IdP : http://127.0.0.1:8081
echo RP  : http://127.0.0.1:8082 .. 8085
echo DB  : %CD%\data\rp.db
echo.
echo Try:  %PY% -m sso_local ticket --config config\local.json --state data\idp-state.json --iss https://idp-alpha.local --sub alice
echo       %PY% -m sso_local status --rp http://127.0.0.1:8082
endlocal & exit /b 0

:error
echo init failed
endlocal & exit /b 1
