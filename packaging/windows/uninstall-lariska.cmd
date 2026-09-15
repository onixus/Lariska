@echo off
setlocal

rem  Removes the Lariska Windows service and its binary.
rem
rem  Usage, from an elevated (Administrator) command prompt:
rem
rem    uninstall-lariska.cmd [/purgedata]
rem
rem  The data directory is kept by default: the agent identity lives there, so
rem  a reinstall that keeps it reports as the same device rather than as a
rem  second one. /purgedata removes it.

set "SERVICE_NAME=Lariska"
set "INSTALL_DIR=%ProgramFiles%\Lariska"
set "DATA_DIR=%ProgramData%\Lariska"
set "PURGE=0"

if /i "%~1"=="/purgedata" set "PURGE=1"
if not "%~1"=="" if not "%PURGE%"=="1" goto :usage

fltmc >nul 2>&1
if errorlevel 1 (
    echo ERROR: this script must run from an elevated ^(Administrator^) command prompt.
    exit /b 1
)

sc.exe query "%SERVICE_NAME%" >nul 2>&1
if errorlevel 1 goto :no_service

echo ==^> Stopping %SERVICE_NAME%
sc.exe stop "%SERVICE_NAME%" >nul 2>&1
call :wait_stopped

echo ==^> Deleting the %SERVICE_NAME% service
sc.exe delete "%SERVICE_NAME%" >nul
if errorlevel 1 (
    echo ERROR: sc.exe delete failed.
    exit /b 1
)
goto :remove_files

:no_service
echo ==^> No %SERVICE_NAME% service registered; nothing to stop

:remove_files
if exist "%INSTALL_DIR%" (
    echo ==^> Removing %INSTALL_DIR%
    rd /s /q "%INSTALL_DIR%"
)

if "%PURGE%"=="1" goto :purge
if exist "%DATA_DIR%" echo ==^> Keeping %DATA_DIR% ^(pass /purgedata to remove the agent identity too^)
goto :done

:purge
if exist "%DATA_DIR%" (
    echo ==^> Removing %DATA_DIR% ^(identity, config and spool^)
    rd /s /q "%DATA_DIR%"
)

:done
echo.
echo Lariska is uninstalled.
exit /b 0

:wait_stopped
rem  Up to ~30s for the service to report STOPPED. `ping` is the sleep that
rem  works in a non-interactive session; `timeout` needs a console.
set /a _tries=0
:wait_loop
sc.exe query "%SERVICE_NAME%" | find "STOPPED" >nul
if not errorlevel 1 exit /b 0
set /a _tries+=1
if %_tries% geq 30 exit /b 1
ping -n 2 127.0.0.1 >nul
goto :wait_loop

:usage
echo Usage: uninstall-lariska.cmd [/purgedata]
exit /b 2
