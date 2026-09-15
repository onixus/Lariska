@echo off
setlocal

rem  Installs the Lariska endpoint inventory agent as a Windows service.
rem
rem  Batch rather than PowerShell on purpose: the environments this agent is
rem  meant for commonly forbid running PowerShell scripts by policy, and an
rem  installer that cannot be run is not an installer. Everything here is
rem  cmd.exe plus sc.exe and icacls.exe, both of which ship with Windows.
rem
rem  Usage, from an elevated (Administrator) command prompt:
rem
rem    install-lariska.cmd <server-url> <provisioning-key> [/plainhttp] [/ca <pem>]
rem
rem  Examples:
rem    install-lariska.cmd https://shapoclyack.corp octo-pk-xxxx
rem    install-lariska.cmd http://192.168.68.115:8080 octo-pk-xxxx /plainhttp
rem
rem  Re-running upgrades in place: the service is stopped, the binary and the
rem  configuration are replaced, and the state directory is left alone so the
rem  agent keeps the identity the server knows this device by.

set "SERVICE_NAME=Lariska"
set "INSTALL_DIR=%ProgramFiles%\Lariska"
set "DATA_DIR=%ProgramData%\Lariska"
set "CONFIG_DIR=%DATA_DIR%\config"
set "STATE_DIR=%DATA_DIR%\state"
set "CONFIG_FILE=%CONFIG_DIR%\lariska.toml"
set "KEY_FILE=%CONFIG_DIR%\provisioning.key"
set "CA_DEST=%CONFIG_DIR%\ca.pem"
set "SOURCE_EXE=%~dp0lariska.exe"
set "TARGET_EXE=%INSTALL_DIR%\lariska.exe"

set "SERVER_URL=%~1"
set "PROV_KEY=%~2"
set "ALLOW_PLAIN=0"
set "CA_FILE="

if "%SERVER_URL%"=="" goto :usage
if "%PROV_KEY%"==""  goto :usage

rem  Remaining arguments, in any order: /plainhttp and /ca <path>. Parsed with
rem  labels rather than a parenthesised block: inside a block cmd expands %~1
rem  once, when it parses the block, so a shift there would have no effect on
rem  the arguments the block goes on to read.
shift
shift
:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="/plainhttp" goto :opt_plainhttp
if /i "%~1"=="/ca" goto :opt_ca
echo ERROR: unknown option "%~1".
goto :usage

:opt_plainhttp
set "ALLOW_PLAIN=1"
shift
goto :parse_args

:opt_ca
set "CA_FILE=%~2"
if not defined CA_FILE goto :usage
shift
shift
goto :parse_args

:args_done

rem  --- preconditions ------------------------------------------------------

rem  fltmc needs administrator rights and nothing else; `net session` would
rem  also fail on a host where the Server service is simply not running.
fltmc >nul 2>&1
if errorlevel 1 (
    echo ERROR: this installer must run from an elevated ^(Administrator^) command prompt.
    exit /b 1
)

if not exist "%SOURCE_EXE%" (
    echo ERROR: lariska.exe not found next to this script ^(expected %SOURCE_EXE%^).
    exit /b 1
)

rem  Substring comparison rather than `echo %SERVER_URL% | findstr`: a URL
rem  carrying an ampersand would break that pipeline apart before findstr ever
rem  saw it.
if "%ALLOW_PLAIN%"=="0" if /i not "%SERVER_URL:~0,8%"=="https://" (
    echo ERROR: the server URL must use https unless /plainhttp is given.
    echo        The provisioning key and the inventory would otherwise cross
    echo        the network in the clear. Got: %SERVER_URL%
    exit /b 1
)

if defined CA_FILE if not exist "%CA_FILE%" (
    echo ERROR: TLS CA bundle not found at %CA_FILE%.
    exit /b 1
)

rem  --- stop an existing service so the binary is not locked ---------------

set "SERVICE_EXISTS=0"
sc.exe query "%SERVICE_NAME%" >nul 2>&1
if not errorlevel 1 set "SERVICE_EXISTS=1"

if "%SERVICE_EXISTS%"=="1" (
    echo ==^> Stopping the existing %SERVICE_NAME% service
    sc.exe stop "%SERVICE_NAME%" >nul 2>&1
    call :wait_stopped
    if errorlevel 1 (
        echo ERROR: %SERVICE_NAME% did not stop; not replacing a running binary.
        exit /b 1
    )
)

rem  --- directories --------------------------------------------------------

rem  Tested by existence rather than with `|| exit /b`: when the directory is
rem  already there mkdir never runs, and `||` would then be judging whatever
rem  command ran last -- `sc.exe query`, which returns 1 when the service is not
rem  registered yet.
echo ==^> Creating directories
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"
if not exist "%STATE_DIR%" mkdir "%STATE_DIR%"
if not exist "%INSTALL_DIR%" (
    echo ERROR: could not create %INSTALL_DIR%.
    exit /b 1
)
if not exist "%CONFIG_DIR%" (
    echo ERROR: could not create %CONFIG_DIR%.
    exit /b 1
)
if not exist "%STATE_DIR%" (
    echo ERROR: could not create %STATE_DIR%.
    exit /b 1
)

rem  The config holds the provisioning key and the state directory holds the
rem  delivery spool: both are readable only by SYSTEM and local Administrators.
rem  Inheritance is switched off so a permissive ProgramData ACL cannot widen
rem  them back.
echo ==^> Restricting ACLs on the data directories
icacls "%CONFIG_DIR%" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" >nul || exit /b 1
icacls "%STATE_DIR%"  /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" >nul || exit /b 1

rem  --- files --------------------------------------------------------------

echo ==^> Installing the binary into %INSTALL_DIR%
copy /y "%SOURCE_EXE%" "%TARGET_EXE%" >nul
if not exist "%TARGET_EXE%" (
    echo ERROR: could not copy lariska.exe to %TARGET_EXE%.
    exit /b 1
)

rem  `set /p` with no newline: the agent reads the whole file as the key, and a
rem  trailing CRLF would be part of it.
rem
rem  No `|| exit /b` on this line: `set /p` reports ERRORLEVEL 1 when its read
rem  fails, and reading from nul is a failed read by design -- that is what makes
rem  it write the value without a newline. The `||` therefore fired on every
rem  run, and the installer exited right here, leaving a config directory that
rem  held the key and nothing else. The file's existence is the real test.
echo ==^> Writing the provisioning key
<nul set /p "=%PROV_KEY%" > "%KEY_FILE%"
if not exist "%KEY_FILE%" (
    echo ERROR: could not write %KEY_FILE%.
    exit /b 1
)

if defined CA_FILE (
    copy /y "%CA_FILE%" "%CA_DEST%" >nul
    if not exist "%CA_DEST%" (
        echo ERROR: could not copy the CA bundle to %CA_DEST%.
        exit /b 1
    )
)

echo ==^> Writing the configuration
> "%CONFIG_FILE%" echo # Written by install-lariska.cmd. See lariska.example.toml
>>"%CONFIG_FILE%" echo # for every supported key.
>>"%CONFIG_FILE%" echo server_url = "%SERVER_URL%"
>>"%CONFIG_FILE%" echo provisioning_key_file = '%KEY_FILE%'
>>"%CONFIG_FILE%" echo state_dir = '%STATE_DIR%'
>>"%CONFIG_FILE%" echo inventory_interval_secs = 3600
>>"%CONFIG_FILE%" echo heartbeat_interval_secs = 60
>>"%CONFIG_FILE%" echo request_timeout_secs = 30
>>"%CONFIG_FILE%" echo log_level = "info"
if "%ALLOW_PLAIN%"=="1" (>>"%CONFIG_FILE%" echo allow_plain_http = true)
if defined CA_FILE (>>"%CONFIG_FILE%" echo tls_ca_file = '%CA_DEST%')

rem  --- validate before handing the service a config it will reject --------

if not exist "%CONFIG_FILE%" (
    echo ERROR: could not write %CONFIG_FILE%.
    exit /b 1
)

echo ==^> Validating the configuration
"%TARGET_EXE%" check-config --config "%CONFIG_FILE%"
if errorlevel 1 (
    echo ERROR: check-config rejected %CONFIG_FILE%; leaving the service unregistered.
    exit /b 1
)

rem  --- service ------------------------------------------------------------

if "%SERVICE_EXISTS%"=="0" (
    echo ==^> Registering the %SERVICE_NAME% service
    rem  sc.exe wants the space after each name=, and the executable path needs
    rem  its own quotes: it contains a space, and without them the SCM reads the
    rem  path as C:\Program with arguments.
    sc.exe create "%SERVICE_NAME%" binPath= "\"%TARGET_EXE%\" --winservice" start= auto DisplayName= "Lariska Endpoint Agent" >nul
    if errorlevel 1 (
        echo ERROR: sc.exe create failed.
        exit /b 1
    )
    sc.exe description "%SERVICE_NAME%" "Cross-platform endpoint inventory agent for Shapoclyack" >nul
)

rem  Recovery actions, set on every run so an existing installation gains them
rem  too. Two reasons, and the second is the one that is easy to miss:
rem
rem    1. An agent that crashes should come back without anyone visiting the
rem       machine, which is the entire premise of a fleet of these.
rem    2. A remotely installed upgrade takes effect only when the process ends
rem       and something starts the binary that is now on disk. The agent stops
rem       with a failure code precisely so this restarts it; without these
rem       actions the machine would be left with the new build installed and
rem       nothing running it.
rem
rem  failureflag is required for the second case: without it the SCM applies
rem  recovery only to a process that died, not to a service that reported
rem  SERVICE_STOPPED with an error code, which is how a graceful stop-to-
rem  upgrade looks.
sc.exe failure "%SERVICE_NAME%" reset= 86400 actions= restart/5000/restart/15000/restart/60000 >nul
sc.exe failureflag "%SERVICE_NAME%" 1 >nul

echo ==^> Starting the service
sc.exe start "%SERVICE_NAME%" >nul
if errorlevel 1 (
    echo ERROR: sc.exe start failed. The service log, if it was reached, is at
    echo        %STATE_DIR%\lariska.log
    exit /b 1
)

echo.
echo Lariska is installed and running against %SERVER_URL%.
echo   binary  %TARGET_EXE%
echo   config  %CONFIG_FILE%
echo   state   %STATE_DIR%
echo.
echo The service writes its log to %STATE_DIR%\lariska.log
echo ^(under the SCM there is no console, so stdout would go nowhere^):
echo   type "%STATE_DIR%\lariska.log"
exit /b 0

rem  --- helpers ------------------------------------------------------------

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
echo Usage: install-lariska.cmd ^<server-url^> ^<provisioning-key^> [/plainhttp] [/ca ^<pem^>]
echo.
echo   server-url        Base URL of the Shapoclyack API.
echo   provisioning-key  Key minted for this endpoint's tenant.
echo   /plainhttp        Permit a plain-http server URL. Lab stands only.
echo   /ca ^<pem^>         PEM bundle for an internal CA terminating the API's TLS.
exit /b 2
