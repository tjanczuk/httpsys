@echo off
setlocal enableextensions enabledelayedexpansion

certutil -f -p httpsys -importpfx %~dp0\..\performance\x509-sha1.pfx 2>&1 > nul
if "%ERRORLEVEL%" neq "0" (
    echo Error installing PFX certificate in LocalMachine\My store. Are you running as admin?
    endlocal
    exit /b -1
)

rem When adding port numbers to the list below, add them also to uninstallx509.bat

for %%i in (3103 3202 3421 3422) do (
    netsh http add sslcert ipport=0.0.0.0:%%i certhash=C08E29A696CCC5A25E2F3B9A9434EA624B837EE8 appid={00112233-4455-6677-8899-AABBCCDDEEFE} 2>&1 > nul
    if "!ERRORLEVEL!" neq "0" (
        echo Error setting up SSL with HTTP.SYS for TCP port %%i. Try running uninstallx509.bat first.
        endlocal
        exit /b -1
    )
)

rem Install client certificate into the Root store so that it is trusted

certutil -f -addstore root %~dp0\..\performance\x509-sha1-client.cer 2>&1 > nul
if "%ERRORLEVEL%" neq "0" (
    echo Error installing CER certificate in LocalMachine\Root store. Are you running as admin?
    endlocal
    exit /b -1
)

rem When adding port numbers to the list below, add them also to uninstallx509.bat

for %%i in (3501) do (
    netsh http add sslcert ipport=0.0.0.0:%%i certhash=C08E29A696CCC5A25E2F3B9A9434EA624B837EE8 appid={00112233-4455-6677-8899-AABBCCDDEEFE} clientcertnegotiation=enable 2>&1 > nul
    if "!ERRORLEVEL!" neq "0" (
        echo Error setting up mutual SSL with HTTP.SYS for TCP port %%i. Try running uninstallx509.bat first.
        endlocal
        exit /b -1
    )
)

endlocal