@echo off
setlocal enableextensions enabledelayedexpansion

rem When adding port numbers to the list below, add them also to installx509.bat

for %%i in (3103 3202 3421 3422 3501) do (
    netsh http delete sslcert ipport=0.0.0.0:%%i 2>&1 > nul
)

rem Remove client certificate (x509-sha1-client, CN=httpsys-client) from LocalMachine\Root store

certmgr -del -c -s -r LocalMachine Root -sha1 54713DE856FB5D4EAEDEC9E4E7A354F5DA02EFEF 2>&1 > nul

endlocal