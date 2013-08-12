@echo off
setlocal enableextensions enabledelayedexpansion

rem When adding port numbers to the list below, add them also to installx509.bat

for %%i in (3103 3202 3421 3422) do (
    netsh http delete sslcert ipport=0.0.0.0:%%i 2>&1 > nul
)

endlocal