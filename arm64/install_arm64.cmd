@echo off

cd /d "%~dp0"
setlocal enabledelayedexpansion

if [%1] == [install] goto :install

if %PROCESSOR_ARCHITECTURE%==ARM64 (
 FOR /F "tokens=1 skip=1 USEBACKQ" %%B IN (`wmic os get BuildNumber`) do set BUILD=!BUILD!%%B
 if defined BUILD (
  goto :build
 ) else (
  echo could not get OS build number
 )
) else (
 echo this works only on ARM64
)
goto :ex

:build
echo OS build number %BUILD%
if !BUILD! GEQ 22000 (
 wscript ..\tools\elevator.vbs "%~dpf0" install
 goto :eof
) else (
 echo only windows 11 or higher is supported
)
goto :ex

:install
echo stopping windivert driver
net stop windivert 2>nul
echo setting testsigning on
bcdedit /set {current} testsigning on
echo replacing WinDivert64.sys with unsigned ARM64 version
copy WinDivert64.sys ..\zapret-winws
copy WinDivert64.sys ..\blockcheck\zapret\nfq
echo copying ip2net and mdig
copy ip2net.exe ..\blockcheck\zapret\ip2net
copy mdig.exe ..\blockcheck\zapret\mdig
echo DONE. now reboot if testsigning was not enabled earlier.

:ex
pause
