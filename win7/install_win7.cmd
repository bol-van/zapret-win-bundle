@echo off

cd /d "%~dp0"
setlocal enabledelayedexpansion

if [%1] == [install] goto :install

if %PROCESSOR_ARCHITECTURE%==AMD64 (
 FOR /F "tokens=1 skip=1 USEBACKQ" %%B IN (`wmic os get BuildNumber`) do set BUILD=!BUILD!%%B
 if defined BUILD (
  goto :build
 ) else (
  echo could not get OS build number
 )
) else (
 echo this works only on x64
)
goto :ex

:build
echo OS build number %BUILD%
if NOT %BUILD%==7601 if NOT %BUILD%==7600 goto dont
"%~dp0..\tools\elevator" "%~dpf0" install
goto :eof

:dont
echo only windows 7 is supported
goto ex

:install
echo copying windows 7 compatible windivert 2.2.0-C
copy WinDivert64.sys ..\zapret-winws
copy WinDivert.dll ..\zapret-winws
copy WinDivert64.sys ..\blockcheck\zapret\nfq
copy WinDivert.dll ..\blockcheck\zapret\nfq
copy WinDivert64.sys ..\blockcheck\zapret2\nfq2
copy WinDivert.dll ..\blockcheck\zapret2\nfq2
echo DONE

:ex
pause
