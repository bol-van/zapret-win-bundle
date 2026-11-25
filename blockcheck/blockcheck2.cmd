@echo off

cd /d "%~dp0"
FOR /F "tokens=* USEBACKQ" %%F IN (`..\cygwin\bin\cygpath -C OEM -a -m zapret2\blog.sh`) DO (
SET P='%%F'
)

"%~dp0..\tools\elevator" ..\cygwin\bin\bash -i "%P%"
