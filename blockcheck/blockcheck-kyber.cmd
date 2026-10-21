@echo off

cd /d "%~dp0"
FOR /F "tokens=* USEBACKQ" %%F IN (`..\cygwin\bin\cygpath -C OEM -a -m zapret\blog_kyber.sh`) DO (
SET P='%%F'
)

"%~dp0..\tools\elevator" ..\cygwin\bin\bash -i "%P%"
