@echo off

if "%1%" == "del" (
	echo DELETE MONKEY DRIVER
	sc delete monkey
	sc stop monkey
	goto :end
)

sc qc monkey
if errorlevel 1 goto :end

echo.
choice /C YN /M "Do you want to stop and delete monkey"
if ERRORLEVEL 2 goto :eof

"%~dp0..\tools\elevator" %0 del
goto :eof

:end
pause
