@echo off

if "%1%" == "del" (
	echo DELETE WINDIVERT DRIVER
	sc delete windivert
	sc stop windivert
	goto :end
)

sc qc windivert
if errorlevel 1 goto :end

echo.
choice /C YN /M "Do you want to stop and delete windivert"
if ERRORLEVEL 2 goto :eof

wscript elevator.vbs "%0" del
goto :eof

:end
pause
