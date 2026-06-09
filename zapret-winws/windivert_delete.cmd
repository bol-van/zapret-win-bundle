@echo off

if "%1%" == "del" (
	echo DELETE WINDIVERT DRIVER
	sc stop windivert
	sc delete windivert
	goto :end
)

sc qc windivert
if errorlevel 1 goto :end

echo.
choice /C YN /M "Do you want to stop and delete windivert"
if ERRORLEVEL 2 goto :eof

"%~dp0elevator" "%~f0" del
goto :eof

:end
pause
