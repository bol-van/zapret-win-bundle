@echo off

if "%1%" == "doit" (
	echo enable tcp timestamps
	netsh interface tcp set global timestamps=enabled
	goto :end
)

"%~dp0elevator" "%~f0" doit
goto :eof

:end
pause

