call :srvdel winws1
call :srvdel winws2
goto :eof

:srvdel
net stop %1
sc delete %1
