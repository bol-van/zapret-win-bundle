@echo off
set TERM=
cd /d "%~dp0bin" && wscript ..\..\tools\elevator.vbs .\bash --login -i
