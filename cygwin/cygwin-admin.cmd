@echo off
set TERM=
cd /d "%~dp0bin" && "%~dp0..\tools\elevator" .\bash --login -i
