start "zapret: wireguard" /min "%~dp0winws.exe" ^
--wf-raw=@"%~dp0windivert.filter\windivert.wireguard.txt" ^
--filter-l7=wireguard --dpi-desync=fake
