start "zapret: wireguard" /min "%~dp0winws.exe" ^
--wf-raw-part=@"%~dp0windivert.filter\windivert_part.wireguard.txt" ^
--filter-l7=wireguard --dpi-desync=fake --dpi-desync-repeats=2
