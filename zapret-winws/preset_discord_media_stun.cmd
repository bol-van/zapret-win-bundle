start "zapret: discord_media,stun" /min "%~dp0winws.exe" ^
--wf-raw=@"%~dp0windivert.filter\windivert.discord_media+stun.txt" ^
--filter-l7=discord,stun --dpi-desync=fake
