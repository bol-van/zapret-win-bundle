start "zapret2: wireguard" /min "%~dp0winws2.exe" ^
--wf-raw-part=@"%~dp0windivert.filter\windivert_part.wireguard.txt" ^
--lua-init=@"%~dp0lua\zapret-lib.lua" ^
--lua-init=@"%~dp0lua\zapret-antidpi.lua" ^
--lua-init=@"%~dp0lua\zapret-auto.lua" ^
--filter-l7=wireguard ^
 --payload=wireguard_initiation ^
  --lua-desync=repeater:instances=2:repeats=3 ^
  --lua-desync=luaexec:code="desync.rnd=brandom(math.random(32,64))" ^
  --lua-desync=fake:blob=rnd
