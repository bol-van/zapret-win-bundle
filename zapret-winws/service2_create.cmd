@rem THIS BATCH FILE REQUIRES MANUAL EDIT
@rem SERVICE INSTALL IS COMMENTED TO PREVENT SCRIPT KIDDIES FROM DAMAGING THEIR SYSTEMS WITHOUT KNOWING HOW TO RECOVER
@rem ЭТОТ ФАЙЛ ТРЕБУЕТ РЕДАКТИРОВАНИЯ
@rem УСТАНОВКА СЛУЖБЫ ЗАКОММЕНТИРОВАНА, ЧТОБЫ ОГРАДИТЬ НИЧЕГО НЕ ПОНИМАЮЩИХ НАЖИМАТЕЛЕЙ НА ВСЕ ПОДРЯД ОТ ПРОБЛЕМ, КОТОРЫЕ ОНИ НЕ В СОСТОЯНИИ РЕШИТЬ
@rem ЕСЛИ НИЧЕГО НЕ ПОНИМАЕТЕ - НЕ ТРОГАЙТЕ ЭТОТ ФАЙЛ, ОТКАЖИТЕСЬ ОТ ИСПОЛЬЗОВАНИЯ СЛУЖБЫ. ИНАЧЕ БУДЕТЕ ПИСАТЬ ПОТОМ ВОПРОСЫ "У МЕНЯ ПРОПАЛ ИНТЕРНЕТ , КАК ВОССТАНОВИТЬ"

set ARGS=^
--wf-tcp-out=80,443  ^
--lua-init=@\"%~dp0lua\zapret-lib.lua\" --lua-init=@\"%~dp0lua\zapret-antidpi.lua\" ^
--lua-init=\"fake_default_tls = tls_mod(fake_default_tls,'rnd,rndsni')\" ^
--blob=quic_google:@\"%~dp0files\quic_initial_www_google_com.bin\" ^
--wf-raw-part=@\"%~dp0windivert.filter\windivert_part.discord_media.txt\" ^
--wf-raw-part=@\"%~dp0windivert.filter\windivert_part.stun.txt\" ^
--wf-raw-part=@\"%~dp0windivert.filter\windivert_part.wireguard.txt\" ^
--wf-raw-part=@\"%~dp0windivert.filter\windivert_part.quic_initial_ietf.txt\" ^
--filter-tcp=80 --filter-l7=http ^
  --out-range=-d10 ^
  --payload=http_req ^
   --lua-desync=fake:blob=fake_default_http:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5 ^
   --lua-desync=fakedsplit:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5 ^
  --new ^
--filter-tcp=443 --filter-l7=tls --hostlist=\"%~dp0files\list-youtube.txt\" ^
  --out-range=-d10 ^
  --payload=tls_client_hello ^
   --lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=11:tls_mod=rnd,dupsid,sni=www.google.com ^
   --lua-desync=multidisorder:pos=1,midsld ^
  --new ^
--filter-tcp=443 --filter-l7=tls ^
  --out-range=-d10 ^
  --payload=tls_client_hello ^
   --lua-desync=fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000:repeats=6 ^
   --lua-desync=multidisorder:pos=midsld ^
  --new ^
--filter-udp=443 --filter-l7=quic --hostlist=\"%~dp0files\list-youtube.txt\" ^
  --payload=quic_initial ^
   --lua-desync=fake:blob=quic_google:repeats=11 ^
  --new ^
--filter-udp=443 --filter-l7=quic ^
  --payload=quic_initial ^
   --lua-desync=fake:blob=fake_default_quic:repeats=11 ^
  --new ^
--filter-l7=wireguard,stun,discord ^
  --payload=wireguard_initiation,wireguard_cookie,stun,discord_ip_discovery ^
   --lua-desync=fake:blob=0x00000000000000000000000000000000:repeats=2

rem call :srvinst winws1
set ARGS=--wf-raw-part=@\"%~dp0windivert.filter\windivert_part.wireguard.txt\" ^
--filter-l7=discord,stun --dpi-desync=fake
rem call :srvinst winws2
goto :eof

:srvinst
net stop %1
sc delete %1
sc create %1 binPath= "\"%~dp0winws2.exe\" %ARGS%" DisplayName= "zapret2 DPI bypass : %1" start= auto
sc description %1 "zapret2 DPI bypass software"
sc start %1
