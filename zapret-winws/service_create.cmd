@rem THIS BATCH FILE REQUIRES MANUAL EDIT
@rem SERVICE INSTALL IS COMMENTED TO PREVENT SCRIPT KIDDIES FROM DAMAGING THEIR SYSTEMS WITHOUT KNOWING HOW TO RECOVER
@rem ЭТОТ ФАЙЛ ТРЕБУЕТ РЕДАКТИРОВАНИЯ
@rem УСТАНОВКА СЛУЖБЫ ЗАКОММЕНТИРОВАНА, ЧТОБЫ ОГРАДИТЬ НИЧЕГО НЕ ПОНИМАЮЩИХ НАЖИМАТЕЛЕЙ НА ВСЕ ПОДРЯД ОТ ПРОБЛЕМ, КОТОРЫЕ ОНИ НЕ В СОСТОЯНИИ РЕШИТЬ
@rem ЕСЛИ НИЧЕГО НЕ ПОНИМАЕТЕ - НЕ ТРОГАЙТЕ ЭТОТ ФАЙЛ, ОТКАЖИТЕСЬ ОТ ИСПОЛЬЗОВАНИЯ СЛУЖБЫ. ИНАЧЕ БУДЕТЕ ПИСАТЬ ПОТОМ ВОПРОСЫ "У МЕНЯ ПРОПАЛ ИНТЕРНЕТ , КАК ВОССТАНОВИТЬ"

set ARGS=^
--wf-tcp=80,443 ^
--wf-raw-part=@\"%~dp0windivert.filter\windivert_part.discord_media.txt\" ^
--wf-raw-part=@\"%~dp0windivert.filter\windivert_part.stun.txt\" ^
--wf-raw-part=@\"%~dp0windivert.filter\windivert_part.wireguard.txt\" ^
--wf-raw-part=@\"%~dp0windivert.filter\windivert_part.quic_initial_ietf.txt\" ^
--filter-tcp=80 --dpi-desync=fake,fakedsplit --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --new ^
--filter-tcp=443 --hostlist=\"%~dp0files\list-youtube.txt\" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=11 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com --new ^
--filter-tcp=443 --dpi-desync=fake,multidisorder --dpi-desync-split-pos=midsld --dpi-desync-repeats=6 --dpi-desync-fooling=badseq,md5sig --new ^
--filter-l7=quic --hostlist=\"%~dp0files\list-youtube.txt\" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic=\"%~dp0files\quic_initial_www_google_com.bin\" --new ^
--filter-l7=quic --dpi-desync=fake --dpi-desync-repeats=11

rem call :srvinst winws1
set ARGS=--wf-raw-part=@\"%~dp0windivert.filter\windivert_part.wireguard.txt\" ^
--filter-l7=discord,stun --dpi-desync=fake
rem call :srvinst winws2
goto :eof

:srvinst
net stop %1
sc delete %1
sc create %1 binPath= "\"%~dp0winws.exe\" %ARGS%" DisplayName= "zapret DPI bypass : %1" start= auto
sc description %1 "zapret DPI bypass software"
sc start %1
