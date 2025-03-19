@rem THIS BATCH FILE REQUIRES MANUAL EDIT
@rem SERVICE INSTALL IS COMMENTED TO PREVENT SCRIPT KIDDIES FROM DAMAGING THEIR SYSTEMS WITHOUT KNOWING HOW TO RECOVER
@rem щрнр тюик рпеасер педюйрхпнбюмхъ
@rem сярюмнбйю яксфаш гюйнллемрхпнбюмю, врнаш нцпюдхрэ мхвецн ме онмхлючыху мюфхлюрекеи мю бяе ондпъд нр опнакел, йнрнпше нмх ме б янярнъмхх пеьхрэ
@rem еякх мхвецн ме онмхлюере - ме рпнцюире щрнр тюик, нрйюфхреяэ нр хяонкэгнбюмхъ яксфаш. хмюве асдере охяюрэ онрнл бнопняш "с лемъ опноюк хмрепмер , йюй бняярюмнбхрэ"

set WINWS1=--wf-l3=ipv4,ipv6 --wf-tcp=80,443 --dpi-desync=fake,fakedsplit --dpi-desync-ttl=7 --dpi-desync-fooling=md5sig
rem schtasks /Create /F /TN winws1 /NP /RU "" /SC onstart /TR "\"%~dp0winws.exe\" %WINWS1%"
rem set WINWS2=--wf-l3=ipv4,ipv6 --wf-udp=443 --dpi-desync=fake
rem schtasks /Create /F /TN winws2 /NP /RU "" /SC onstart /TR "\"%~dp0winws.exe\" %WINWS2%"
