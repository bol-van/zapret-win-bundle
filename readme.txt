Zapret winws bundle for windows

main repository : https://github.com/bol-van/zapret

requirements :
 Windows 7 x64, Windows server 2008 R2 (os updates may be required)
 Windows 8+ x64, Windows server 2012+ (may require to disable secure boot)
 Windows 11+ ARM64, Windows server 2025+ (requires testsigning mode)

quick start

1) disable all DPI bypass software including any VPN and zapret itself
2) run blockcheck/blockcheck.cmd to discover DPI bypass strategies
3) if your ISP fakes DNS - change DNS. if your ISP redirects DNS - use encrypted DNS. then restart blockcheck.
4) open blockcheck.log and find working winws strategies (command line options)
5) if you can combine found strategies for http, https, quic. need knowledge how DPI bypass works.
6) run winws instances as admin from zapret-winws
7) zapret-winws/task_*.cmd manage scheduled task(s) to auto start winws.
   edit .cmd files, add there your command line options. if required - clone the code to support multiple instances.
   create and run scheduled task as admin

1) отключите все средства обхода блокировок, включая сам zapret
2) запустите blockcheck/blockcheck.cmd для поиска стратегий обхода DPI
3) если провайдер подменяет DNS - поменяйте DNS. если перехватывает DNS - используйте шифрованный DNS. затем перезапустите blockcheck.
4) откройте blockcheck.log и найдите там рабочие стратегии (аргументы командной строки winws)
5) если можете - обьедините стратегии для http, https и quic. это требует знаний как работает обход DPI.
6) запустите winws с найденными параметрами из zapret-winws от имени администратора
7) zapret-winws/task_*.cmd управляют запланированными задачами для автозапуска вместе с windows.
   внесите туда параметры winws, при необходимости дублируйте код для поддержки нескольких экземпляров winws.
   создайте и запустите запланированные задачи. запускать cmd от имени администратора.


ARM64 preparation :
1) run arm64/install_arm64.cmd
2) reboot if testsigning mode is not already enabled. "test mode" text should be present in the right bottom corner of the screen.

ARM64 подготовка :
1) запустите arm64/install_arm64.cmd
2) перезагрузите систему, если режим testsigning не был включен ранее. надпись "тестовый режим" должна быть на рабочем столе справа внизу.
