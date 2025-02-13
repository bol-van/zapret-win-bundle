# zapret winws bundle for windows

[main repository](https://github.com/bol-van/zapret)

requirements :
* Windows 7 x64, Windows server 2008 R2 (os updates may be required)
* Windows 8+ x64, Windows server 2012+ (may require to disable secure boot)
* Windows 11+ ARM64, Windows server 2025+ (requires testsigning mode)

[ENGLISH](#quick-start)

### Краткое описание файлов

* `_CMD_ADMIN.cmd` : открыть командную строку под администратором
* `winws.exe` : главный компонент zapret, средство обхода DPI, версия nfqws для windows
* `preset_russia.cmd` : интерактивный запуск наиболее распространенной стратегии для России
* `preset_russia_autohostlist.cmd` : интерактивный запуск наиболее распространенной стратегии для России с автоматическим заполнением хостлиста на основе обнаружения блокировок
* `service_*.cmd` : установка и управление службой windows (режим неинтерактивного автозапуска). НЕ ЗАПУСКАТЬ БЕЗ РЕДАКТИРОВАНИЯ !
* `task_*.cmd` : установка и управление запланированными задачами windows (режим неинтерактивного автозапуска). НЕ ЗАПУСКАТЬ БЕЗ РЕДАКТИРОВАНИЯ !
* `windivert_delete.cmd` : остановить и удалить драйвер windivert
* `killall.exe` : программа из cygwin для посылки unix сигналов winws
* `elevator.exe` : запускает программы от имени администратора
* `cygwin\cygwin.cmd` : запуск командной строки cygwin под текущим пользователем
* `cygwin\cygwin-admin.cmd` : запуск командной строки cygwin под администратором
* `blockcheck\blockcheck.cmd` : анализатор способов обхода DPI. Запускать только с остановленным zapret и другими средствами обхода DPI !

### быстрый старт

1) отключите все средства обхода блокировок, включая сам zapret
2) запустите `blockcheck/blockcheck.cmd` для поиска стратегий обхода DPI
3) если провайдер подменяет DNS - поменяйте DNS. если перехватывает DNS - используйте шифрованный DNS.
4) откройте `blockcheck.log` и найдите там рабочие стратегии (аргументы командной строки winws)
5) если можете - обьедините стратегии для http, https и quic. это требует знаний как работает обход DPI.
6) запустите winws с найденными параметрами из zapret-winws от имени администратора
7) `zapret-winws/task_*.cmd` управляют запланированными задачами для автозапуска вместе с windows.
   `zapret-winws/service_*.cmd` управляет службами windows для автозапуска вместе с windows.
   выберите один из вариантов, внесите туда параметры winws, при необходимости дублируйте код для поддержки нескольких экземпляров winws.
   создайте и запустите запланированные задачи. запускать cmd от имени администратора.

Подробности читайте в основном репозитории в `docs/windows.txt`, `docs/quick_start_windows.txt`

### ARM64 подготовка
1) запустите `arm64/install_arm64.cmd`
2) перезагрузите систему, если режим testsigning не был включен ранее. надпись "тестовый режим" должна быть на рабочем столе справа внизу.

### WIN7 подготовка
Если windivert не работает как есть запустите `win7/install_win7.cmd`. Или накатите обновления ESU.

### АНТИВИРУСЫ
windivert может вызвать реакцию антивируса.
windivert - это инструмент для перехвата и фильтрации трафика, необходимый для работы zapret.
Замена iptables и NFQUEUE в Linux, которых нет под Windows.
Он может использоваться как хорошими, так и плохими программами, но сам по себе не является вирусом.
Драйвер windivert64.sys подписан для возможности загрузки в 64-битное ядро windows.
Но антивирусы склонны относить подобное к классам повышенного риска или хакерским инструментам.
В случае проблем используйте исключения или выключайте антивирус совсем.

---
### quick start

1) disable all DPI bypass software including any VPN and zapret itself
2) run `blockcheck/blockcheck.cmd` to discover DPI bypass strategies
3) if your ISP fakes DNS - change DNS. if your ISP redirects DNS - use encrypted DNS.
4) open `blockcheck.log` and find working winws strategies (command line options)
5) if you can combine found strategies for http, https, quic. need knowledge how DPI bypass works.
6) run winws instances as admin from zapret-winws
7) `zapret-winws/task_*.cmd` manage scheduled task(s) to auto start winws.
   `zapret-winws/service_*`.cmd manages windows service(s) to auto start winws.
   choose one of them. edit .cmd files, add there your command line options. if required - clone the code to support multiple instances.
   create and run scheduled task as admin

### brief files description

* `_CMD_ADMIN.cmd` : open command prompt as administrator
* `winws.exe` : main zapret component, DPI bypass tool, nfqws version for windows
* `preset_russia.cmd` : run interactively most common strategy for Russia
* `preset_russia_autohostlist.cmd` : run interactively most common strategy for Russia with automatic hostlist fill based on blocking discovery
* `service_*.cmd` : windows service setup and control (non-interactive autostart mode)
* `task_*.cmd` : scheduled tasks setup and control (non-interactive autostart mode)
* `windivert_delete.cmd` : stop and delete windivert driver
* `killall.exe` : cygwin tool used in reload_lists.cmd. allows to send signals to winws.
* `elevator.exe` : simple tool to run a program as admin
* `cygwin\cygwin.cmd` : run cygwin prompt with current user privileges
* `cygwin\cygwin-admin.cmd` : run cygwin prompts with administrator privileges
* `blockcheck\blockcheck.cmd` : DPI bypass analyzer tool. Run only with zapret and other DPI bypass software stopped !

For full description refer to `docs/windows.txt` in the main repository.

### ARM64 preparation
1) run `arm64/install_arm64.cmd`
2) reboot if testsigning mode is not already enabled. "test mode" text should be present in the right bottom corner of the screen.

### WIN7 preparation
If windivert cannot start as is run `win7/install_win7.cmd`. Or install ESU updates.

### ANTIVIRUS WARNING
windivert may cause antivirus reaction. It's not a virus, your antivirus is insane.
It can treat windivert as potential risk or hacker instrument.
Use exceptions or disable AV completely if you are affected.
