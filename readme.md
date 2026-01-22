# zapret winws bundle for windows

[main zapret1 repository](https://github.com/bol-van/zapret)

[main zapret2 repository](https://github.com/bol-van/zapret2)

requirements :
* Windows 7 x64, Windows server 2008 R2 (ESU updates or windivert files replacement required)
* Windows 8+ x64, Windows server 2012+ (may require to disable secure boot)
* Windows 11+ ARM64, Windows server 2025+ (requires testsigning mode)
* Windows Server requires installing of wireless networking feature

### Что это

Сборка, обьединяющая zapret1 и zapret2 под windows, включающая в себя минимальный cygwin комплект и blockcheck.

Это не однокнопочное решение, готовых стратегий и кнопки "открыть сайты" нет. Нужно понимать как работает zapret, иначе бесполезно.

### Краткое описание файлов

* `_CMD_ADMIN.cmd` : открыть командную строку под администратором
* `winws.exe` : главный компонент zapret, средство обхода DPI, версия nfqws для windows
* `winws2.exe` : главный компонент zapret2, средство обхода DPI, версия nfqws2 для windows
* `preset1_example.cmd` : интерактивный запуск стратегии-примера на базе winws (не является готовым лекарством)
* `preset2_example.cmd` : интерактивный запуск стратегии-примера на базе winws2 (не является готовым лекарством)
* `preset2_wireguard.cmd` : интерактивный запуск обхода блокировки wireguard протокола на любых портах
* `service*.cmd` : установка и управление службой windows (режим неинтерактивного автозапуска). НЕ ЗАПУСКАТЬ БЕЗ РЕДАКТИРОВАНИЯ !
* `enable_tcp_timestamps.cmd` : включить таймштампы tcp. по умолчанию отключены. требуются для ts fooling.
* `windivert_delete.cmd` : остановить и удалить драйвер windivert
* `killall.exe` : программа из cygwin для посылки unix сигналов winws
* `elevator.exe` : запускает программы от имени администратора
* `cygwin\cygwin.cmd` : запуск командной строки cygwin под текущим пользователем
* `cygwin\cygwin-admin.cmd` : запуск командной строки cygwin под администратором
* `blockcheck\blockcheck.cmd` : анализатор способов обхода DPI. Запускать только с остановленным zapret и другими средствами обхода DPI !
* `blockcheck\blockcheck-kyber.cmd` : то же самое, но используется CURL с многопакетным TLS Client Hello
* `blockcheck\blockcheck2.cmd` : анализатор способов обхода DPI на базе winws2. Запускать только с остановленным zapret и другими средствами обхода DPI !
* `blockcheck\blockcheck2-kyber.cmd` : то же самое, но используется CURL с многопакетным TLS Client Hello

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
Любой желающий может сравнить файлы с [оригиналами](https://reqrypt.org/download) от автора.
Но антивирусы склонны относить подобное к классам повышенного риска или хакерским инструментам.
В случае проблем используйте исключения или выключайте антивирус совсем.

---

### What is it ?

Combined zapret1 and zapret2 compilation for windows with minimal cygwin and blockcheck.

This is not one-button solution to open sites. zapret understanding is required to use.

### brief files description

* `_CMD_ADMIN.cmd` : open command prompt as administrator
* `winws.exe` : main zapret component, DPI bypass tool, nfqws version for windows
* `winws2.exe` : main zapret2 component, DPI bypass tool, nfqws2 version for windows
* `preset1_example.cmd` : run interactively example strategy using winws
* `preset2_example.cmd` : run interactively example strategy using winws2
* `preset2_wireguard.cmd` : run interactively wireguard protocol bypass
* `service*.cmd` : windows service setup and control (non-interactive autostart mode)
* `enable_tcp_timestamps.cmd` : enable tcp timestamps. they are disabled by default and required for ts fooling.
* `windivert_delete.cmd` : stop and delete windivert driver
* `killall.exe` : cygwin tool used in reload_lists.cmd. allows to send signals to winws.
* `elevator.exe` : simple tool to run a program as admin
* `cygwin\cygwin.cmd` : run cygwin prompt with current user privileges
* `cygwin\cygwin-admin.cmd` : run cygwin prompts with administrator privileges
* `blockcheck\blockcheck.cmd` : DPI bypass analyzer tool. Run only with zapret and other DPI bypass software stopped !
* `blockcheck\blockcheck-kyber.cmd` : use CURL with multi-segment TLS Client Hello
* `blockcheck\blockcheck2.cmd` : DPI bypass analyzer tool, winws2 based. Run only with zapret and other DPI bypass software stopped !
* `blockcheck\blockcheck2-kyber.cmd` : use CURL with multi-segment TLS Client Hello

### ARM64 preparation
1) run `arm64/install_arm64.cmd`
2) reboot if testsigning mode is not already enabled. "test mode" text should be present in the right bottom corner of the screen.

### WIN7 preparation
If windivert cannot start as is run `win7/install_win7.cmd`. Or install ESU updates.

### ANTIVIRUS WARNING
windivert may cause antivirus reaction. It's not a virus, your antivirus is insane.
It can treat windivert as potential risk or hacker instrument.
Use exceptions or disable AV completely if you are affected.
