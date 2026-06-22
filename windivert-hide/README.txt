Это попытка скрыть windivert от некоторых программ (игры, античит), которые его не любят.
Может сработать, если проверка идет только по наличию драйвера с именем службы "windivert" или именем файла драйвера "WinDivert64.sys".
Имя службы драйвера переименовано в "Monkey", а файл драйвера - в "Monkey64.sys".
Однако, если проверка идет по имени устройства, создаваемого драйвером, или иным способом,
не связанным с именем службы и именем файла драйвера, то такую проверку обмануть не выйдет.
Monkey64.sys является точной копией WinDivert64.sys. WinDivert.dll был пересобран с небольшим патчингом кода.

Для использования переписать файлы WinDivert.dll и Monkey64.sys туда, где находится файл winws.exe.
Предварительно не забыть снять все программы, использующие windivert, и остановить оригинальную службу драйвера "WinDivert"
("sc stop windivert" от администратора или "zapret-winws/windivert_delete.cmd")

Для удаления измененной версии драйвера запустить "monkey_delete.cmd".


This is to hide windivert from software that check for presence of "WinDivert" service.
It does not help in case software checks for device created by driver.
It still has original name because changing it would require to recompile and resign driver.

To use : copy WinDivert.dll and Monkey64.sys to winws.exe folder.
