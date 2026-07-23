Простой тестер стратегий по списку из файла.
Скопируйте эту директорию под другим именем в blockcheck2.d, отредактируйте list файлы, впишите туда свои стратегии.
В диалоге blockcheck2.sh выберите тест с названием вашей директории.
Можно комментировать строки символом '#' в начале строки.
Параметры со спец символами типа "<" должны быть эскейпнуты по правилам shell.
Альтернативный путь до файлов стратегий можно задать переменными LIST_HTTP, LIST_HTTPS_TLS12, LIST_HTTPS_TLS13, LIST_QUIC.

This is simple strategy tester from a file.
Copy this folder, write your strategies into list files and select your test in blockcheck2 dialog.
Lines can be commented using the '#' symbol at the line start.
Parameters with special symbols like "<" must be escaped.
Strategy list files paths can be overriden in env variables : LIST_HTTP, LIST_HTTPS_TLS12, LIST_HTTPS_TLS13, LIST_QUIC.
