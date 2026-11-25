# Wireless Security Analyzer

Для Windows x64. Установка .NET не требуется: среда выполнения включена в поставку.

Полностью распакуйте архив и запустите `WirelessSecurityAnalyzer.exe` в папке `win-x64`.
Можно перенести папку целиком, в том числе в путь с пробелами и русскими буквами.
Сохраняйте EXE, `runtime` и `docs` вместе.

```text
win-x64/
  WirelessSecurityAnalyzer.exe   основной файл запуска
  runtime/                      приложение, .NET, Avalonia и библиотеки
  docs/
    README.md                   эта инструкция
    dependencies.json           состав, происхождение и SHA-256 файлов
```

В `runtime` сохранена штатная раскладка зависимостей .NET. EXE создан обычным
загрузчиком из .NET SDK и указывает на `runtime/WirelessSecurityAnalyzer.dll`.
Метаданные `.deps.json` и `.runtimeconfig.json`, нативные библиотеки и возможные
подпапки локализации находятся рядом с управляемым приложением. Не перемещайте
отдельные DLL и не запускайте служебные файлы из `runtime`.

Карта `dependencies.json` различает собственный код, UI, сеть, диагностику,
сторонние пакеты, компоненты .NET и служебные файлы по фактическому графу
зависимостей. Категории в карте логические: физическое соседство библиотек нужно
штатному загрузчику. Ресурсы Avalonia, шрифты и локальная OUI-база остаются
встроенными в сборки. Отладочные PDB в пользовательскую поставку не включаются.

По умолчанию логи создаются в `%LOCALAPPDATA%\WirelessSecurityAnalyzer\Logs`.
Папку можно изменить в «Настройках»; новый путь применяется после перезапуска.
Выбор хранится в `%LOCALAPPDATA%\WirelessSecurityAnalyzer\settings.json`.
Если папка недоступна, программа использует стандартную или временную папку
и показывает пояснение.
Папка приложения может быть доступна только для чтения. Для функций Wi-Fi
нужны Windows, исправный адаптер и служба WLAN AutoConfig; доступность сетевых
узлов и служб зависит от настроек самой сети.

Для разработчика: команда публикации из корня репозитория:

```text
dotnet publish src/WirelessSecurityAnalyzer.App -c Release -p:PublishProfile=WindowsX64
```

Она автоматически создаёт папку `publish/win-x64`, ZIP и файл SHA-256 рядом.
Повторная публикация заменяет предыдущий состав поставки. Обычные `dotnet build`
и Debug сохраняют стандартные каталоги и символы отладки. Параметр
`-p:WsaOrganizePublish=false -p:WsaCreateArchive=false` оставляет стандартную
плоскую публикацию для диагностики; используйте для неё отдельный каталог.

Single-file, trimming, AOT и ReadyToRun здесь не включены.

При запуске открывается «Сетевой аудит». Выберите активный IPv4-интерфейс
в «Устройствах» или подключитесь к поддерживаемой Wi-Fi-сети в «Эфире».
Проверки начинаются только по команде пользователя. «Настройки» позволяют
сохранить стартовую вкладку, интерфейс, профиль аудита, включение своего ПК
и компактную высоту строк. Параметры аудита применяются при следующем запуске,
а высота строк сразу после сохранения.

## FluentFTP (MIT)

Copyright (c) 2015 Robin Rodricks and FluentFTP Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
