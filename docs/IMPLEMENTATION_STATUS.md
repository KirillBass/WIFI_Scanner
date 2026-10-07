# Состояние реализации

ТЗ: `WirelessSecurityAnalyzer_Codex_TZ.docx` и предоставленный 7 октября 2026 года `WirelessSecurityAnalyzer_Milestone2_Codex.docx`. По запросу пользователя реализован второй этап поверх существующего сканера. Аппаратная проверка на Windows остаётся отдельной необходимой проверкой для обоих этапов.

## Первый этап — код реализован, аппаратная проверка ожидается

- Создан `WirelessSecurityAnalyzer.sln` с тремя проектами приложения. Тестирование ведётся локально, результаты сообщаются в чате.
- Core: immutable модели WifiAccessPoint и WifiAdapter, WifiBand, интерфейсы сканера/адаптеров, структурированные ошибки, преобразование частот и каналов.
- Infrastructure.Windows: P/Invoke WLAN API, ABI-структуры, SafeHandle, освобождение native memory, callback с удержанием delegate, TaskCompletionSource, отмена и тайм-аут.
- WindowsWifiScanner: реальные BSS, несколько адаптеров, объединение по BSSID, последовательное выполнение сканирований, локальное логирование.
- App: Avalonia 12.1.3, MVVM на CommunityToolkit, DI, русскоязычная тёмная тема, sidebar, шесть страниц навигации, ручной scan, TableView, индикатор RSSI, поиск/фильтры/сортировка, отмена, loading/empty/error states и переход к Location settings.
- README и профиль self-contained Windows x64.

Профиль публикации собирает self-contained приложение Windows x64 с включённым .NET Runtime. Папка публикации — `publish/win-x64/`; архив для переноса — `publish/WirelessSecurityAnalyzer-win-x64.zip`.

Реальную работу `wlanapi.dll`, запуск Windows `.exe`, соответствие результатов реальной Wi-Fi среде и поведение конкретных драйверов нужно проверить на Windows, прежде чем объявлять первый milestone полностью завершённым.

## Второй этап — код реализован, локальные проверки выполнены

### Новые файлы

- Core/Models: `SignalSample.cs`, `SignalStatistics.cs`, `WifiScanSnapshot.cs`, `WifiMonitorSnapshot.cs`.
- Core/Analysis: `SignalHistory.cs`, `SignalStatisticsCalculator.cs`.
- Core/Interfaces: `IWifiMonitorService.cs`, `IWifiScanState.cs`.
- Infrastructure.Windows/Wifi: `WifiMonitorService.cs`, `WifiScanService.cs`.

### Изменённые существующие файлы

- `Directory.Packages.props`, App `.csproj` и `packages.lock.json`: ScottPlot.Avalonia 5.1.59, совместимый с Avalonia 12, и его зависимости.
- `App.axaml.cs`: singleton DI-регистрации координатора, общего снимка и monitor service.
- `AccessPointsViewModel.cs`: получение общего успешного снимка, синхронизация ручных/автоматических результатов, ожидаемая остановка команды.
- `AccessPointRowViewModel.cs`: подпись SSID/BSSID/канал/RSSI для выбора.
- `SignalViewModel.cs`, `SignalView.axaml`, `SignalView.axaml.cs`: рабочий экран, команды, состояние, статистика и график.
- `MainWindowViewModel.cs`, `MainWindow.axaml.cs`, `MainWindow.axaml`: отмена и ожидание фоновых операций при закрытии; обозначение второго этапа.
- `DashboardViewModel.cs`, `DashboardView.axaml`: общие статус/выбранная сеть/текущий RSSI мониторинга.
- `SettingsView.axaml`: актуальная информация об интервале и времени жизни истории.
- `NativeWifiException.cs`, `WifiErrorPresenter.cs`: уточнение фатальных ошибок при недоступности WLAN и отключении устройства.
- README и этот документ: использование и актуальный статус.

Низкоуровневый scanner не заменён. Добавлены классификации кодов 50/1722 как недоступности WLAN и 1167 как недоступности адаптера, чтобы мониторинг не повторял заведомо неработающие операции бесконечно. Ожидание `WlanRegisterNotification`, SafeHandle и освобождение native memory сохранены.

### Цикл и данные

`SignalViewModel → IWifiMonitorService → IWifiScanner/WifiScanService → WindowsWifiScanner → Windows WLAN API`.

После успешного scan координатор публикует read-only копию полного списка BSS для «Эфира» и «Сигнала». Монитор выбирает BSSID без учёта регистра, добавляет реальное измерение и публикует read-only историю со статистикой. После полностью завершённого scan ждёт 5–60 секунд; следующий scan начинается только после этой паузы. Первое сканирование запускается сразу.

Общий семафор WifiScanService не допускает параллельных ручных и автоматических calls. Дополнительная прежняя защита WindowsWifiScanner сохранена. Stop отменяет запрос, ожидание очереди/уведомления/паузы и дожидается monitoring task. Уже переданный Windows `WlanScan` не получает физической команды отмены: это ограничение системного API.

Истории привязаны к BSSID, максимум 300 измерений на историю, в хронологическом порядке. Сохраняется максимум 32 истории; старые неактивные вытесняются. Timestamp — время получения scan result; данные живут в памяти до закрытия приложения. Stat calculator отдаёт Current как последнее по времени измерение, Average как арифметическое среднее dBm, Min/Max и LastSeen; пустой набор даёт nullable-показатели и Count=0. Все показатели относятся к текущему ограниченному окну.

При исчезновении точки sample не добавляется, история остаётся, текущий RSSI показывается как «—». При восстановлении запись продолжается. Timeout/ScanFailed логируются и допускают следующую попытку; отсутствие адаптера, RadioOff, недоступная служба, AccessDenied, неподдерживаемая ОС и некорректные native-данные останавливают loop. Неожиданные ошибки также завершаются контролируемо с сохранением истории.

Выбор точки/интервала блокируется во время мониторинга. Clear очищает только выбранную историю и не останавливает loop. Навигация сохраняет singleton service/ViewModel. Закрытие главного окна асинхронно ожидает завершения мониторинга, ручного scan и начальной проверки адаптеров.

### График

ScottPlot.Avalonia 5.1.59, API major 5. AvaPlot остаётся тем же при обновлении данных; обновляется серия из максимум 300 точек, затем запрашивается перерисовка. Переход на UI thread выполнен в ViewModel; изменения графика выполняются только в View, через UI Dispatcher, с объединением повторных запросов обновления. Core/monitor service не зависят от Avalonia.

По X — UTC Timestamp с локальным отображением HH:mm:ss; по Y — RSSI, сильный сигнал выше. Основной диапазон −100…−20 dBm расширяется для реальных значений вне него. Цвета берутся из существующих theme resources. Проверены подпись и читаемость обеих осей на тёмном фоне.

Использованный API и зависимости проверены по [официальной странице пакета](https://www.nuget.org/packages/ScottPlot.Avalonia/5.1.59), [Avalonia quickstart](https://scottplot.net/quickstart/avalonia/) и [ScottPlot 5 cookbook](https://scottplot.net/cookbook/5/CustomizingTicks/).

### Проверки 7 октября 2026 года

- Release build: 0 errors, 0 warnings.
- Локальные тесты: 98 passed, 0 failed, 1 skipped (реальное Windows-оборудование недоступно в Linux).
- Покрыты: bounded/chronological history, точная статистика из ТЗ, пустые состояния, BSSID case matching, исчезновение/восстановление, временные/фатальные ошибки, реальные паузы после завершения scan, cancellation, Stop/Start/Clear, общий scan gate и неизменяемые snapshots.
- Avalonia headless UI: прежний «Эфир», все страницы, общий список, выбор/блокировка выбранного BSSID, навигация при мониторинге, ScottPlot series/axes/clear без пересоздания control, Location settings, ожидание отмены при закрытии окна.
- Обычное GUI на Linux/X11: запуск, сообщение о неподдерживаемой платформе, переход в «Сигнал», читаемый тёмный экран/пустой график, выбор интервала и корректное закрытие. Созданы локальные изображения окна и графика для визуальной проверки.

Тестовые исходники и артефакты находятся вне репозитория, в отдельной локальной директории. Они не включены в solution приложения и не публикуются в Git. Hardware scan, живые RSSI на Windows и отключение настоящего USB-адаптера ещё не проверены: эти сценарии локально проверялись с fake scanner и требуют реальной Windows-проверки.

## Оставшиеся этапы

1. Аппаратная проверка обоих реализованных этапов на Windows с Wi-Fi адаптером.
2. RSSI-weighted ChannelAnalyzer, оценочная модель перекрытия, рекомендации по диапазонам, локальные тесты и экран «Каналы».
3. Устройства собственной локальной IP-сети: Wi-Fi IPv4 interface, subnet/gateway, ограниченный discovery до 1024 адресов, соседняя таблица через IP Helper API, контролируемый параллелизм и отмена.
4. Полный Dashboard, сведения о текущем подключении, итоговая UX-полировка и проверка стабильности Release на Windows.

Алгоритм оценки каналов и discovery пока отсутствуют. Их страницы явно обозначают этот статус. Порт-сканер, crawler, перехват трафика, анализ контента, базы данных и cloud services не входят в текущую реализацию.
