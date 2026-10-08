# Состояние реализации

ТЗ: `WirelessSecurityAnalyzer_Codex_TZ.docx`, `WirelessSecurityAnalyzer_Milestone2_Codex.docx`, `WirelessSecurityAnalyzer_Milestone3_Codex.docx`, `WirelessSecurityAnalyzer_Milestone4_Codex.docx`. Реализован код первых четырёх этапов поверх существующего сканера. Аппаратная проверка на Windows остаётся необходимой проверкой.

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

## Третий этап — код реализован, локальные проверки выполнены

### Новые файлы

- `Core/Analysis/Channels/SignalWeightCalculator.cs`: чистый вес RSSI, с параметрами из options.
- `Core/Analysis/Channels/ChannelOverlapCalculator.cs`: коэффициент пересечения равных полос по реальной разнице частот.
- `Core/Analysis/Channels/WifiChannelCatalog.cs`: централизованные кандидаты, конфигурация по диапазонам и преобразования через прежний WifiChannelHelper.
- `Core/Analysis/Channels/ChannelAnalyzer.cs`: нормализация входных BSS, дедупликация, scores/counts/levels, стабильная рекомендация и готовая геометрия контуров.
- `Core/Interfaces/IChannelAnalyzer.cs`, `IChannelOverlapModel.cs`, `IChannelCandidateProvider.cs`: независимые от UI договоры.
- `Core/Models/ChannelAnalysisOptions.cs`: коэффициенты, пороги, исключаемый BSSID и необязательный список кандидатов для анализируемого диапазона.
- `Core/Models/ChannelLoadLevel.cs`, `ChannelAnalysisResult.cs`: уровни и immutable результат одного канала.
- `Core/Models/ChannelAnalysisSnapshot.cs`: immutable анализ; в этом же файле связанная модель `ChannelSpectrumCurve` с read-only геометрией и исходной BSS.
- `Core/Models/WifiScanFailure.cs`: ошибка общего источника, упорядоченная вместе с успешными снимками.
- `App/ViewModels/ChannelRowViewModel.cs`: русские подписи уровней, единицы и числовая оценка для таблицы.

### Изменённые существующие файлы

- `App.axaml.cs`: DI для options, overlap model, candidate provider и analyzer.
- `ChannelsViewModel.cs`: диапазон, общий снимок/ошибка, анализ, однократное обновление/отмена, сохранение данных, журналирование и остановка.
- `ChannelsView.axaml`: выбор диапазона, состояния, AvaPlot, рекомендация и семь колонок таблицы.
- `ChannelsView.axaml.cs`: отображение готовых контуров, частотная ось, палитра ScottPlot и подсказки по BSSID; оценки здесь не рассчитываются.
- `MainWindowViewModel.cs`: отмена и ожидание обновления «Каналов» при закрытии.
- `MainWindow.axaml`: обозначение третьего этапа.
- `IWifiScanState.cs`, `WifiScanService.cs`: добавлены LastFailure/Failed. Прежний successful snapshot сохраняется при ошибке; новые успешные данные снимают ошибку. Cancellation не публикуется как failure. Общая возрастающая Version упорядочивает успешные и неуспешные попытки; запоздалые уведомления игнорируются.
- README и этот документ; локальный учебный разбор дополнен отдельно, он исключён из Git.

Пакеты, solution, низкоуровневый WindowsWifiScanner, Native Wi-Fi API и цикл WifiMonitorService не заменялись. Нового scanner или polling loop нет. Новые зависимости NuGet не требуются: используется уже установленный ScottPlot.Avalonia 5.1.59.

### Формулы и политика

`SignalWeight = clamp((rssi - floor) / (ceiling - floor), 0, 1)`, defaults: −95/−35 dBm. `OverlapFactor = clamp(1 - abs(apFrequency - candidateFrequency) / width, 0, 1)`, default width 20 МГц. `RawScore = SUM(weight × overlap)`; `LoadScorePercent = clamp(raw / saturation × 100, 0, 100)`, default saturation 3.0. Пороги 20/40/60/80 — в options, конфигурация проверяется до расчёта. Нормализация фиксирована, максимум текущего scan не используется.

DirectBssCount считает нормализованный канал, InfluencingBssCount — положительное перекрытие, включая очень слабую BSS с нулевым весом. Дедупликация по BSSID без учёта регистра, strongest wins; порядок суммирования детерминирован. Hidden и одинаковые SSID разных BSSID учитываются независимо. Некорректные частоты/BSSID пропускаются с диагностическими счётчиками и Warning, неправильные номера/диапазоны уточняются по частоте. Используется последний RSSI; усреднение по истории мониторинга не применяется.

Рекомендация: минимальный процент → меньше InfluencingBssCount → меньше DirectBssCount → меньший номер канала. При пустом диапазоне или отсутствии кандидатов recommended=null. Базовые наборы: 2,4 ГГц 1–13; 5 ГГц 25 распространённых primary 20-МГц каналов; 6 ГГц 59 каналов 1+4n. Канал 14 / специальный 6-ГГц канал 2 добавляются только при обнаружении либо явной настройке. Провайдер можно заменить данными региона/адаптера; текущий набор не подтверждает разрешение канала. Это пояснение видно в интерфейсе.

График: X — центральная частота МГц, Y — RSSI dBm; более сильная BSS выше. Core строит симметричный косинусный контур с шириной 20 МГц и пиком на реальном центре/RSSI. Контур является визуальным приближением, а не спектральной маской. Цвета назначает палитра ScottPlot, оси и фон берутся из темы. При наведении показаны SSID/BSSID/канал/частота/RSSI; длинная общая легенда скрыта. AvaPlot сохраняется при обновлениях; новые линии заменяют старые, перерисовка объединяется и выполняется на UI thread только при изменённом анализе.

`WifiScanService.Updated → ChannelsViewModel → IChannelAnalyzer → ChannelAnalysisSnapshot → таблица/ScottPlot`. Ручные и автоматические результаты обновляют все три страницы. «Обновить анализ» выполняет одну отменяемую операцию в существующей очереди. Источник и Core не меняют ObservableCollection; ViewModel и график обновляются на UI thread. Остановка мониторинга оставляет последний анализ. Закрытие окна ожидает завершения нового refresh command.

### Локальные проверки третьего этапа

- Release build: 0 ошибок, 0 предупреждений.
- Тесты: 155 passed, 0 failed, 1 skipped (требуется реальное Windows-оборудование). Все исходники тестов хранятся вне репозитория.
- Новые 57 проверок: формулы/границы/монотонность/пороги/фиксированная нормализация, сильные/слабые/несколько BSS, Hidden и одинаковые SSID, counts/tie-breakers, пустые диапазоны/кандидаты, 5/6-ГГц расстояния, специальные каналы/конфигурация, нормализация/дедупликация, ExcludedBssid, геометрия и immutable результаты; UI/table/plot/band/hover/empty/error/cancel/shutdown, общий monitoring snapshot, source failure/version ordering и изоляция ошибочного subscriber.
- Прежние проверки сканирования, «Эфира», мониторинга/истории/ScottPlot, навигации всех страниц и закрытия окна проходят.
- Linux GUI: запуск приложения, рабочая страница «Каналы», empty state и обработка UnsupportedPlatform. В отдельном локальном preview проверены тестовые BSS 2,4/5/6 ГГц, переключение диапазонов, положение/высота пиков, таблица и корректное закрытие; тестовых данных в production scanner нет. Изображения остаются в локальных артефактах.

Остаются аппаратные сценарии Windows: реальный scan, анализ настоящих 2,4/5/6-ГГц BSS, проверка драйверов/разрешений и отключения USB Wi-Fi адаптера. В Linux проверяется алгоритм и UI, а не работа wlanapi.dll. Реальная ширина, RF airtime/не-Wi-Fi помехи, regulatory domain и текущий подключённый BSSID не определяются. Четвёртый этап не реализован.

## Четвёртый этап — код реализован, аппаратная проверка ожидается

### Добавленные и изменённые файлы

Добавлены 20 production-файлов; существующие solution, проекты, версии NuGet и WindowsWifiScanner сохранены.

- Core/Models: `LocalNetworkInfo.cs` — интерфейс/IPv4-контекст; `NetworkDevice.cs` — устройство, состояние, evidence и наблюдение; `DeviceDiscoveryResult.cs` — результат, прогресс, neighbor/probe DTO и snapshot мониторинга.
- Core/Interfaces: `ILocalNetworkService.cs`, `IDeviceDiscoveryService.cs`, `IDeviceMonitorService.cs`, `INetworkDiscoverySources.cs` — договоры выбора сети, единичного discovery, сессионного мониторинга и источников Ping/neighbor/DNS. Связанные небольшие договоры сгруппированы в одном файле.
- Core/Network: `SubnetCalculator.cs`, `DeviceDiscoveryOptions.cs`, `DeviceStateTracker.cs`, `NetworkDiscoveryException.cs` — чистая арифметика, проверяемые лимиты, история и ошибки.
- Infrastructure.Windows/Interop: `IpHelperNativeMethods.cs`, `IpHelperStructs.cs` — Win32 calls и ABI отдельно от Core.
- Infrastructure.Windows/Network: `WindowsLocalNetworkService.cs`, `WindowsNeighborTableReader.cs`, `PingHostProbe.cs`, `HostnameResolver.cs`, `WindowsDeviceDiscoveryService.cs`, `DeviceMonitorService.cs` — источники ОС, один цикл и единственный scan/delay loop.
- App/ViewModels: `DeviceRowViewModel.cs` — подписи/форматирование строки и пояснения состояний.

Изменены `DevicesViewModel.cs`, `DevicesView.axaml`, `App.axaml.cs` (DI), `MainWindowViewModel.cs` (инициализация и shutdown), `MainWindow.axaml` (этап 4), README и этот отчёт. Локальный учебный разбор дополнен отдельно и остаётся исключённым из Git.

### Интерфейс и подсеть

Выбираются OperationalStatus.Up Wi-Fi/Ethernet интерфейсы с пригодным unicast IPv4; loopback/tunnel/PPP и APIPA исключаются. Начальный приоритет детерминирован: gateway → Wireless80211 → имя/ID → числовой IPv4. Пользователь может явно выбрать другой контекст в ComboBox; Ethernet без gateway также допустим. Связи с WLAN через текстовое имя/описание не вводятся. Контекст включает ID, текущий interface index, IPv4, prefix и gateway; смена любого из них останавливает цикл до публикации частичных результатов.

SubnetCalculator преобразует октеты в uint в сетевом порядке, строит маску, network/broadcast и host range. /24 содержит 254, /22 — 1022 host-адреса; собственный IP исключается из probes. /31 имеет 2 endpoint, /32 — 1, broadcast=null; для MVP sweep обоих явно запрещён. Guard до enumeration/сетевых запросов ограничивает максимум 1024 hosts. Полное перечисление /8 или /0 не выполняется; произвольного удалённого диапазона нет.

### Один discovery cycle

1. Проверка актуальности выбранного интерфейса и IPv4-контекста.
2. GetIpNetTable2(AF_INET), фильтр interface index/host range, копирование managed данных, FreeMibTable в finally.
3. Lazy enumeration с Parallel.ForEachAsync: максимум 32 Ping, timeout 500 мс по умолчанию. Собственный компьютер добавляется из NetworkInfo. Системный маршрут проверяется через GetBestInterfaceEx перед отправкой; другой интерфейс/отсутствие маршрута означает пропуск адреса.
4. Повторная проверка контекста и чтение neighbor table; всего два чтения за цикл.
5. Merge по IP: latency берётся только из успешного echo reply, MAC — только из валидных системных данных; fresh neighbor может обнаружить устройство без Ping. Reachable подтверждает присутствие. Новая/сменившая MAC динамическая запись после probes также учитывается, если оба чтения удались. Неизменные Stale/Delay/Probe, Permanent/Incomplete/Unreachable и просто изменение счётчика возраста не подтверждают Online. Gateway flag сам по себе не создаёт устройство.
6. Необязательный системный reverse DNS: timeout 1000 мс, параллелизм 4 по умолчанию; успешный hostname кэшируется на 5 минут в контексте IPv4. Отдельный глобальный DNS gate ограничивает незавершённые операции до 8; после timeout место освобождается при завершении исходного lookup. Имя не является подтверждением присутствия или ключом истории.
7. Проверка контекста и возврат read-only observations/метаданных. Прогресс ограничен примерно 10 обновлениями в секунду и сменами этапов.

Существенные Win32 ошибки записываются в log. При недоступной neighbor table сохраняются результаты Ping и показывается предупреждение. Если итоговое чтение соседей не удалось, есть ошибки probes или пропущенные маршруты, результат не увеличивает счётчики отсутствия. Все ICMP операции с ошибкой дают отдельную ошибку цикла. DNS failure/timeout не ломает discovery; отмена не считается ошибкой.

### История, мониторинг, UI

DeviceStateTracker сопоставляет валидный MAC в текущей L2-сети, затем IP при отсутствии противоречащего известного MAC. Одинаковые hostname не объединяют устройства. При смене известного MAC на том же IP создаётся отдельная история. FirstSeen сохраняется при DHCP-смене IP известного MAC и повторном обнаружении; LastSeen обновляется только при подтверждённом evidence. Первый/второй полный пропуск → Unknown, третий → Offline; порог в options. Новый evidence возвращает Online. Прерванный/ошибочный scan не старит историю.

DeviceMonitorService координирует и ручной discovery, и фоновые циклы. Lifecycle gate отвергает второй запуск во время операции; discovery дополнительно сериализует прямые вызовы. Первый цикл сразу; задержка 10/30/60/120 секунд начинается после завершения предыдущего. Временные ошибки probes допускают следующую попытку, смена/исчезновение сети останавливает мониторинг. История хранится в памяти до закрытия/смены контекста. Stop и shutdown отменяют token и ожидают worker/команды; навигация цикл не останавливает.

DevicesViewModel переносит snapshot/progress на UI Dispatcher и игнорирует старые версии и callbacks после Stop. Строки обновляются по изменённому массиву данных; progress не пересоздаёт ObservableCollection. Таблица: IP/роль/MAC/hostname/latency/state/LastSeen/FirstSeen; карточки сети/счётчики, поиск IP/MAC/hostname, filters и числовой IP/latency/LastSeen sort. Пояснения Online/Unknown/Offline доступны при наведении; шлюз и «Этот ПК» явно помечены. Интерфейс/интервал блокируются во время мониторинга.

### Проверки и ограничения

- Baseline перед изменениями: Release 0 warnings/errors, 155 passed, 1 hardware skipped.
- Итог: restore с locked dependencies; Release build 0 warnings/errors; 250 passed, 0 failed, 2 skipped; self-contained Windows x64 publish. Тестовые исходники/зависимости и GUI preview находятся вне репозитория.
- Новые проверки: IPv4 /24,/30,/29,/22,/31,/32,/0; маска/границы/count/guard; hysteresis/FirstSeen/LastSeen/MAC-first/IP fallback/context reset; Ping/Neighbor merge, stale cache, route skip, errors, DNS timeout, ограниченный probe/DNS parallelism, cancellation; scan/delay loop/manual overlap/context disappearance/subscriber isolation; ABI/padding/endian parsing; карточки/table/search/filter/sort/row identity/cancel/shutdown/selection/errors. Прежние проверки этапов 1–3 проходят.
- Linux GUI: production startup/DI, сообщение UnsupportedPlatform, навигация и корректное закрытие. Отдельный локальный стенд с фальшивыми сетевыми зависимостями: заполненная таблица, роли, 3 состояния, фильтр Online, Start/Stop Monitoring, сохранение данных после Stop, навигация при работающем мониторинге и shutdown. Демонстрационные данные не включены в production.
- Два integration skip требуют Windows: настоящий WLAN scan и чтение Windows neighbor table. Настоящие ПК/роутер/телефон, USB-adapter unplug/recovery и ограничения драйверов/политик в этой Linux-среде не проверены.
- Client/AP Isolation, guest VLAN, сон, ICMP filtering и кэш соседей могут скрывать узлы. Это список локальной IP-сети, не AP association table. MAC может быть приватным; vendor/владелец не определяются. DNS использует серверы ОС, cloud/MAC lookup API отсутствуют. Port/service scan, packet capture и SQLite history не добавлялись.

API сверены с [документацией GetIpNetTable2/FreeMibTable](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipnettable2) и [состояний MIB_IPNET_ROW2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipnet_row2); ABI также проверен локальными тестами layout.

## Device Identity — расширение Milestone 4

Функционал включён в [Version 5 (5.0.0)](https://github.com/KirillBass/WIFI_Scanner/releases/tag/v5.0.0). Это расширение реализованных Milestones 1–4; номер релиза не обозначает отдельный Milestone 5.

Поверх существующего обнаружения добавлено асинхронное определение hostname/friendly name/vendor/model/type и источников отдельных полей. До окончания identity строка уже доступна; LastSeen/state по имени не обновляются. Resolver-ы: LocalComputer, Reverse DNS только к DNS выбранной подсети с RD=0, mDNS/DNS-SD network cycle, NBSTAT UDP 137, LLMNR reverse PTR TCP 5355, SSDP/UPnP read-only и embedded OUI MA-L/MA-M/MA-S.

Cache 15 минут, MAC-first/IP fallback и scope сети, controlled concurrency, cancellation/Stop/shutdown, source priority, private-MAC detection, таблица vendor/display/tooltip реализованы. Низкоуровневый discovery и функции этапов 1–4 сохранены; новых NuGet-пакетов нет. Restore/build/publish успешны, Release 0 warnings/errors; локально 333 passed, 0 failed, 2 Windows hardware skipped. Production startup/DI и отдельный GUI preview проверены. Прежние описания системного DNS/5-минутного hostname cache выше относятся к исходному Milestone 4; актуальный путь описан в [техническом отчёте](DEVICE_IDENTITY_REPORT.md), содержащем все 14 пунктов ТЗ и итоговые проверки.

## «Эфир»: Vendor / Wi-Fi Standard / Security

Текущие исходники дополняют прежние BSS локальными метаданными: общий embedded OUI resolver для BSSID; Native PHY + безопасный TLV parser HT/VHT/HE/EHT; RSN/WPA suites для Open/WEP/WPA/WPA2/WPA3/transition и OWE. Protocol, authentication, pairwise/group cipher, PMF и источник хранятся раздельно. Неподтверждённые поля остаются Unknown; приватный BSSID не проходит OUI lookup. WEP требует однозначного подтверждения Windows network list, Privacy bit сам по себе недостаточен.

«Эфир» содержит 10 читаемых колонок с горизонтальной прокруткой, security tooltip и деталями выбранной AP. Повторный snapshot обновляет ту же строку и её детали. Scan loop, RSSI monitoring, модель 20-МГц Channel Analyzer, Device Discovery/Identity и NuGet dependencies сохранены. Данные/unsafe pointers не передаются за пределы native lifetime; новых внешних web API нет.

Restore/build/test успешны; Release 0 ошибок/предупреждений; 447 passed, 0 failed, 2 Windows hardware skipped. Добавлено 114 локальных проверок, тестовые файлы остаются вне repository. GUI проверен на Linux с отдельным локальным preview; настоящий WLAN scan/6-GHz радиоэфир требуют Windows. Подробный отчёт из 15 пунктов — [AIR_CAPABILITIES_REPORT.md](AIR_CAPABILITIES_REPORT.md). Функционал включён в [Version 6 (6.0.0)](https://github.com/KirillBass/WIFI_Scanner/releases/tag/v6.0.0); релиз содержит self-contained Windows x64 архив и SHA-256.

## Оставшиеся этапы

1. Аппаратная проверка четырёх реализованных этапов на Windows с Wi-Fi/Ethernet адаптером, включая настоящее обнаружение телефона/роутера и исчезновение интерфейса.
2. Полный Dashboard, сведения о текущем подключении, итоговая UX-полировка и проверка стабильности Release на Windows.

Discovery реализован в пределах собственной выбранной IPv4-подсети. Порт-сканер, crawler, перехват трафика, анализ контента, базы данных и cloud services не входят в текущую реализацию.
