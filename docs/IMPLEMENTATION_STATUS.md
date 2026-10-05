# Состояние реализации

Исходное ТЗ: `WirelessSecurityAnalyzer_Codex_TZ.docx`, предоставленное пользователем. Работа ведётся последовательно по milestone; аппаратная проверка первого этапа является условием перехода к мониторингу.

## Первый этап — код реализован, аппаратная проверка ожидается

- Создан `WirelessSecurityAnalyzer.sln` с тремя проектами приложения. Тестирование ведётся локально, результаты сообщаются в чате.
- Core: immutable модели WifiAccessPoint и WifiAdapter, WifiBand, интерфейсы сканера/адаптеров, структурированные ошибки, преобразование частот и каналов.
- Infrastructure.Windows: P/Invoke WLAN API, ABI-структуры, SafeHandle, освобождение native memory, callback с удержанием delegate, TaskCompletionSource, отмена и тайм-аут.
- WindowsWifiScanner: реальные BSS, несколько адаптеров, объединение по BSSID, последовательное выполнение сканирований, локальное логирование.
- App: Avalonia 12.1.3, MVVM на CommunityToolkit, DI, русскоязычная тёмная тема, sidebar, шесть страниц навигации, ручной scan, TableView, индикатор RSSI, поиск/фильтры/сортировка, отмена, loading/empty/error states и переход к Location settings.
- README и профиль self-contained Windows x64.

Профиль публикации собирает self-contained приложение Windows x64 с включённым .NET Runtime. Папка публикации — `publish/win-x64/`; архив для переноса — `publish/WirelessSecurityAnalyzer-win-x64.zip`.

Реальную работу `wlanapi.dll`, запуск Windows `.exe`, соответствие результатов реальной Wi-Fi среде и поведение конкретных драйверов нужно проверить на Windows, прежде чем объявлять первый milestone полностью завершённым.

## Оставшиеся этапы

1. После аппаратной проверки: IWifiMonitorService, конфигурируемый интервал около 5 секунд, ограниченная история 300 samples на BSSID, статистика RSSI и SignalView со ScottPlot.
2. RSSI-weighted ChannelAnalyzer, оценочная модель перекрытия, рекомендации по диапазонам, unit tests и экран «Каналы».
3. Устройства собственной локальной IP-сети: Wi-Fi IPv4 interface, subnet/gateway, ограниченный discovery до 1024 адресов, соседняя таблица через IP Helper API, контролируемый параллелизм и отмена.
4. Полный Dashboard, сведения о текущем подключении, итоговая UX-полировка и проверка стабильности Release на Windows.

Реализация графиков, monitoring, алгоритма оценки каналов и discovery пока отсутствует. Их страницы явно обозначают этот статус. Не реализованы порт-сканер, crawler, перехват трафика, анализ контента, базы данных или cloud services.
