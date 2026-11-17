# Milestone 5 - подключение к Wi-Fi и Network Session

Дата реализации: 14 октября 2026 года. Расширен существующий solution; оформление Light_Interface и ранее выполненный рефакторинг сохранены. Новые NuGet-пакеты не добавлены. Функционал включён в [Version 7](https://github.com/KirillBass/WIFI_Scanner/releases/tag/v7.0.0), подготовленный 14 октября 2026 года. Архив Light_Interface относится к предыдущей версии.

## 1. Новые и изменённые файлы

Новые файлы относительно состояния проекта перед данным этапом:

| Слой | Файлы | Назначение |
| --- | --- | --- |
| Core/Interfaces | `IWifiConnectionService.cs`, `INetworkSessionService.cs` | Асинхронные операции подключения и общий контекст сети |
| Core/Models | `WifiConnection.cs`, `NetworkSession.cs` | Запрос, результат, состояния/ошибки, фактическое соединение, immutable сессия |
| Core/Network | `NetworkSessionService.cs`, `WifiConnectionPolicy.cs` | Версии/границы сессии, поддерживаемые типы защиты и сообщения |
| Infrastructure.Windows/Wifi | `WifiProfileBuilder.cs`, `WifiConnectionOptions.cs`, `IWifiConnectionBackend.cs`, `NativeWifiConnectionBackend.cs`, `WindowsWifiConnectionService.cs` | XML, тайм-ауты/координатор, подменяемая граница Windows API и orchestration |
| Infrastructure.Windows/NativeWifi | `NativeWifiConnection.cs`, `WlanConnectionStructs.cs` | Partial существующего NativeWifiClient, ожидание уведомлений, ABI |
| App/ViewModels | `NetworkSessionViewModel.cs`, `WifiConnectionDialogViewModel.cs`, `NetworkAuditViewModel.cs` | Общая UI-проекция, модальный диалог, контекст аудита |
| App/Views | `WifiConnectionDialog.axaml` и `.axaml.cs`, `NetworkAuditView.axaml` и `.axaml.cs` | Диалог и страница аудита |
| docs | `WIFI_CONNECTION_REPORT.md` | Этот отчёт |

Изменены существующие файлы:

- `Core/Models/WifiAccessPoint.cs`, `NativeWifi/BssMapper.cs`: сохранение исходных байтов SSID.
- `NativeWifi/NativeWifiClient.cs`, `NativeWifiMethods.cs`: общая безопасная регистрация callback, dispatch connection notifications, P/Invoke Connect/Disconnect/QueryInterface. Прежний путь сканирования сохранён.
- `Wifi/WindowsWifiScanner.cs`: общий gate со службой подключения, исключающий одновременные WLAN scan/connect операции.
- `Core/Interfaces/IDeviceMonitorService.cs`, `Core/Network/DeviceStateTracker.cs`, `Network/DeviceMonitorService.cs`: ResetAsync останавливает discovery/enrichment и очищает историю, сохраняя монотонную версию snapshot.
- `Network/Identity/DeviceIdentityCache.cs`: явная очистка при смене сессии.
- `App.axaml`, `App.axaml.cs`: шаблон страницы и singleton-регистрации DI.
- `AccessPointsViewModel.cs`, `AccessPointsView.axaml`: выбор сети, доступность кнопки подключения и объяснение неподдерживаемой защиты.
- `NetworkSessionViewModel.cs`, `MainWindow.axaml`: общий сетевой контекст и строка состояния. Вкладка «Главная» удалена; отключение Wi-Fi перенесено в «Эфир».
- `DevicesViewModel.cs`: выбор сети общей сессии, очистка прежних строк, блокировка discovery до IPv4.
- `MainWindowViewModel.cs`, `MainWindow.axaml`, `MainWindow.axaml.cs`: седьмая вкладка, постоянный статус, модальный диалог, переход после Ready, асинхронный shutdown.
- `README.md`, `docs/IMPLEMENTATION_STATUS.md`: использование и статус реализации.

Ранее выполненные изменения общих ViewModel, графиков и укрупнение небольших моделей сохранены.

## 2. WlanConnect flow

```mermaid
flowchart TD
    A[Эфир: выбранная строка BSS] --> B[Модальный диалог: адаптер и известный пароль]
    B --> C[Проверка SSID, защиты и пароля]
    C --> D[Новая SessionId; остановка прежнего мониторинга]
    D --> E[Временный XML-профиль в памяти]
    E --> F[Регистрация уведомлений; WlanConnect]
    F --> G[connection_complete: результат Windows]
    G --> H[Фактический SSID/BSSID; ожидание IPv4]
    H --> I{Получен пригодный IPv4?}
    I -->|Да| J[Session Ready; Сетевой аудит]
    I -->|Нет, истёк тайм-аут| K[Подключено, ожидание IP; аудит недоступен]
    K -->|Адрес появился позже| J
```

Сервис проверяет запрос до изменения сессии и до обращения к WLAN. Локальный gate отклоняет повторное Connect/Disconnect; общий координатор сериализует сканер и connector. Подключение выполняется к SSID, без обязательного desired-BSSID: Windows вправе выбрать другую BSS этого SSID. В сессию записывается фактический BSSID из WlanQueryInterface. Нативные вызовы выполняются вне UI-потока.

Возврат WlanConnect означает запуск операции, окончание определяется уведомлением. Это соответствует [документации WlanConnect](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanconnect).

## 3. Профили Open и WPA2-Personal

`WifiProfileBuilder` использует XElement и namespace WLAN profile v1. Профили имеют случайное несекретное имя, тип ESS и ручное подключение. SSID кодируется исходными байтами в hex; строковое имя добавляется только при допустимых XML-символах. Спецсимволы экранируются средствами XML-библиотеки.

Open: authentication=open, encryption=none, useOneX=false, sharedKey отсутствует. WPA2-Personal: WPA2PSK/AES, useOneX=false, sharedKey с passPhrase либо networkKey. Поддерживается 8–63 печатных ASCII-символа или PSK из 64 hex-символов. Unicode SSID допускается; Unicode passphrase отклоняется с объяснением, поскольку Windows profile schema ограничивает WPA/WPA2 passphrase ASCII. См. [sharedKey в схеме Windows](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wlan-profileschema-sharedkey-security-element).

Проверка WPA2-Personal требует CCMP в списке Pairwise и допускает групповой CCMP либо TKIP. Вариант `Pairwise: TKIP, CCMP; Group: TKIP` разрешён: XML по-прежнему запрашивает WPA2PSK/AES, автоматического fallback на TKIP для клиента нет. Групповой шифр отображается отдельно и не выдаётся за AES. Пара authentication/encryption задаётся по [схеме authEncryption Windows](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wlan-profileschema-authencryption-security-element).

В WlanConnect передаётся `wlan_connection_mode_temporary_profile`. WlanSetProfile/сохранение профиля/удаление пользовательских профилей не используются.

## 4. Защита пароля

Пароль отображается маской; поле очищается сразу при запуске операции и повторно в finally/при закрытии. Запрос - обычный класс с безопасным ToString, без генерируемого record-ToString с полем Password. Credentials исключены из NetworkSession, результатов, конфигурации и сообщений исключений. Сервис пишет только тип ошибки и код, без объекта исходного исключения или XML.

XML живёт только при запуске нативного подключения; ссылки освобождаются в finally. Неуправляемая Unicode-копия обнуляется через ZeroFreeGlobalAllocUnicode. Строки .NET неизменяемы: гарантированное обнуление всех управляемых копий/внутренних буферов Windows не обещается. Приложение минимизирует время их жизни и не сохраняет пароль на диск.

## 5. Native Wi-Fi notifications

Callback удерживается полем NativeWifiClient до снятия регистрации и закрытия handle. Проверяются source ACM, interface GUID, размер фиксированного заголовка, SSID и имя временного профиля. Хвост notification с XML не читается и не журналируется.

- connection_start: состояние Authenticating.
- connection_attempt_fail: сохраняется reason code; это промежуточная попытка, Task не завершается.
- connection_complete: reason=0 означает успех, иначе возвращается типизированная ошибка. Ранее полученный код аутентификации сохраняется, если финальный код сообщает отсутствие доступной сети.
- interface_removal: понятная ошибка отсутствующего/отключённого адаптера.
- network_not_available: сеть недоступна на данном интерфейсе.
- disconnected: завершает ожидающий Disconnect.

Ожидание основано на TaskCompletionSource и WaitAsync с отменой/тайм-аутом; фиксированной задержки для угадывания association нет. Промежуточные попытки и финальное уведомление различаются согласно [описанию WLAN notifications](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms706902(v=vs.85)).

## 6. Ожидание DHCP/IPv4

После association состояние ObtainingAddress. Используется прежний ILocalNetworkService / WindowsLocalNetworkService: выбирается пригодный IPv4 именно Wi-Fi интерфейса подключения по GUID. Маска/подсеть вычисляются прежним SubnetCalculator; APIPA, loopback и невалидные адреса прежним сервисом отфильтровываются. Отсутствующий шлюз допустим для локальной сети и показывается как «-»; интернет-доступ не проверяется.

Параметры WifiConnectionOptions: association 25 секунд, IPv4 18 секунд, Disconnect 8 секунд, опрос адреса 500 мс. Отдельный связанный CancellationToken ограничивает также ожидающие сетевые операции. При истечении IPv4-тайм-аута Wi-Fi остаётся подключённым, Ready=false. Фоновое обновление сессии раз в 2 секунды замечает адрес, появившийся позднее. Пока диалог открыт и принадлежит этому соединению, Ready закрывает его и открывает аудит.

## 7. NetworkSessionService

Singleton в DI - единственный источник текущего SSID/BSSID/интерфейса/IPv4/префикса/подсети/шлюза/защиты/ConnectedAt. Immutable snapshot имеет SessionId и возрастающую Version; UI читает одну NetworkSessionViewModel, обновляемую через Avalonia Dispatcher. Старые версии и результаты с чужим expectedSessionId игнорируются.

Новая попытка подключения создаёт новый SessionId. Изменение SSID, GUID интерфейса, IPv4/префикса/шлюза либо потеря адреса также меняют контекст. Другая сеть с тем же IPv4/подсетью различается по SSID и новой сессии. Роуминг между BSSID одного SSID при сохранённом сетевом контексте обновляет BSSID без сброса истории. При смене сети служба сначала останавливает signal/device monitoring и identity worker, очищает DeviceStateTracker и DeviceIdentityCache. Это исключает повторное использование прежних имён и устройств в новой сети.

При старте читается уже установленное соединение Windows; последующее внешнее переключение/исчезновение сети обнаруживается опросом с интервалом 2 секунды. Быстрое отключение и повторное подключение между двумя опросами может остаться незамеченным. Приложение не трактует неизвестные сведения о group cipher/PMF как подтверждённые; выбранная защита BSS и фактически известные Windows параметры различаются.

## 8. Навигация после подключения

В «Эфире» кнопка доступна для выбранной поддерживаемой сети; Enterprise и другие неподдерживаемые типы имеют пояснение. Модальный Window используется только для подключения; основное приложение остаётся одним окном.

После успешного результата Ready диалог закрывается и MainWindowViewModel выбирает «Сетевой аудит». До IPv4 автоматического перехода нет. Там показаны сетевой контекст, счётчик текущих устройств и кнопки обновления/отключения. «Устройства» остаётся доступной отдельной вкладкой и использует прежнее обнаружение. Сохранены светлое оформление и вкладки сверху; постоянный статус размещён в нижней строке вместо sidebar из более раннего макета ТЗ.

## 9. Disconnect и shutdown

Disconnect переводит сессию в Disconnecting, останавливает операции и вызывает WlanDisconnect. Уведомление disconnected подтверждает завершение; при тайм-ауте дополнительно проверяется фактическое отсутствие association. Сессия, список устройств и identity cache очищаются. Постоянные Windows-профили пользователя не удаляются.

Отмена pending association вызывает best-effort WlanDisconnect. Отмена пользователем во время ожидания IPv4 также отключает уже установленное соединение. При shutdown pending tasks/мониторинг отменяются и ожидаются; соединение, уже успешно установленное к этому моменту, автоматически не отключается. После завершения задач DI освобождает нативный handle и callback.

## 10. Ограничения типов сетей и этапа

Подключаются Open и WPA2-Personal AES/CCMP. Пока не подключаются WPA3-SAE, WPA2/WPA3 transition, WPA-Personal, WPA/TKIP, WEP, OWE, Enterprise/802.1X/EAP, ad-hoc и скрытые SSID без известного имени. Отображение прежних метаданных этих сетей в «Эфире» сохранено. Unicode WPA2 passphrase отклоняется согласно схеме Windows; Unicode SSID поддерживается.

IPv6-аудит, captive portal, сохранение credentials, pinning к BSSID, port/service scan, Nmap/pcap/monitor mode и изменения параметров роутера не добавлялись. DNS/identity/discovery используют ранее существующие локальные методы.
