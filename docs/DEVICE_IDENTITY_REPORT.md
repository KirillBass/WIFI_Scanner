# Device Identity — расширение Milestone 4

ТЗ `WirelessSecurityAnalyzer_DeviceIdentity_Codex.docx` полностью прочитано. Изменения выполнены поверх существующего solution с тремя проектами. WLAN scanner, RSSI, channel analysis, ICMP/neighbor discovery и правила состояний сохранены. Отчёт следует пунктам 1–14 раздела 42 ТЗ.

Функционал подготовлен для [Version 5 (5.0.0)](https://github.com/KirillBass/WIFI_Scanner/releases/tag/v5.0.0). При подготовке релиза `Directory.Build.props` обновлён до 5.0.0, подпись `MainWindow.axaml` показывает версию 5, README содержит ссылку на новый релиз.

1. **Изменённые файлы.** Пути от корня проекта:

   - `src/WirelessSecurityAnalyzer.Core/Models/NetworkDevice.cs`: immutable identity, display/friendly/vendor/model/source/update и состояние обогащения.
   - `src/WirelessSecurityAnalyzer.Core/Models/DeviceDiscoveryResult.cs`: признак фонового enrichment в snapshot.
   - `src/WirelessSecurityAnalyzer.Core/Network/DeviceStateTracker.cs`: сохранение identity между циклами/DHCP, merge без изменения LastSeen/FirstSeen/evidence/state, защита от ответа для заменённого устройства.
   - `src/WirelessSecurityAnalyzer.Infrastructure.Windows/Network/DeviceMonitorService.cs`: отдельная отменяемая enrichment task после публикации discovery; Stop/shutdown ожидают её завершения.
   - `src/WirelessSecurityAnalyzer.Infrastructure.Windows/Network/HostnameResolver.cs`: существующий resolver переиспользован; PTR направляется только к локальным DNS выбранного интерфейса, короткий timeout, RD=0, раннее завершение по ответу.
   - `src/WirelessSecurityAnalyzer.Infrastructure.Windows/WirelessSecurityAnalyzer.Infrastructure.Windows.csproj`: embedded OUI resource.
   - `src/WirelessSecurityAnalyzer.App/App.axaml.cs`: DI resolver-ов/cache/transport; production `ResolveHostnames=false` исключает старую блокирующую DNS-фазу discovery.
   - `src/WirelessSecurityAnalyzer.App/ViewModels/DeviceRowViewModel.cs`: display name/vendor/private MAC и подробная подсказка.
   - `src/WirelessSecurityAnalyzer.App/ViewModels/DevicesViewModel.cs`: состояние enrichment, Stop, поиск friendly/vendor, сохранение строк и UI Dispatcher.
   - `src/WirelessSecurityAnalyzer.App/Views/DevicesView.axaml`: имя/производитель, tooltip, фоновый индикатор, видимая горизонтальная прокрутка.
   - `README.md`, `docs/IMPLEMENTATION_STATUS.md`: актуальное поведение и ограничения.
   - Учебный `РАЗБОР_ПРОЕКТА_ЛОКАЛЬНО.md` дополнен локально; он исключён из Git и не публикуется.

2. **Добавленные production-файлы.** В Core:

   - `Models/DeviceIdentity.cs`: identity, DeviceNameSource, DeviceVendorSource, IdentificationConfidence и источники отдельных metadata fields.
   - `Interfaces/IDeviceIdentityResolver.cs`: агрегатор, per-host/network resolver contracts, DeviceIdentityUpdate.
   - `Network/DeviceIdentityMerger.cs`: независимый приоритет каждого поля, сохранение предыдущих данных.
   - `Network/MacAddressHelper.cs`: local bit.

   В `Infrastructure.Windows/Network/Identity/`:

   - `DeviceIdentityOptions.cs`, `DeviceIdentityCache.cs`, `DeviceIdentityResolver.cs`.
   - `LocalComputerNameResolver.cs`, `ReverseDnsNameResolver.cs`, `MdnsNameResolver.cs`, `NetBiosNameResolver.cs`, `LlmnrNameResolver.cs`, `SsdpDeviceResolver.cs`, `MacVendorResolver.cs`.
   - `IdentityDatagramClient.cs`, `DnsPacket.cs`, `UpnpDescriptionClient.cs`.
   - `Data/oui.tsv`, `Data/README.md`.

   Добавлен данный `docs/DEVICE_IDENTITY_REPORT.md`. Новых проектов и NuGet-пакетов нет. Шесть файлов тестов находятся в частном каталоге локального тестирования вне репозитория.

3. **Методы идентификации.** LocalComputer, Reverse DNS, mDNS/DNS-SD, NetBIOS NBSTAT, LLMNR PTR, SSDP/UPnP и OUI. Все сетевые методы читают сведения уже найденных устройств; новых устройств по identity alone не создают. Собственный ПК получает Environment.MachineName без сетевого запроса. Используются стандартные .NET NetworkInterface/UdpClient/TcpClient/Socket/HttpClient/XML API; UI не вызывается из resolver-ов.

4. **Приоритеты.** DisplayName: FriendlyName → Hostname → «—», без vendor fallback. Hostname: LocalComputer → mDNS → Reverse DNS → NetBIOS → LLMNR. FriendlyName: SSDP → опубликованный DNS-SD instance/TXT. Vendor: UPnP manufacturer → OUI. ModelName, ModelDescription и DeviceType объединяются независимо: SSDP → явное mDNS metadata; у каждого сохраняется фактический источник. Пустое/менее приоритетное значение не стирает найденное. Например, SSDP «Living room TV» и PTR «android-123456» сосуществуют. Vendor не создаёт модель или тип. Confidence показывает качество источника, а не криптографическую аутентификацию устройства.

5. **mDNS.** Один network-wide cycle через `224.0.0.251:5353`; source socket привязан к выбранному IPv4 и Windows interface index. Используется one-shot legacy-unicast режим с ephemeral port, без занятого Bonjour port 5353. Questions сгруппированы по 16: DNS-SD PTR известных типов и reverse PTR уже найденных IP. Ответы A/PTR/SRV/TXT индексируются и сопоставляются только с найденными IP. ID проверяется; TTL=0 удаляет record внутри цикла. При отсутствующих дополнительных данных выполняется bounded follow-up, максимум 64 questions. DNS codec проверяет границы, RDATA, длину labels/names, compression loops, число records и TXT/SRV encoding. Исходный `.local` сохраняется. Никаких responder/spoof/capture функций.

6. **SSDP/UPnP.** Один M-SEARCH для root devices к `239.255.255.250:1900`, MX=1, окно 2 секунды. LOCATION deduplicated, максимум 64 description URL и 4 параллельных чтения. Ответ должен принадлежать найденному IP. URL только HTTP/HTTPS с literal IPv4 этого ответившего устройства, без credentials/fragment. Socket привязан к выбранному интерфейсу; TTL=1, destination фиксируется без DNS lookup. Proxy/cookies/redirect выключены; HTTP timeout 1 секунда, headers максимум 16 КБ, тело максимум 512 КБ даже без Content-Length. XML parser запрещает DTD/внешние entities и ограничивает документ; извлекается только root device friendlyName/manufacturer/modelName/modelDescription/deviceType. Control/icon/presentation URL не открываются; UPnP actions не выполняются.

7. **Vendor.** Local OUI snapshot содержит 58 242 префикса MA-L/MA-M/MA-S длиной 24/28/36 бит; longest-prefix match. База встроена в DLL, интернет в runtime не нужен. Первичный реестр — IEEE, публичный снимок получен из Wireshark, поскольку прямой сервер IEEE вернул HTTP 418. Источник, дата получения, provenance и SHA-256 записаны в `Data/README.md`. `04:EC:D8` в снимке — Intel Corporate, `10:A3:B8` — Iskratel d.o.o.; учебные примеры ТЗ не подменяют данные. Явный UPnP manufacturer имеет приоритет над OUI; OUI часто указывает изготовителя NIC, а не готового изделия.

8. **Private MAC.** `MacAddressHelper.IsLocallyAdministered` проверяет `bytes[0] & 0x02` для шестибайтного адреса. При local bit OUI не используется; UI показывает «Приватный / случайный MAC», если нет явного manufacturer. Достоверно опубликованный UPnP manufacturer допустим и для такого MAC. Private MAC не означает установленный факт рандомизации: это локальное назначение адреса.

9. **Cache.** Process-local TTL 15 минут, максимум 4096 записей с вытеснением по expiry. Контекст: interface ID/index + network/prefix + gateway. Ключ устройства — валидный MAC, иначе IP. Тот же MAC после DHCP-смены IP получает прежний identity; другая сеть/другой MAC на том же IP cache не наследуют. Cache hit не вызывает resolver-ы; после TTL разрешено обновление. Пустой завершённый результат также кэшируется, чтобы не повторять запросы каждые 30 секунд. Нулевой ответ не стирает историю. Незавершённое отменённое разрешение не кэшируется; завершённые устройства большого batch сохраняются отдельно после окончания сетевых методов, чтобы следующий цикл продолжал обработку оставшихся адресов.

10. **Задержка discovery и monitoring.** Сам WindowsDeviceDiscoveryService не переписан; в production отключена его необязательная blocking hostname phase. Monitor сначала публикует IP/MAC/latency/state/history, затем Task.Run запускает агрегатор. До 4 per-host name operations и 4 UPnP HTTP reads одновременно; mDNS/SSDP по одному циклу на сеть. Имя обновляет прежний row на UI Dispatcher, без изменения LastSeen или presence. Delay monitoring не ждёт identity; следующий завершённый discovery отменяет прежний незавершённый batch и запускает обработку новых/cache-expired устройств. Stop/context switch/shutdown отменяют и ожидают задачи; late callbacks отклоняются. Независимого бесконечного name-resolution loop нет.

11. **Restore/build.** Выполнены `dotnet restore WirelessSecurityAnalyzer.sln --locked-mode` и `dotnet build WirelessSecurityAnalyzer.sln -c Release --no-restore`; успешно, 0 warnings и 0 errors. `dotnet publish src/WirelessSecurityAnalyzer.App -c Release -p:PublishProfile=WindowsX64` успешно создал self-contained Windows x64 приложение в `publish/win-x64/`. Локальный архив `publish/WirelessSecurityAnalyzer-win-x64.zip` пересобран с новыми исходниками; CRC и отсутствие тестовых/учебных файлов проверены, SHA-256 сохранён рядом. Пакеты и lock files сохранены; версия приложения для релиза — 5.0.0.

12. **Test.** Выполнен `dotnet test WirelessSecurityAnalyzer.sln -c Release --no-build --no-restore`. В публичном solution нет тестовых проектов согласно прежнему пожеланию пользователя, поэтому фактический набор выполняется отдельным `dotnet test` приватного local-tests solution. Проверяются display priority, private bit, OUI MA-L/M/S, source merge, cache TTL/DHCP/context/cancel, bounded concurrency, malformed DNS/mDNS/NBSTAT/LLMNR/SSDP/XML, URL validation/redirect/response limits, discovery-before-enrichment, row identity, search, Stop/shutdown, monitoring cadence и регрессия Milestones 1–4. Сетевые HTTP/UDP fixtures обращаются только к серверу на собственном IP процесса; при отсутствии пригодного IPv4 они отдельно пропускаются. Hardware tests WLAN/IP Helper отделены и требуют Windows. Итог: **333 passed, 0 failed, 2 skipped** (Core 147; Windows/GUI 186 + 2 hardware skips). По сравнению с baseline 250 passed добавлено 83 проверки; весь прежний набор проходит.

13. **Ручная проверка.** Production Avalonia приложение запускается на Linux с рабочими DI-регистрациями; страница устройств корректно объясняет UnsupportedPlatform. В отдельном локальном GUI preview с fake dependencies проверены заполнение таблицы до enrichment, friendly/hostname/vendor/private MAC, фактическое открытие подробной tooltip, горизонтальная прокрутка, Stop, Start monitoring и сохранение данных. При Stop индикатор пропадает, найденные сведения остаются; неизвестное имя после завершения отображается «—». Fixtures/screenshots/tests в публикуемый проект не входят. ПК+телефон+роутер/TV в настоящей Windows LAN из этой Linux-среды не проверены; автоматические fixtures не выдаются за аппаратное подтверждение.

14. **Ограничения.** Только выбранная IPv4-сеть. Private/rotating MAC не даёт устойчивой идентичности между разными адресами. Нет гарантии имени: sleep/isolation/firewall/disabled protocols/устройство без опубликованных сведений дают «—». mDNS legacy-unicast и multi-question ответы поддерживаются не всеми устройствами; DNS-SD service list ограничен и не является сканером служб. LLMNR reverse использует TCP 5355 по RFC 4795, а не недопустимый unicast UDP. Public/VPN/off-subnet DNS пропускается, рекурсивный поиск не запрашивается; пересылку локальным DNS-сервером вопреки RD=0 приложение контролировать не может. PTR CNAME chains/UDP truncation TCP fallback не реализованы. LOCATION hostname URL и HTTPS с недоверенным сертификатом пропускаются; embedded UPnP devices отдельно не идентифицируются. OUI — локальный snapshot без автообновления. Последний хороший identity сохраняется в истории с timestamp; TTL запускает повторную попытку, но сам по себе не доказывает, что старое имя неверно. Отдельная selected-device panel заменена подробным tooltip. Нет external web API, telemetry, port/service scanner, SMB/Nmap/capture/poisoning/UPnP control.

Источники протоколов: [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762), [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763), [RFC 4795 §2.4](https://www.rfc-editor.org/rfc/rfc4795), [RFC 1002](https://www.rfc-editor.org/rfc/rfc1002), [UPnP Device Architecture 2.0](https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v2.0.pdf), [Microsoft IP_UNICAST_IF](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options).
