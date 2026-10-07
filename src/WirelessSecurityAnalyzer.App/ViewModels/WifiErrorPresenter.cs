using WirelessSecurityAnalyzer.Core.Common;

namespace WirelessSecurityAnalyzer.App.ViewModels;

internal static class WifiErrorPresenter
{
    internal static string GetMessage(WifiException exception) => exception.Kind switch
    {
        WifiErrorKind.UnsupportedPlatform => "Сканирование Wi-Fi доступно только в Windows 10/11. Эта среда позволяет проверить интерфейс приложения.",
        WifiErrorKind.NoAdapter => "Wi-Fi адаптер не обнаружен. Проверьте подключение адаптера и его драйвер.",
        WifiErrorKind.RadioOff => "Wi-Fi отключён или адаптер не готов. Включите Wi-Fi и отключите режим «В самолёте».",
        WifiErrorKind.ServiceUnavailable => "Служба WLAN AutoConfig недоступна или операция WLAN не поддерживается. Проверьте службу автонастройки WLAN и драйвер адаптера.",
        WifiErrorKind.AccessDenied => "Windows запретила доступ к данным Wi-Fi. Проверьте разрешение определения местоположения и доступ для классических приложений в параметрах конфиденциальности.",
        WifiErrorKind.Timeout => "Адаптер не сообщил о завершении сканирования за 10 секунд. Попробуйте повторить сканирование.",
        WifiErrorKind.InvalidNativeData => "Драйвер вернул некорректные данные Wi-Fi. Попробуйте обновить драйвер адаптера.",
        _ => "Не удалось просканировать эфир. Проверьте состояние Wi-Fi и повторите попытку. Подробности сохранены в локальном журнале."
    };
}
