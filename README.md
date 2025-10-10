# CrabSock VPN Client

VPN клиент с поддержкой TUN Mode для маршрутизации всего трафика через VPN.

## Возможности

- Подключение к VPN через SOCKS5 прокси
- TUN Mode для маршрутизации всего системного трафика
- Сохранение конфигураций
- Системный прокси
- Автозапуск

## Установка и запуск

### Development версия

```bash
cd /home/victor/PhpstormProjects/have-fun/CrabSock/ui
env GDK_BACKEND=x11 DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY WEBKIT_DISABLE_COMPOSITING_MODE=1 WEBKIT_DISABLE_SANDBOX=1 npm run tauri:dev
```

### Release версия (для TUN Mode)

1. Соберите release версию:
```bash
cd /home/victor/PhpstormProjects/have-fun/CrabSock/ui
npm run tauri:build
```

2. Установите capability для TUN Mode:
```bash
./set_capability.sh
```

3. Запустите release версию:
```bash
env GDK_BACKEND=x11 DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY WEBKIT_DISABLE_COMPOSITING_MODE=1 WEBKIT_DISABLE_SANDBOX=1 ./src-tauri/target/release/crab-sock
```

## TUN Mode

TUN Mode создает виртуальный сетевой интерфейс для улучшенной работы с прокси. В текущей реализации:

- Создается TUN интерфейс для мониторинга сетевого трафика
- Используется системный прокси для маршрутизации трафика
- Обеспечивает лучшую совместимость с различными приложениями
- Не блокирует интернет-соединение

### Требования для TUN Mode

- Linux система
- Права администратора (sudo)
- Capability `cap_net_admin`

### Использование TUN Mode

1. Подключитесь к VPN
2. Включите "TUN Mode" в настройках
3. При первом использовании приложение запросит права администратора
4. После предоставления прав будет собрана release версия
5. Запустите release версию для использования TUN Mode

## Конфигурации

Конфигурации сохраняются в `~/.config/crabsock/configs.json`

## Системный прокси

Включение "System proxy" устанавливает системный прокси на SOCKS5 прокси приложения (127.0.0.1:1080).

## Troubleshooting

### TUN Mode не работает

1. Убедитесь, что запущена release версия, а не development
2. Проверьте, что установлена capability: `getcap ./src-tauri/target/release/crab-sock`
3. Убедитесь, что у вас есть права sudo

### Белый экран после перезапуска

Это известная проблема в development режиме. Используйте release версию для стабильной работы.

### Ошибка "Operation not permitted"

Убедитесь, что:
1. Запущена release версия
2. Установлена capability `cap_net_admin=ep`
3. TUN интерфейс не занят другим процессом