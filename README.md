# PacketSniffer

<img width="1888" height="1009" alt="изображение" src="https://github.com/user-attachments/assets/2ece927f-fcdf-4a6a-8657-e5bb272d1545" />


Лёгкий сниффер сетевых пакетов на C++ с Qt GUI и libpcap.

## Возможности
- Захват пакетов с выбранного интерфейса (libpcap)
- Графический интерфейс на Qt5/Qt6 Widgets
- Отображение базовой информации о пакетах

## Зависимости
- CMake ≥ 3.15
- Компилятор C++17 (GCC/Clang)
- libpcap (headers + runtime)
- Qt6 Widgets (или Qt5 Widgets, если Qt6 не найден)

Установка зависимостей (Ubuntu/Debian):
```bash
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev qtbase5-dev qt6-base-dev
```

## Сборка
Стандартная out-of-source сборка CMake.
```bash
# Вариант Qt GUI (по умолчанию включён)
cmake -S . -B build_qt -DUSE_QT_GUI=ON
cmake --build build_qt --config Release -j

# CLI/Web вариант (если предусмотрен кодом)
# cmake -S . -B build -DUSE_QT_GUI=OFF
# cmake --build build --config Release -j
```

После сборки бинарь будет в `build_qt/PacketSniffer`.

## Запуск (рекомендуемо)
Для захвата пакетов нужны сетевые привилегии. Есть два безопасных варианта:

1) Выдать capabilities бинарю (без sudo при каждом запуске):
```bash
# Скопировать в системный путь
sudo cp build_qt/PacketSniffer /usr/local/bin/PacketSniffer_qt
sudo chmod 755 /usr/local/bin/PacketSniffer_qt
# Выдать нужные права
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/PacketSniffer_qt
# Проверить
getcap /usr/local/bin/PacketSniffer_qt
# Запуск
/usr/local/bin/PacketSniffer_qt
```

2) Запустить под sudo (менее удобно):
```bash
sudo ./build_qt/PacketSniffer
```

Важно: не используйте `/tmp` для бинаря с capabilities — часто `/tmp` смонтирован с `nosuid`, и kernel проигнорирует file capabilities.
Проверьте:
```bash
findmnt /tmp -o TARGET,OPTIONS | sed -n '2p'
```
Если виден `nosuid`, перенесите бинарь в путь без этой опции (например, `/usr/local/bin`).

## Быстрый ответ на вопрос «чем запускать?»
- Если уже делали шаги выше: `/usr/local/bin/PacketSniffer_qt`
- Из каталога сборки (требует sudo либо capabilities): `./build_qt/PacketSniffer`

## Разработка
Пересборка после правок:
```bash
cmake --build build_qt -j
```
Если вы заменили бинарь в `/usr/local/bin`, заново выдайте capabilities:
```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/PacketSniffer_qt
```

## Отладка проблем с правами
- Ошибка: `pcap_open_live failed: <iface>: You don't have permission ... (socket: Operation not permitted)`
  - Убедитесь, что бинарь запущен с sudo или имеет capabilities: `getcap /usr/local/bin/PacketSniffer_qt`
  - Избегайте запуска бинаря из `/tmp` при `nosuid`
  - Проверьте, что интерфейс существует: `ip link`

## Лицензия
MIT

Автор: t.me/BengaminButton
