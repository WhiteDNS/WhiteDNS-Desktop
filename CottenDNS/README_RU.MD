<p align="center">
  <img src="assets/cottendns.png" alt="Логотип CottenDNS" width="150">
</p>

<h1 align="center">CottenDNS</h1>

<p align="center">
  <strong>DNS-туннель с приоритетом скорости для цензурируемых, нестабильных сетей с большими потерями.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img alt="Лицензия MIT" src="https://img.shields.io/badge/license-MIT-16a34a?style=flat-square"></a>
  <a href="https://github.com/TaJirax/cottenDNS/actions/workflows/build-go.yml"><img alt="Сборка" src="https://github.com/TaJirax/cottenDNS/actions/workflows/build-go.yml/badge.svg"></a>
  <a href="https://github.com/TaJirax/cottenDNS/releases/latest"><img alt="Последний выпуск" src="https://img.shields.io/github/v/release/TaJirax/cottenDNS?style=flat-square"></a>
</p>

<p align="center">
  <a href="README.MD">English</a> ·
  <a href="README_FA.MD">فارسی</a> ·
  <a href="README_RU.MD">Русский</a> ·
  <a href="README_ZH.MD">简体中文</a> ·
  <a href="README_ES.MD">Español</a>
</p>

<p align="center">
  <a href="https://github.com/TaJirax/cottenDNS/releases/latest">Скачать</a> ·
  <a href="docs/ENGINEERING_CHANGES.md">Инженерные заметки</a> ·
  <a href="CONFIG_PRESETS.md">Профили</a> ·
  <a href="https://t.me/whitedns">Telegram</a>
</p>

> [!IMPORTANT]
> CottenDNS предназначен для сетей, где обычные VPN и прокси заблокированы, но остаётся рабочий DNS-канал. DNS-туннель по своей природе медленнее обычного VPN. Цель проекта — максимальная полезная скорость и непрерывность соединения под цензурой.

## Начать здесь

| Задача | Раздел |
| --- | --- |
| Развернуть новый туннель | [Полное руководство](#полное-руководство-по-установке) |
| Понять выбор транспорта | [Автоматический режим](#автоматический-режим) |
| Выбрать профиль | [Профили](#профили) |
| Проверить сервер | [Мониторинг](#мониторинг) |
| Встроить Android engine | [Android и submodule](#android-и-submodule) |

## Происхождение и авторы

CottenDNS создан на основе работы двух проектов:

1. **[MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN)**, автор **Amin Mahmoudi** — исходная малозатратная архитектура, ARQ, балансировка резолверов и мультиплексирование сессий.
2. **[StormDNS](https://github.com/nullroute1970/StormDNS)**, сопровождаемый **NullRoute1970** — прямой предшественник CottenDNS.
3. **CottenDNS**, сопровождаемый **tajirax**, расширяет эту основу и сохраняет совместимость с клиентами MasterDNS/StormDNS.

CottenDNS — самостоятельный производный проект, а не заявление об авторстве исходной архитектуры. Проекты сохраняют наследование лицензии MIT; см. [LICENSE](LICENSE).

## Как это работает

```text
Приложение
   │
   ▼
Локальный SOCKS5 / TCP
   │
   ▼
Клиент CottenDNS
   ├── UDP/53 ─────┐
   ├── TCP/53 ─────┤
   ├── DoT ────────┤──► DNS-резолвер ──► Сервер CottenDNS ──► Интернет
   └── DoH ────────┘
```

Клиент делит потоки на небольшие DNS-кадры, шифрует и при необходимости сжимает их, выбирает путь через резолвер и восстанавливает потери с помощью ARQ и Reed–Solomon FEC. Сервер собирает поток и устанавливает исходящее соединение напрямую, через внешний SOCKS5 либо к фиксированной TCP-цели.

Встроенный SOCKS5 поддерживает TCP и универсальные UDP-ассоциации. Локальный DNS-сервер и кэш включаются по желанию.

## Основные преимущества

| Проблема сети | Поведение CottenDNS |
| --- | --- |
| UDP быстрее, но иногда отравляется или ограничивается | Рабочий UDP сохраняется; переключается только повреждённый резолвер |
| Пути резолверов сильно отличаются | Каждая пара `(резолвер, транспорт)` оценивается отдельно |
| Upload и download имеют разное качество | Раздельная статистика доставки, ошибок, RTT и достоверности |
| Ограниченный DNS MTU | MTU измеряется для каждого пути; пакет идёт только туда, где помещается |
| Большие потери | ARQ, ACK/NACK, немедленный replay, адаптивное дублирование и FEC |
| Поддельный ответ приходит слишком быстро | Запускается одна проверенная альтернативная попытка |
| Путь умер с пакетами в полёте | Неподтверждённые кадры переигрываются без новой сессии |
| Защитные копии перегружают канал | FEC, дублирование, replay и сканирование используют общий бюджет |
| Несколько путей равноценны | Одинарные bulk-пакеты распределяются между зрелыми путями |
| DPI распознаёт повторяющийся DNS | Ротация типов записей, изменение QNAME, случайные ID/cookie, DoT/DoH |

## Автоматический режим

Рекомендуемые настройки:

```toml
CONFIG_PRESET = "speed"
RESOLVER_TRANSPORT = "auto"
PATH_CONTROLLER_MODE = "unified"
COMPARABLE_PATH_STRIPING = true
```

Клиент автоматически:

- сначала использует UDP и не отказывается от него без причины;
- сравнивает UDP и TCP/53 отдельно для каждого резолвера;
- меняет только плохой или значительно более медленный путь;
- учитывает размер пакета, MTU, RTT, потери, направление и качество измерений;
- поддерживает резервные пути редкими проверками без конкуренции с трафиком;
- не складывает без необходимости FEC, сканирование и дублирование;
- запускает альтернативу при признаках DNS poisoning;
- переигрывает кадры до полного истечения ARQ RTO.

`auto` не включает DoT/DoH скрытно. Они выбираются пользователем:

```toml
RESOLVER_TRANSPORT = "dot" # или "doh"
```

Отдельные исключения:

```toml
RESOLVER_TRANSPORT_PATHS = { "1.1.1.1" = "doh", "8.8.8.8" = "auto", "9.9.9.9" = "tcp" }
```

## Динамический сервер

UDP, TCP/53, DoT и DoH используют один движок сессий. При:

```toml
ENCRYPTION_AUTO_DETECT = true
```

сервер автоматически принимает клиентские методы 1–5. AES-128/192/256-GCM проверяются раньше устаревших неаутентифицированных методов. XOR и ChaCha20 дополнительно проверяются по состоянию сессии и строгой структуре MTU-запросов. Метод `0` без шифрования разрешается только при явной настройке сервера.

Разные клиенты могут выбирать разные поддерживаемые шифры, транспорты, MTU, сжатие и параметры надёжности. Сервер применяет только свои безопасные пределы.

## Полное руководство по установке

Обычная схема:

```text
[Устройство клиента] → [DNS-резолверы] → [делегированный поддомен на VPS] → [Интернет]
```

### Перед началом

Потребуются домен с доступом к DNS-записям, Linux VPS с публичным IPv4 и `sudo`, открытые входящие UDP/53 и TCP/53 и клиент Windows, Linux или macOS. Порт 53 должен быть открыт и в локальном firewall, и в сетевом firewall провайдера VPS.

> [!CAUTION]
> Порт 53 может занимать `systemd-resolved`, BIND, dnsmasq или панель управления. Перед установкой проверьте `sudo ss -lntup | grep ':53 '`. Не закрывайте SSH-порт.

### Шаг 1 — Делегируйте короткий поддомен

Создайте у DNS-провайдера домена:

```dns-zone
ns.example.com.  300  IN  A   203.0.113.10
v.example.com.   300  IN  NS  ns.example.com.
```

Замените IP на адрес VPS. Не включайте CDN-проксирование для этих записей. Короткое имя оставляет больше места для полезной нагрузки DNS.

Проверьте распространение:

```bash
dig +short A ns.example.com
dig +short NS v.example.com
```

Ожидаются IP сервера и `ns.example.com.`. Если NS не виден, сначала исправьте делегирование.

### Шаг 2 — Установите сервер

```bash
sudo install -d -m 0755 /opt/cottendns
cd /opt/cottendns
curl -fsSL https://raw.githubusercontent.com/TaJirax/cottenDNS/main/server_linux_install.sh | sudo bash
```

В запросе установщика укажите `v.example.com`. Он скачивает release, создаёт конфигурацию и ключ, настраивает systemd, открывает UDP/TCP 53 в поддерживаемом firewall и проверяет `/healthz`.

Основные файлы:

```text
/opt/cottendns/server_config.toml
/opt/cottendns/encrypt_key.txt
```

Скопируйте ключ на клиент через безопасный канал:

```bash
sudo cat /opt/cottendns/encrypt_key.txt
```

### Шаг 3 — Проверьте сервер

```bash
systemctl is-active cottendns
curl -fsS http://127.0.0.1:9090/healthz
sudo ss -lnup | grep ':53 '
sudo ss -lntp | grep ':53 '
```

При ошибке:

```bash
journalctl -u cottendns -n 100 --no-pager
```

Не публикуйте порт `9090`: мониторинг по умолчанию предназначен для localhost.

### Шаг 4 — Настройте клиент

Скачайте архив своей платформы из [Releases](https://github.com/TaJirax/cottenDNS/releases/latest). Оставьте бинарник, `client_config.toml` и `client_resolvers.txt` в одной папке.

Минимальная безопасная конфигурация:

```toml
DOMAINS = ["v.example.com"]
ENCRYPTION_KEY = "ключ-сервера"
DATA_ENCRYPTION_METHOD = 3

PROTOCOL_TYPE = "SOCKS5"
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 18000

CONFIG_PRESET = "speed"
STARTUP_MODE = "resolvers"
RESOLVER_TRANSPORT = "auto"
PATH_CONTROLLER_MODE = "unified"
COMPARABLE_PATH_STRIPING = true
```

`client_resolvers.txt`:

```text
1.1.1.1
8.8.8.8
9.9.9.9
```

Начинайте с небольшого разнообразного списка: огромный список плохих резолверов только замедляет сканирование.

### Шаг 5 — Выполните первый запуск

Linux:

```bash
chmod +x ./CottenDns_Client_*
./CottenDns_Client_Linux_AMD64_vVERSION --config ./client_config.toml
```

Windows PowerShell:

```powershell
.\CottenDns_Client_Windows_AMD64_vVERSION.exe --config .\client_config.toml
```

Клиент проверит доступность туннеля, MTU, задержку, потери и UDP/TCP-путь каждого резолвера. Для сканирования без запуска proxy добавьте `--scan-only`.

Оставьте `STARTUP_MODE = "resolvers"` при каждом запуске. Доступность,
отравление, транспорт и MTU резолверов могут измениться между перезапусками.
`FAST_CONNECT = true` запускает соединение после появления небольшого
проверенного пула, а остальные резолверы проверяются в фоне без доверия старому
кэшу.

### Шаг 6 — Проверьте SOCKS5

Укажите в приложении `SOCKS5 127.0.0.1:18000` или выполните:

```bash
curl --proxy socks5h://127.0.0.1:18000 https://example.com/
```

`socks5h` передаёт разрешение имени через proxy.

### Безопасное обновление

```bash
cd /opt/cottendns
curl -fsSL https://raw.githubusercontent.com/TaJirax/cottenDNS/main/server_linux_install.sh | sudo bash -s -- --upgrade
```

Обновление сохраняет конфигурацию и ключ и откатывается, если новая служба не проходит health check. Для клиента распакуйте новый release отдельно и не удаляйте старую папку, пока новый бинарник не пройдёт сканирование и SOCKS-тест.

## Профили

| Профиль | Назначение |
| --- | --- |
| `speed` | Основной режим для максимальной полезной скорости |
| `survival` | Большие потери и нестабильные резолверы |
| `tcp-survival` | UDP/53 почти не работает, TCP/53 доступен |
| `iran`, `china`, `russia`, `venezuela`, `cuba` | Стартовые клиентские настройки для региональных ограничений |
| `low-bandwidth` | Очень слабый upload или строгий лимит DNS-запросов |

Это отправные точки, а не автоматическое определение страны. См. [CONFIG_PRESETS.md](CONFIG_PRESETS.md).

## Мониторинг

```bash
curl -s http://127.0.0.1:9090/healthz
curl -s 'http://127.0.0.1:9090/healthz?details=1' | jq
curl -s http://127.0.0.1:9090/metrics
```

Использование процесса:

```bash
pid=$(systemctl show -p MainPID --value cottendns)
ps -p "$pid" -o pid,%cpu,%mem,rss,vsz,etime,cmd
top -p "$pid"
```

## Android и submodule

Android-приложение может подключать этот репозиторий как Git submodule или CI-зависимость. Проверенный коммит движка:

```text
8eea49d1267b1a41441c25c75e69e6f12ad0a11f
```

Движок компилируется для Android arm64, armv7, amd64 и 386 без CGO. Оболочка приложения должна сохранить рекомендуемые TOML-настройки.

## Совместимость и безопасность

- Новый клиент + новый сервер: все функции.
- Старые клиенты + новый сервер: поддерживаются, включая MasterDNS/StormDNS.
- Новый клиент + старый сервер: клиентская маршрутизация работает, но новые серверные функции недоступны.
- Для аутентифицированного шифрования используйте AES-GCM `3`, `4` или `5`.
- DoT/DoH скрывает участок клиент→резолвер, но не весь маршрут.
- Метаданные объёма и времени могут показать, что используется туннель.
- Не публикуйте `encrypt_key.txt`.
- Используйте проект только там, где вы имеете право это делать.

## Документация и разработка

| Документ | Содержание |
| --- | --- |
| [CONFIG_PRESETS.md](CONFIG_PRESETS.md) | Профили и настройка |
| [ENGINEERING_CHANGES.md](docs/ENGINEERING_CHANGES.md) | Архитектура, исправления и тесты |
| [client_config.toml.simple](client_config.toml.simple) | Все параметры клиента |
| [server_config.toml.simple](server_config.toml.simple) | Все параметры сервера |

```bash
go build ./cmd/client
go build ./cmd/server
go test ./...
go vet ./...
```

## Лицензия и благодарности

CottenDNS сопровождается **tajirax** и распространяется по [MIT License](LICENSE).

- **Amin Mahmoudi** — [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN), исходная архитектура.
- **NullRoute1970** — [StormDNS](https://github.com/nullroute1970/StormDNS), прямой upstream.
- Спасибо всем участникам и пользователям, предоставляющим данные из цензурируемых сетей.
