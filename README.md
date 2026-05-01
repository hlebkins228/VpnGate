# MyVPN — VPN-протокол на Go поверх Yandex API Gateway WebSocket

Простой VPN-сервер с TUN-интерфейсом и шифрованием ChaCha20-Poly1305. Транспорт работает поверх **WebSocket через Yandex API Gateway**: клиент подключается к API Gateway по `wss://`, а VPN-сервер обменивается с ним сообщениями через HTTP-вебхуки и Yandex Connection Management API.

## Архитектура

```
   ┌─────────┐  TUN packet           ┌────────────────────────────┐
   │ Клиент  │  → ChaCha20 + LZ4 →   │ Yandex API Gateway         │
   │ (TUN)   │  → wss:// .../ws  →   │  (websocket extension)     │
   └─────────┘                       └─────────────┬──────────────┘
                                                   │
                                  HTTP webhook на  │  ↑ Connection
                                  $connect /       │  Management API
                                  $message /       │  (Bearer IAM token)
                                  $disconnect      ↓  (REST POST :send)
                                                   │
                                          ┌────────┴────────┐
                                          │  VPN Server     │
                                          │  (TUN, NAT,     │
                                          │  iptables,      │
                                          │  HTTP webhook)  │
                                          └─────────────────┘
```

- **Клиент** открывает одно WebSocket-соединение к URL Yandex API Gateway, шифрует IP-пакеты из TUN (`ChaCha20-Poly1305` + опциональный `LZ4`) и отправляет их одним бинарным WebSocket-сообщением.
- **Yandex API Gateway** на каждое сообщение от клиента вызывает HTTP-вебхук VPN-сервера, передавая бинарное тело и заголовок `X-Yc-Apigateway-Websocket-Connection-Id`. На события `$connect` / `$disconnect` идут отдельные вебхуки.
- **VPN-сервер** принимает вебхуки на `/ws`, расшифровывает пакеты и пишет их в TUN. Чтобы отправить ответный пакет конкретному клиенту, сервер дёргает `apigateway-connections.api.cloud.yandex.net/.../connections/{connectionId}:send` с IAM-токеном.

Формат WebSocket-сообщения: `[1 байт флагов] [12 байт nonce] [ciphertext+tag]`. Бит 0 во флагах — признак сжатия LZ4.

## Требования

- Go 1.25 или выше для сборки
- Linux на сервере, права root/sudo (TUN, iptables, NAT)
- Linux на клиенте, права root/sudo (TUN, маршрутизация)
- Аккаунт в Yandex Cloud, созданный API Gateway, сервисный аккаунт с ролью `serverless.apiGateway.websocketWriter` (или эквивалентом для Connection Management API)
- Публичный HTTPS-эндпоинт сервера, к которому API Gateway сможет постучать вебхуками (например, реверс-прокси за TLS-сертификатом)

## Сборка

```bash
go build -o myvpn-server ./cmd/server
go build -o myvpn-client ./cmd/client
```

## Настройка Yandex API Gateway

1. **Создайте сервисный аккаунт** в Yandex Cloud и выдайте ему права на использование Connection Management API:

   ```bash
   yc iam service-account create --name myvpn-gw
   yc resource-manager folder add-access-binding <FOLDER_ID> \
       --role serverless.apiGateway.websocketWriter \
       --service-account-name myvpn-gw
   ```

   Если такой роли нет в вашем фолдере, используйте роль `editor` на фолдер (минимально требуется доступ к `apigateway.websocket.connections.send`).

2. **Подготовьте OpenAPI-спецификацию** API Gateway. Готовый шаблон лежит в [`examples/api-gateway.yaml`](examples/api-gateway.yaml). Замените в нём `VPN_SERVER_URL` на публичный HTTPS-адрес вашего VPN-сервера (например `vpn.example.com`):

   ```yaml
   paths:
     /ws:
       x-yc-apigateway-websocket-connect:
         x-yc-apigateway-integration:
           type: http
           url: https://vpn.example.com/ws
           method: POST
           headers:
             X-Yc-Apigateway-Websocket-Connection-Id: '{X-Yc-Apigateway-Websocket-Connection-Id}'
             X-Yc-Apigateway-Websocket-Event-Type: 'CONNECT'
       x-yc-apigateway-websocket-message:
         x-yc-apigateway-integration:
           type: http
           url: https://vpn.example.com/ws
           method: POST
           headers:
             X-Yc-Apigateway-Websocket-Connection-Id: '{X-Yc-Apigateway-Websocket-Connection-Id}'
             X-Yc-Apigateway-Websocket-Event-Type: 'MESSAGE'
       x-yc-apigateway-websocket-disconnect:
         x-yc-apigateway-integration:
           type: http
           url: https://vpn.example.com/ws
           method: POST
           headers:
             X-Yc-Apigateway-Websocket-Connection-Id: '{X-Yc-Apigateway-Websocket-Connection-Id}'
             X-Yc-Apigateway-Websocket-Event-Type: 'DISCONNECT'
   ```

3. **Создайте API Gateway**:

   ```bash
   yc serverless api-gateway create \
       --name myvpn-ws \
       --spec=examples/api-gateway.yaml
   ```

   После создания запомните выданный домен (`d5d...apigw.yandexcloud.net`). URL клиентского соединения будет `wss://<домен>/ws`.

## Запуск VPN-сервера

VPN-сервер должен быть доступен из интернета по HTTPS, чтобы Yandex API Gateway мог отправлять ему вебхуки. Самый простой вариант — поставить `caddy` / `nginx` перед сервером, выдать TLS и проксировать `/ws` (и опционально `/healthz`) на `localhost:8080`.

### IAM-токен для Connection Management API

Сервер должен уметь дёргать `apigateway-connections.api.cloud.yandex.net`, поэтому ему нужен IAM-токен сервисного аккаунта. Поддерживаются три источника (выбираются в этом порядке приоритета):

1. `MYVPN_IAM_TOKEN_FILE=<path>` — токен читается из файла и периодически перечитывается (раз в 5 минут). Подходит для случая, когда внешний скрипт обновляет файл, например:

   ```bash
   # каждый час по cron
   yc iam create-token --service-account-name myvpn-gw > /run/yc-iam-token
   ```

2. `YC_IAM_TOKEN=<token>` — статический токен в переменной окружения (живёт около 12 часов после `yc iam create-token`).

3. **Метадата-сервис** — если сервер запущен на Yandex Compute Cloud-ВМ с привязанным сервисным аккаунтом, токен автоматически берётся с `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` и автообновляется. Это источник по умолчанию, если не заданы первые два.

Имя переменной metadata-URL можно переопределить через `YC_METADATA_URL`, базовый URL Connection Management API — через `YC_CONNECTIONS_API_URL`.

### Команда запуска

На Yandex Compute Cloud-ВМ с привязанным SA достаточно:

```bash
sudo ./myvpn-server -key /etc/myvpn/key.bin
```

Или с внешним IAM-токеном (обновляемым внешним cron):

```bash
sudo MYVPN_IAM_TOKEN_FILE=/run/yc-iam-token \
    ./myvpn-server -key /etc/myvpn/key.bin
```

Все остальные параметры (`-listen`, webhook-путь, pprof) имеют разумные значения по умолчанию и при необходимости задаются переменными окружения (см. ниже).

Сервер автоматически:

- создаст TUN-интерфейс `myvpn0` с IP `10.0.0.1/24`;
- включит IP forwarding;
- настроит NAT (MASQUERADE) для VPN-подсети;
- добавит правила iptables для FORWARD;
- будет принимать вебхуки Yandex API Gateway на `/ws`;
- будет толкать ответные пакеты в Connection Management API.

### Параметры сервера

Флаги (самое часто изменяемое):

| Флаг | Env-альтернатива | Описание | По умолчанию |
|---|---|---|---|
| `-key` | `MYVPN_KEY` | файл с 32-байтным ключом ChaCha20-Poly1305 | сгенерировать случайный |
| `-listen` | `MYVPN_LISTEN` | адрес HTTP-сервера (вебхуки + опционально прямой WS) | `:8080` |
| `-direct-ws` | `MYVPN_DIRECT_WS` | включить локальный WS-эндпоинт для отладки без API Gateway | `false` |
| `-verbose` | `MYVPN_VERBOSE` | подробное логирование | `false` |

Переменные окружения (без флагов, редко меняемое):

| Переменная | Описание | По умолчанию |
|---|---|---|
| `YC_IAM_TOKEN` | статический IAM-токен Yandex Cloud | — |
| `MYVPN_IAM_TOKEN_FILE` | путь к файлу с IAM-токеном (перечитывается раз в 5 минут) | — |
| `MYVPN_PPROF_ADDR` | адрес pprof HTTP-сервера (пусто = выключен) | — |
| `MYVPN_WEBHOOK_PATH` | путь, на который Yandex API Gateway шлёт вебхуки | `/ws` |
| `MYVPN_DIRECT_WS_PATH` | путь прямого WS (используется при `-direct-ws=true`) | `/ws-direct` |
| `MYVPN_DISABLE_YANDEX_API` | `true` — выключить push в Yandex API Gateway, оставив только прямой WS | `false` |
| `YC_METADATA_URL` | переопределить URL metadata-сервиса IAM | YC metadata |
| `YC_CONNECTIONS_API_URL` | переопределить базовый URL Connection Management API | `https://apigateway-connections.api.cloud.yandex.net` |

## Запуск VPN-клиента

```bash
sudo ./myvpn-client \
    -server "wss://d5d...apigw.yandexcloud.net/ws" \
    -key /etc/myvpn/key.bin
```

Или с переменными окружения (удобно для systemd / docker):

```bash
sudo MYVPN_SERVER="wss://d5d...apigw.yandexcloud.net/ws" \
    MYVPN_KEY=/etc/myvpn/key.bin \
    ./myvpn-client
```

Клиент автоматически:

- создаст TUN-интерфейс `myvpn0` с указанным IP (по умолчанию `10.0.0.2`);
- настроит маршрут «весь трафик через VPN» (если `MYVPN_AUTO_ROUTES ≠ false`);
- сохранит маршрут к домену API Gateway через старый шлюз, чтобы не терять связь;
- при выходе восстановит оригинальные маршруты.

### Параметры клиента

Флаги (самое часто изменяемое):

| Флаг | Env-альтернатива | Описание | По умолчанию |
|---|---|---|---|
| `-server` | `MYVPN_SERVER` | WebSocket URL (`wss://...apigw.yandexcloud.net/ws`) | — (обязательно) |
| `-key` | `MYVPN_KEY` | файл с ключом (32 байта или 64 hex-символа) | — (обязательно) |
| `-ip` | `MYVPN_CLIENT_IP` | IP TUN-интерфейса клиента | `10.0.0.2` |
| `-verbose` | `MYVPN_VERBOSE` | подробное логирование | `false` |

Переменные окружения (без флагов):

| Переменная | Описание | По умолчанию |
|---|---|---|
| `MYVPN_AUTO_ROUTES` | `true`/`false` — автоматическая настройка маршрутов | `true` |
| `MYVPN_INSECURE_TLS` | `true`/`false` — отключить проверку TLS-сертификата (только для отладки) | `false` |
| `MYVPN_PPROF_ADDR` | адрес pprof HTTP-сервера (пусто = выключен) | — |
| `MYVPN_WS_HEADERS` | дополнительные HTTP-заголовки рукопожатия в виде `Key1: V1, Key2: V2` | — |

## Локальная отладка без Yandex Cloud

Чтобы протестировать VPN без реального API Gateway, у сервера есть «прямой» WebSocket-эндпоинт. Включите его флагом `-direct-ws`:

Сервер:

```bash
sudo MYVPN_DISABLE_YANDEX_API=true \
    ./myvpn-server -direct-ws -key key.bin
```

Клиент:

```bash
sudo MYVPN_AUTO_ROUTES=false \
    ./myvpn-client -server "ws://SERVER_IP:8080/ws-direct" -key key.bin
```

В этом режиме сервер сам терминирует WebSocket-соединения и не вызывает Yandex API. Это удобно для проверки, что шифрование, TUN и маршрутизация настроены правильно, прежде чем заворачивать всё в API Gateway.

Путь прямого WS по умолчанию — `/ws-direct`. Его можно поменять переменной `MYVPN_DIRECT_WS_PATH=/your-path`.

## Ключи шифрования

```bash
# случайный 32-байтный ключ
dd if=/dev/urandom of=key.bin bs=1 count=32

# или из hex-строки
echo "1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890" | xxd -r -p > key.bin
```

Передайте один и тот же `key.bin` серверу и каждому клиенту.

## Особенности и ограничения

- **Размер пакета**: Yandex API Gateway ограничивает WebSocket-сообщение 128 КБ. С TUN MTU 1420 + overhead ChaCha20-Poly1305 (28 байт) + флаг сжатия (1 байт) пакет помещается с большим запасом.
- **Idle-таймаут**: API Gateway закрывает соединение, если оно молчит 10 минут. Клиент шлёт ping-фреймы каждые 30 секунд, поэтому в норме соединение поддерживается.
- **Время жизни соединения**: API Gateway принудительно разрывает WebSocket через 60 минут. В этом случае клиент завершает работу — рестарт восстановит соединение.
- **Биллинг**: оплачивается количество запросов и исходящий трафик API Gateway (см. [тарификацию](https://yandex.cloud/ru/docs/api-gateway/pricing)). Ping-фреймы и сообщения от сервера к клиенту бесплатны.
- **TLS на сервере**: Yandex API Gateway требует HTTPS до бэкенда. Без TLS вебхуки работать не будут.

## Структура репозитория

```
client/                  — TUN, RouteManager и логика VPN-клиента
server/                  — TUN, NAT, NetworkManager и логика VPN-сервера
internal/                — общий код (шифрование, протокол, сжатие, пул буферов)
internal/transport/      — транспорт WebSocket (клиент + серверный HTTP webhook +
                           клиент Connection Management API + IAM-провайдеры)
cmd/{client,server}/     — CLI бинарники
examples/api-gateway.yaml — готовая OpenAPI-спецификация для Yandex API Gateway
```
