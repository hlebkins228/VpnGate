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

Сервер должен уметь дёргать `apigateway-connections.api.cloud.yandex.net`, поэтому ему нужен IAM-токен сервисного аккаунта. Поддерживаются три источника, в порядке приоритета:

1. `-iam-token-file <path>` — токен читается из файла и периодически перечитывается (раз в 5 минут). Подходит для случая, когда внешний скрипт обновляет файл, например:

   ```bash
   # каждый час по cron
   yc iam create-token --service-account-name myvpn-gw > /run/yc-iam-token
   ```

2. `-iam-token <token>` или переменная окружения `YC_IAM_TOKEN` — статический токен (живёт около 12 часов после `yc iam create-token`).

3. **Метадата-сервис** — если сервер запущен на Yandex Compute Cloud-ВМ с привязанным сервисным аккаунтом, токен автоматически берётся с `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` и автообновляется. По умолчанию используется этот источник, если не заданы первые два.

### Команда запуска

```bash
sudo ./myvpn-server \
    -listen :8080 \
    -webhook-path /ws \
    -key /etc/myvpn/key.bin \
    -iam-token-file /run/yc-iam-token
```

Сервер автоматически:

- создаст TUN-интерфейс `myvpn0` с IP `10.0.0.1/24`;
- включит IP forwarding;
- настроит NAT (MASQUERADE) для VPN-подсети;
- добавит правила iptables для FORWARD;
- будет принимать вебхуки Yandex API Gateway на `/ws`;
- будет толкать ответные пакеты в Connection Management API.

### Параметры сервера

| Флаг | Описание | По умолчанию |
|---|---|---|
| `-listen` | адрес HTTP-сервера (вебхуки + опционально прямой WS) | `:8080` |
| `-webhook-path` | путь, на который Yandex API Gateway шлёт вебхуки | `/ws` |
| `-direct-ws-path` | путь для прямого WebSocket (отладка без API Gateway, см. ниже). Пусто = выключено | `""` |
| `-key` | файл с 32-байтным ключом ChaCha20-Poly1305 | сгенерировать случайный |
| `-iam-token` | статический IAM-токен Yandex Cloud | — |
| `-iam-token-file` | файл с IAM-токеном (перечитывается раз в 5 минут) | — |
| `-iam-metadata-url` | URL метадата-сервиса для получения IAM | YC metadata |
| `-yc-connections-api` | базовый URL Connection Management API | `https://apigateway-connections.api.cloud.yandex.net` |
| `-disable-yandex-api` | выключить интеграцию с Yandex API Gateway (только прямой WS) | `false` |
| `-verbose` | подробное логирование | `false` |
| `-pprof` | адрес pprof | `:6060` |
| `-metrics` | адрес метрик | `:6061` |

## Запуск VPN-клиента

```bash
sudo ./myvpn-client \
    -server "wss://d5d...apigw.yandexcloud.net/ws" \
    -key /etc/myvpn/key.bin \
    -ip 10.0.0.2
```

Клиент автоматически:

- создаст TUN-интерфейс `myvpn0` с указанным IP;
- настроит маршрут «весь трафик через VPN» (если `-auto-routes=true`);
- сохранит маршрут к домену API Gateway через старый шлюз, чтобы не терять связь;
- при выходе восстановит оригинальные маршруты.

### Параметры клиента

| Флаг | Описание | По умолчанию |
|---|---|---|
| `-server` | WebSocket URL (например `wss://...apigw.yandexcloud.net/ws`) | — (обязательно) |
| `-key` | файл с ключом (32 байта или 64 hex-символа) | — (обязательно) |
| `-ip` | IP TUN-интерфейса клиента | `10.0.0.2` |
| `-auto-routes` | автоматическая настройка маршрутов | `true` |
| `-ws-headers` | дополнительные HTTP-заголовки рукопожатия в виде `Key1: V1, Key2: V2` | — |
| `-insecure-tls` | отключить проверку TLS-сертификата (только для отладки) | `false` |
| `-verbose` | подробное логирование | `false` |
| `-pprof` | адрес pprof | `:6060` |

## Локальная отладка без Yandex Cloud

Чтобы протестировать VPN без реального API Gateway, у сервера есть «прямой» WebSocket-эндпоинт. Включите его флагом `-direct-ws-path`:

Сервер:

```bash
sudo ./myvpn-server \
    -listen :8080 \
    -direct-ws-path /ws-direct \
    -disable-yandex-api \
    -key key.bin
```

Клиент:

```bash
sudo ./myvpn-client \
    -server "ws://SERVER_IP:8080/ws-direct" \
    -key key.bin \
    -ip 10.0.0.2 \
    -auto-routes=false
```

В этом режиме сервер сам терминирует WebSocket-соединения и не вызывает Yandex API. Это удобно для проверки, что шифрование, TUN и маршрутизация настроены правильно, прежде чем заворачивать всё в API Gateway.

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
