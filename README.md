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
- На клиенте — Linux (root) или Windows 10/11 (администратор + [Wintun](https://www.wintun.net/))
- Аккаунт в Yandex Cloud, созданный API Gateway, сервисный аккаунт с ролью `serverless.apiGateway.websocketWriter` (или эквивалентом для Connection Management API)
- Публичный HTTPS-эндпоинт сервера, к которому API Gateway сможет постучать вебхуками (например, реверс-прокси за TLS-сертификатом)

## Сборка

Клиент кросс-платформенный — один и тот же `cmd/client` собирается под Linux и Windows. Под капотом TUN-интерфейс открывается через [`golang.zx2c4.com/wireguard/tun`](https://pkg.go.dev/golang.zx2c4.com/wireguard/tun) (Linux: `/dev/net/tun`, Windows: Wintun).

Сервер — Linux-only из-за iptables/NAT.

```bash
# Linux-сервер и Linux-клиент
go build -o myvpn-server ./cmd/server
go build -o myvpn-client ./cmd/client

# Windows-клиент (кросс-компиляция с Linux)
GOOS=windows GOARCH=amd64 go build -o myvpn-client.exe ./cmd/client
```

## Развёртывание через Yandex API Gateway

Это рабочий продакшен-режим: клиент подключается по `wss://` к Yandex API Gateway, тот вызывает HTTP-вебхуки на ваш VPN-сервер, а сервер пушит обратные пакеты через Yandex Connection Management API. Ниже — полный путь от пустого облака до работающего туннеля.

### Что вам понадобится

- Аккаунт в [Yandex Cloud](https://yandex.cloud/) с привязанным платёжным аккаунтом (API Gateway и трафик платные).
- Установленный и авторизованный [`yc`](https://yandex.cloud/ru/docs/cli/quickstart) CLI (`yc init`).
- Домен с TLS-сертификатом, указывающий на ваш VPN-сервер (нужен для HTTPS, без него API Gateway не сможет постучаться в бэкенд). Удобнее всего использовать Caddy — он сам выпустит сертификат через Let's Encrypt.
- Один из двух вариантов сервера:
  - **Yandex Compute Cloud-ВМ** с привязанным сервисным аккаунтом (рекомендуется — IAM-токен берётся из metadata-сервиса автоматически).
  - **Внешний VPS** — тогда IAM-токен придётся обновлять самостоятельно через файл и cron.

Перед запуском зафиксируйте идентификаторы фолдера и облака:

```bash
yc config get folder-id
yc config get cloud-id
```

### Шаг 1. Сервисный аккаунт и роль для Connection Management API

Сервисный аккаунт нужен серверу, чтобы получать IAM-токен и через него пушить пакеты обратно в API Gateway.

```bash
# создаём SA
yc iam service-account create --name myvpn-server

# узнаём id фолдера один раз
FOLDER_ID=$(yc config get folder-id)

# выдаём SA минимально необходимую роль:
# api-gateway.websocketWriter — даёт право на :send в Connection Management API
yc resource-manager folder add-access-binding "$FOLDER_ID" \
    --role api-gateway.websocketWriter \
    --service-account-name myvpn-server
```

Если ваша область видимости (фолдер) не позволяет назначать конкретно `api-gateway.websocketWriter`, можно временно дать `editor` на фолдер — этого тоже хватит, но это значительно шире, чем нужно.

Если запускаете VPN-сервер **на ВМ Yandex Compute Cloud** — привяжите этот SA к ВМ:

```bash
yc compute instance update <INSTANCE_NAME_OR_ID> \
    --service-account-name myvpn-server
```

После этого на ВМ заработает metadata-сервис: код сервера сам подтянет IAM-токен с `http://169.254.169.254/...` и будет его обновлять автоматически.

Если запускаете на **внешнем VPS** — создайте на своей машине авторизованный ключ или пользуйтесь уже залогиненным `yc` и обновляйте токен периодически (см. [шаг 4](#шаг-4-настройка-iam-токена-если-внешний-vps)).

### Шаг 2. Публичный HTTPS-эндпоинт для VPN-сервера

API Gateway требует, чтобы интеграция отвечала по `https://` — без TLS вебхуки доходить не будут. Самый короткий путь — поставить Caddy перед сервером.

1. На VPN-сервере направьте A-запись вашего домена на его IP (например, `vpn.example.com → 1.2.3.4`).
2. Поставьте Caddy и положите простую конфигурацию:

   ```bash
   sudo apt install caddy   # или установите по https://caddyserver.com/docs/install
   sudo nano /etc/caddy/Caddyfile
   ```

   ```caddy
   vpn.example.com {
       reverse_proxy 127.0.0.1:8080 {
           # API Gateway шлёт сообщения до 128 КБ; даём запас
           transport http {
               read_timeout 90s
               write_timeout 90s
           }
       }
   }
   ```

   ```bash
   sudo systemctl reload caddy
   ```

   Caddy сам получит и продлит сертификат через Let's Encrypt. Проверьте, что HTTPS поднялся: `curl -I https://vpn.example.com/healthz` (страница 404 — это нормально, главное чтобы был ответ от сервера, а не TLS-ошибка).

   <details>
   <summary>Альтернатива: nginx</summary>

   ```nginx
   server {
       listen 443 ssl http2;
       server_name vpn.example.com;

       ssl_certificate     /etc/letsencrypt/live/vpn.example.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/vpn.example.com/privkey.pem;

       location /ws {
           proxy_pass http://127.0.0.1:8080/ws;
           proxy_request_buffering off;     # API Gateway шлёт бинарь крупными кусками
           proxy_buffering off;
           client_max_body_size 256k;       # запас сверх 128 КБ лимита API Gateway
           proxy_read_timeout 90s;
           proxy_send_timeout 90s;
       }
   }
   ```

   </details>

3. Откройте порт 443 на firewall (для Yandex Compute: security group → правило allow tcp:443).

### Шаг 3. Сборка и деплой VPN-сервера

На целевой Linux-машине:

```bash
# собрать
go build -o myvpn-server ./cmd/server

# подготовить ключ ChaCha20-Poly1305 (32 байта). Тот же файл нужен клиенту.
sudo install -d -m 700 /etc/myvpn
dd if=/dev/urandom of=/etc/myvpn/key.bin bs=1 count=32
sudo install -m 600 ./myvpn-server /usr/local/bin/myvpn-server

# первый запуск (обычно через systemd unit):
sudo /usr/local/bin/myvpn-server -key /etc/myvpn/key.bin
```

При корректной работе в логе должно появиться:

```
✓ Network configured: IP forwarding enabled, NAT via eth0
VPN server listening on :8080 (HTTP)
  webhook path:  /ws
  ...
VPN server started. Press Ctrl+C to stop ...
```

### Шаг 4. Настройка IAM-токена (если внешний VPS)

На Yandex Compute Cloud-ВМ с привязанным SA (см. шаг 1) — пропустите этот шаг, токен сервер берёт автоматически.

На внешнем VPS — обновляйте токен по cron каждые 30–60 минут:

```bash
# /usr/local/bin/refresh-yc-token
#!/bin/bash
set -e
yc iam create-token > /run/yc-iam-token.tmp
mv /run/yc-iam-token.tmp /run/yc-iam-token
chmod 600 /run/yc-iam-token
```

```cron
# crontab -e
*/30 * * * * /usr/local/bin/refresh-yc-token >> /var/log/yc-token.log 2>&1
```

И запускайте сервер с переменной окружения:

```bash
sudo MYVPN_IAM_TOKEN_FILE=/run/yc-iam-token \
    /usr/local/bin/myvpn-server -key /etc/myvpn/key.bin
```

Сервер сам перечитывает файл раз в 5 минут — рестарт после обновления не нужен.

Альтернативно, можно прямо передать статический токен (живёт ~12 часов):

```bash
sudo YC_IAM_TOKEN="$(yc iam create-token)" \
    /usr/local/bin/myvpn-server -key /etc/myvpn/key.bin
```

### Шаг 5. Создание API Gateway

1. Откройте [`examples/api-gateway.yaml`](examples/api-gateway.yaml) и замените все вхождения `VPN_SERVER_URL` на ваш домен из шага 2 (например, `vpn.example.com`):

   ```bash
   sed -i 's/VPN_SERVER_URL/vpn.example.com/g' examples/api-gateway.yaml
   ```

2. Создайте API Gateway:

   ```bash
   yc serverless api-gateway create \
       --name myvpn-ws \
       --spec examples/api-gateway.yaml
   ```

   После создания посмотрите выданный домен:

   ```bash
   yc serverless api-gateway get myvpn-ws --format json | jq -r .domain
   # пример: d5d4abcdefghij1234567.apigw.yandexcloud.net
   ```

   Если позже понадобится подменить спецификацию (например, сменили домен бэкенда):

   ```bash
   yc serverless api-gateway update myvpn-ws --spec examples/api-gateway.yaml
   ```

### Шаг 6. Smoke-тест из консоли

До запуска полного клиента можно проверить, что webhook'и доходят, через [`wscat`](https://www.npmjs.com/package/wscat):

```bash
npm install -g wscat
wscat -c "wss://d5d4abcdefghij1234567.apigw.yandexcloud.net/ws"
# > Connected (press CTRL+C to quit)
# Введите любой произвольный текст — клиент сам по себе ничего полезного
# не отправит, но в логах VPN-сервера должна появиться строка
# "ws/gateway: client <connection-id> connected" (если включён -verbose).
```

Если в логах сервера видна запись о CONNECT — значит, цепочка `клиент → API Gateway → Caddy/nginx → myvpn-server` работает, и можно запускать настоящий VPN-клиент.

### Шаг 7. Запуск VPN-клиента

Передайте клиенту тот же `key.bin`, что у сервера, и URL вашего API Gateway (`wss://<домен>/ws`):

```bash
# Linux
sudo ./myvpn-client \
    -server "wss://d5d4abcdefghij1234567.apigw.yandexcloud.net/ws" \
    -key /etc/myvpn/key.bin

# Windows (PowerShell от администратора, рядом с .exe должна лежать wintun.dll)
.\myvpn-client.exe `
    -server "wss://d5d4abcdefghij1234567.apigw.yandexcloud.net/ws" `
    -key C:\myvpn\key.bin
```

Клиент сам:

- настроит TUN-интерфейс с IP `10.0.0.2/24`,
- добавит host-маршрут до домена API Gateway через прежний шлюз (чтобы внутри туннеля не потерять связь с самим gateway),
- развернёт split-default route (`0.0.0.0/1` + `128.0.0.0/1`) поверх существующего default-маршрута,
- при потере WebSocket'а (например, по 60-минутному лимиту API Gateway) **автоматически переподключится** с экспоненциальным backoff'ом — VPN-клиент при этом не выходит.

### Проверка, что всё работает

После запуска клиента:

```bash
curl https://ifconfig.me        # должен вернуть IP вашего VPN-сервера, а не вашего интернет-провайдера
curl https://api.ipify.org      # дублирующая проверка
ping -c 3 8.8.8.8               # ICMP должен ходить через туннель
```

В логах VPN-сервера на `-verbose` будут видны webhook-сообщения вида:

```
ws/webhook: client <connection-id> connected via API Gateway
Received 76 bytes from client <connection-id>, writing to TUN
TUN: 198 bytes -> 1 client(s)
```

### Troubleshooting

| Симптом | Что проверить |
|---|---|
| Клиент не подключается, в `wscat` сразу `error: Unexpected server response: 502` | API Gateway не смог достучаться до бэкенда. Проверьте: открыт ли 443 на firewall, доступен ли `https://vpn.example.com/ws` снаружи (попробуйте `curl -X POST https://vpn.example.com/ws -H 'X-Yc-Apigateway-Websocket-Event-Type: CONNECT' -H 'X-Yc-Apigateway-Websocket-Connection-Id: test'`). |
| `wscat` сразу получает `error: Unexpected server response: 400`, в логах Yandex Cloud `code: 400, event_type: CONNECT, response_length_bytes: 29` | Это «`missing connection id header`» от нашего сервера: у `type: http`-интеграции Yandex API Gateway **по умолчанию не форвардит заголовки оригинального запроса** на бэкенд. Лечится тем, что в каждой `x-yc-apigateway-websocket-*` операции объявлен `parameters:`-блок с нужными `X-Yc-Apigateway-Websocket-*` заголовками, а в `headers:` интеграции они подставляются через `{name}`-syntax. Так и сделано в актуальном `examples/api-gateway.yaml`. После правки спеки: `yc serverless api-gateway update --name <имя> --spec api-gateway.yaml`. |
| В логе сервера `connID` = литерал `{X-Yc-Apigateway-Websocket-Connection-Id}` (со скобками) | Substitution `{name}` в `type: http`-интеграции работает **только** если параметр объявлен в `parameters:`-блоке операции. В актуальном `examples/api-gateway.yaml` все нужные заголовки объявлены в `parameters:` для каждой из трёх websocket-операций. Если у тебя в спеке нет `parameters:`-блоков — обнови файл из репозитория. |
| В логах Yandex `code: 503, event_type: CONNECT, response_length_bytes: 0` (и в логах сервера ничего нет) | Скорее всего в спеке стоит `headers: { '*': '*' }`. Это форвардит ВСЕ заголовки оригинального WebSocket-handshake'а, включая hop-by-hop (`Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-*`). Бэкенды на HTTP/2 (включая ngrok) такой запрос отбивают с 503 ещё до твоего сервера. Используй явное перечисление `X-Yc-Apigateway-Websocket-*` через `parameters:` + substitution, как в актуальном `examples/api-gateway.yaml`, без `'*': '*'`. |
| Клиент падает с `Connection error: ... websocket: bad handshake` сразу после старта | Скорее всего в `-server` указан `ws://...apigw.yandexcloud.net/...`. Yandex API Gateway отдаёт WebSocket только по TLS — нужно `wss://` (порт 443). Текущая версия клиента сама апгрейдит схему и пишет `WARNING: ... upgrading to wss://...`; если это сообщение не появилось — пересоберите клиент из последнего main. |
| Клиент подключился, но `curl ifconfig.me` показывает реальный IP | Маршруты не настроились. На Linux: `ip route`, должны быть `0.0.0.0/1 dev myvpn0` и `128.0.0.0/1 dev myvpn0`. На Windows запустите клиент с `-verbose` — выведется итоговая forwarding table. |
| В логе сервера `push to <id>: HTTP 401 Unauthorized` | IAM-токен невалиден. На Compute Cloud-ВМ — проверьте, что SA привязан (`yc compute instance get ... | grep service_account_id`). На внешнем VPS — пересоздайте файл с токеном (`yc iam create-token > /run/yc-iam-token`). |
| В логе сервера `push to <id>: HTTP 403 Forbidden` | Сервисному аккаунту не выдана роль `api-gateway.websocketWriter`. Пересмотрите шаг 1. |
| В логе сервера `push to <id>: HTTP 404 Not Found` | Соединение уже закрыто на стороне API Gateway (idle/таймаут/клиент дисконнект). Это нормально, но если повторяется — возможно, бэкенд не успевает обработать DISCONNECT. |
| Клиент после 60 минут переподключается, но трафик не идёт | TCP-соединения внутри туннеля пережили реконнект и пытаются продолжаться через старые номера соединений. Это сетевой эффект, не баг — TCP сам обнаружит проблему и переустановит соединение. |
| `Error reading from TUN: too many segments` в логе сервера | Должно быть исправлено в текущей версии (батчевое чтение TUN с учётом GRO/TSO offload'ов). Если воспроизводится — пересоберите сервер из последнего main. |
| Логи сервера тихие, при этом клиент пишет `websocket: read error ... reconnecting` каждые несколько секунд | Скорее всего, TLS-прокси перед сервером отбивает запросы (например, `client_max_body_size` маловат у nginx, или Caddy отвалился). Проверьте логи прокси. |

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

## Запуск VPN-клиента на Windows 11

Клиент тот же самый `cmd/client`, просто собранный под Windows. На Windows TUN-интерфейс реализуется через драйвер [Wintun](https://www.wintun.net/) (тот же, что использует WireGuard). Доступ к Wintun делает библиотека `golang.zx2c4.com/wireguard/tun` — мы не пишем низкоуровневый код самостоятельно.

### Подготовка

1. Скачайте и распакуйте свежий релиз с https://www.wintun.net/builds/. Внутри лежит `wintun.dll` для разных архитектур.
2. Скопируйте `wintun.dll` нужной разрядности (`amd64` для 64-битной Windows 11) **в ту же папку, где лежит `myvpn-client.exe`**, либо в `%SystemRoot%\System32`. Без этой DLL клиент не запустится.
3. Запускайте PowerShell / cmd **от имени администратора** — Wintun-адаптер и правка таблицы маршрутизации требуют прав.

### Команда запуска

```powershell
.\myvpn-client.exe `
    -server "wss://d5d...apigw.yandexcloud.net/ws" `
    -key C:\myvpn\key.bin
```

Или через переменные окружения:

```powershell
$env:MYVPN_SERVER  = "wss://d5d...apigw.yandexcloud.net/ws"
$env:MYVPN_KEY     = "C:\myvpn\key.bin"
.\myvpn-client.exe
```

При запуске клиент:

- создаёт Wintun-адаптер с именем `myvpn0` и IP `10.0.0.2/24`;
- настраивает IP/MTU 1420 напрямую через WinAPI (`winipcfg.LUID.SetIPAddresses` / `MibIPInterfaceRow.NLMTU`) — никаких внешних вызовов `netsh`;
- если `MYVPN_AUTO_ROUTES ≠ false`, добавляет три маршрута через WinAPI (`winipcfg.LUID.AddRoute`, тот же путь использует сам WireGuard):
  - host-маршрут к API Gateway через прежний шлюз (чтобы не потерять связь);
  - `0.0.0.0/1` и `128.0.0.0/1` через туннель (split default route — перекрывают весь IPv4-простор без удаления оригинального дефолта);
- при выходе аккуратно удаляет добавленные маршруты и закрывает Wintun-сессию.

Параметры клиента полностью совпадают с Linux-версией (см. таблицы выше).

### Известные нюансы Windows-клиента

- **Wintun не входит в репозиторий**. DLL качается с https://www.wintun.net/ (MIT-лицензия от WireGuard), кладётся рядом с `.exe`. Можно встроить её через `//go:embed` и распаковывать на лету, но текущий клиент этого не делает.
- **DNS**: split default route отправит DNS-запросы в туннель. Если у вас на корпоративном Wi-Fi есть локальный DNS — он не будет доступен, пока туннель активен. Решение — указать публичный DNS в настройках адаптера (`netsh interface ipv4 add dnsservers "myvpn0" 8.8.8.8`).
- **IPv6 не маршрутизируется через VPN** — split default route добавлен только для IPv4. Если в системе включён IPv6 default-маршрут, IPv6-трафик пойдёт мимо туннеля. Чтобы этого избежать, отключите IPv6 на физическом интерфейсе или на адаптере Wintun.

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
- **Время жизни соединения**: API Gateway принудительно разрывает WebSocket через 60 минут. Клиент **автоматически переподключается** с экспоненциальным backoff'ом — VPN-сессия не прерывается, но TCP-соединения внутри туннеля во время разрыва теряют пакеты (TCP их перешлёт сам).
- **Биллинг**: оплачивается количество запросов и исходящий трафик API Gateway (см. [тарификацию](https://yandex.cloud/ru/docs/api-gateway/pricing)). Ping-фреймы и сообщения от сервера к клиенту бесплатны.
- **TLS на сервере**: Yandex API Gateway требует HTTPS до бэкенда. Без TLS вебхуки работать не будут.

## Производительность и батчинг

Yandex API Gateway обрабатывает MESSAGE-вебхуки одного WS-соединения **последовательно**: пока POST по очередному пакету не вернулся, следующий пакет ждёт в очереди шлюза. На RTT клиент → шлюз → бэкенд ~50 мс это даёт жёсткий потолок ~20 пакетов/сек × ~1 КБ = ~160 кбит/с (наблюдалось как 300 кбит/с в speedtest до батчинга). Кроме того, при попытке speedtest'а пушить на гигабитной скорости в шлюзе копится очередь, latency пакетов растёт линейно (наблюдалось `duration_seconds = 23.2 с` для 81-байтного MESSAGE), и TCP-стек внутри туннеля коллапсирует.

Чтобы обойти это, транспорт **склеивает несколько VPN-пакетов в одно WS-сообщение**:

- **Формат**: внутри одного WS-фрейма лежит последовательность `[uint16 BE длина пакета][пакет][uint16 BE длина пакета][пакет]…`. Каждый «пакет» — это уже зашифрованный VPN-пакет, как до батчинга.
- **Окно склеивания**: 2 мс (`DefaultBatchCoalesceWindow`). За это время накапливаются все пакеты, готовые к отправке, и улетают одним WS-сообщением. Для VPN-трафика 2 мс латентности совершенно незаметны.
- **Размер батча**: до 90 КБ (`MaxBatchPayloadBytes`) — с запасом под 96 КБ-лимит на push в Connection Management API. В один батч умещается 60+ типичных VPN-пакетов размером 1.5 КБ.
- **Эффект**: количество вебхуков, отправляемых API Gateway'ем на бэкенд, и количество push-вызовов с бэкенда обратно на клиента уменьшаются в 30–60 раз. Эффективная пропускная способность через API Gateway растёт пропорционально (с ~300 кбит/с до 5–15 Мбит/с в зависимости от размеров пакетов).
- **direct-ws**: формат тот же, но выгоды по throughput там нет — в direct-режиме нет per-message round-trip'а. Совместимость сохранена.

Тонкости:

- Если очередь входящих пакетов на сервере переполняется при разборе одного батча, оставшиеся пакеты дропаются (TCP внутри туннеля их перешлёт). Размер очереди по умолчанию 4096 (был 1024 до батчинга).
- При закрытии соединения накопленный батч **не** отправляется (закрытие → пакеты уже неактуальны). Это важно для graceful shutdown сервера и переподключения клиента.
- Если в проде нужно отключить батчинг (для сравнительных замеров), достаточно установить `BatchCoalesceWindow: -1` в `WSClientConfig` / `WSServerConfig` — каждый VPN-пакет будет уходить в отдельном WS-сообщении.

## Структура репозитория

```
client/                  — кросс-платформенный VPN-клиент:
                            tun.go            — общий wrapper над wireguard/tun
                            tun_linux.go      — настройка интерфейса через `ip`
                            tun_windows.go    — настройка интерфейса через winipcfg (WinAPI)
                            routes_linux.go   — RouteManager на `ip route`
                            routes_windows.go — RouteManager на winipcfg.LUID.AddRoute (split default)
                            client.go         — общая логика VPNClient
server/                  — Linux VPN-сервер: TUN (через wireguard/tun), NAT (iptables)
internal/                — общий код (шифрование ChaCha20-Poly1305, сжатие LZ4, envcfg)
internal/transport/      — транспорт WebSocket (клиент + серверный HTTP webhook +
                           клиент Connection Management API + IAM-провайдеры)
cmd/client/              — CLI клиента (собирается под Linux и Windows из одного исходника)
cmd/server/              — CLI сервера (Linux-only)
examples/api-gateway.yaml — готовая OpenAPI-спецификация для Yandex API Gateway
```

## Graceful shutdown

Сервер реагирует на `SIGINT`/`SIGTERM` корректным завершением (по умолчанию таймаут — 10 секунд):

1. Закрывается TUN-интерфейс — это разблокирует читателя и не даёт ядру слать пакеты в уже отключённый туннель.
2. WebSocket-транспорт рассылает всем активным клиентам close-фреймы (`CloseNormalClosure`) и закрывает их соединения.
3. `http.Server.Shutdown(ctx)` ждёт окончания in-flight webhook'ов от Yandex API Gateway.
4. Откатываются iptables-правила (`MASQUERADE`, `FORWARD`) и возвращается прежнее значение `net.ipv4.ip_forward`.

Повторный `Ctrl+C` в течение этих 10 секунд приведёт к немедленному `os.Exit(1)` — на случай, если что-то зависло. Клиент симметрично корректно закрывает TUN, восстанавливает таблицу маршрутизации и закрывает WebSocket.
