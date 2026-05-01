package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Yandex API Gateway добавляет в HTTP-запрос интеграции набор заголовков,
// описанный в https://yandex.cloud/ru/docs/api-gateway/concepts/extensions/websocket
const (
	HeaderConnectionID = "X-Yc-Apigateway-Websocket-Connection-Id"
	HeaderEventType    = "X-Yc-Apigateway-Websocket-Event-Type"
	HeaderConnectedAt  = "X-Yc-Apigateway-Websocket-Connected-At"
	HeaderDisconnectStatus = "X-Yc-Apigateway-Websocket-Disconnect-Status-Code"
	HeaderDisconnectReason = "X-Yc-Apigateway-Websocket-Disconnect-Reason"

	EventConnect    = "CONNECT"
	EventMessage    = "MESSAGE"
	EventDisconnect = "DISCONNECT"
)

// IncomingPacket — пакет, полученный от какого-либо клиента.
type IncomingPacket struct {
	// ConnID идентификатор соединения (заголовок X-Yc-Apigateway-Websocket-Connection-Id).
	// Для прямого WS режима — внутренний ID, не относится к Yandex API Gateway.
	ConnID string
	// Data полезные данные (бинарное тело сообщения).
	Data []byte
}

// connSink интерфейс для отправки пакета конкретному клиенту.
//
// Реализуется либо через Yandex Connection Management API (webhook режим),
// либо напрямую в WebSocket connection (direct режим).
type connSink interface {
	Send(ctx context.Context, data []byte) error
	Close() error
}

// directWSSink — sink, пишущий прямо в WebSocket соединение.
type directWSSink struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
	timeout time.Duration
}

func (s *directWSSink) Send(_ context.Context, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.timeout > 0 {
		_ = s.conn.SetWriteDeadline(time.Now().Add(s.timeout))
	}
	return s.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (s *directWSSink) Close() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = s.conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	return s.conn.Close()
}

// gatewaySink — sink, отправляющий пакет через Yandex Connection Management API.
type gatewaySink struct {
	push   *YCPushClient
	connID string
}

func (s *gatewaySink) Send(ctx context.Context, data []byte) error {
	return s.push.SendBinary(ctx, s.connID, data)
}

func (s *gatewaySink) Close() error { return nil }

// WSServerConfig параметры WebSocket-серверного транспорта.
type WSServerConfig struct {
	// Listen адрес HTTP сервера, например ":8080".
	Listen string
	// WebhookPath путь, по которому Yandex API Gateway будет дёргать webhook (POST).
	// Должен совпадать с URL в `x-yc-apigateway-integration: type: http`.
	// По умолчанию "/ws".
	WebhookPath string
	// DirectWSPath путь для "прямого" WebSocket-эндпоинта (без API Gateway).
	// Если пусто — прямой режим отключён.
	DirectWSPath string
	// PushClient клиент Yandex Connection Management API.
	// Обязателен, если хотя бы один клиент должен подключаться через API Gateway.
	PushClient *YCPushClient
	// IncomingQueueSize размер канала входящих пакетов. По умолчанию 1024.
	IncomingQueueSize int
	// WriteTimeout таймаут на запись в прямой WS. 0 = WSDefaultWriteTimeout.
	WriteTimeout time.Duration
	// PongWait таймаут чтения для прямого WS (с учётом ping-фреймов клиента). 0 = WSDefaultPongWait.
	PongWait time.Duration
	// Verbose подробное логирование.
	Verbose bool
	// PushContextTimeout таймаут на одну отправку через Connection API.
	// 0 = pushDefaultTimeout.
	PushContextTimeout time.Duration
}

// WSServerTransport — серверный транспорт, мультиклиентный.
//
// Разделяет два источника соединений:
//   - HTTP webhook от Yandex API Gateway: события CONNECT/MESSAGE/DISCONNECT;
//     отправка обратно идёт через Connection Management API.
//   - Прямой WebSocket: для локальной отладки без API Gateway.
//
// Все входящие пакеты сходятся в один канал, доступный через Recv().
type WSServerTransport struct {
	cfg WSServerConfig

	httpSrv *http.Server
	listener net.Listener
	upgrader websocket.Upgrader

	connsMu sync.RWMutex
	conns   map[string]connSink

	incoming chan IncomingPacket

	done    chan struct{}
	wg      sync.WaitGroup
	closed  bool
	closeMu sync.Mutex

	pushTimeout time.Duration
}

// NewWSServerTransport создаёт серверный транспорт и запускает HTTP сервер.
func NewWSServerTransport(cfg WSServerConfig) (*WSServerTransport, error) {
	if cfg.Listen == "" {
		return nil, errors.New("listen address is required")
	}
	if cfg.WebhookPath == "" {
		cfg.WebhookPath = "/ws"
	}
	if !strings.HasPrefix(cfg.WebhookPath, "/") {
		cfg.WebhookPath = "/" + cfg.WebhookPath
	}
	if cfg.DirectWSPath != "" && !strings.HasPrefix(cfg.DirectWSPath, "/") {
		cfg.DirectWSPath = "/" + cfg.DirectWSPath
	}
	if cfg.IncomingQueueSize <= 0 {
		cfg.IncomingQueueSize = 1024
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = WSDefaultWriteTimeout
	}
	if cfg.PongWait == 0 {
		cfg.PongWait = WSDefaultPongWait
	}
	pushTimeout := cfg.PushContextTimeout
	if pushTimeout <= 0 {
		pushTimeout = pushDefaultTimeout
	}

	t := &WSServerTransport{
		cfg:         cfg,
		conns:       make(map[string]connSink),
		incoming:    make(chan IncomingPacket, cfg.IncomingQueueSize),
		done:        make(chan struct{}),
		pushTimeout: pushTimeout,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  WSMaxMessageSize,
			WriteBufferSize: WSMaxMessageSize,
			CheckOrigin:     func(*http.Request) bool { return true },
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.WebhookPath, t.handleWebhook)
	if cfg.DirectWSPath != "" {
		mux.HandleFunc(cfg.DirectWSPath, t.handleDirectWS)
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}

	t.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	t.listener = listener

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		if err := t.httpSrv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("ws transport: HTTP server error: %v", err)
		}
	}()

	return t, nil
}

// Addr возвращает фактический адрес HTTP-сервера (полезно при Listen=":0").
func (t *WSServerTransport) Addr() net.Addr {
	if t.listener == nil {
		return nil
	}
	return t.listener.Addr()
}

// Recv возвращает следующий входящий пакет.
// Блокируется до получения пакета или закрытия транспорта.
func (t *WSServerTransport) Recv() (IncomingPacket, error) {
	select {
	case <-t.done:
		return IncomingPacket{}, errors.New("ws transport closed")
	case pkt, ok := <-t.incoming:
		if !ok {
			return IncomingPacket{}, errors.New("ws transport closed")
		}
		return pkt, nil
	}
}

// Send отправляет данные клиенту с указанным connID.
func (t *WSServerTransport) Send(connID string, data []byte) error {
	t.connsMu.RLock()
	sink, ok := t.conns[connID]
	t.connsMu.RUnlock()
	if !ok {
		return fmt.Errorf("connection %s not registered", connID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), t.pushTimeout)
	defer cancel()
	return sink.Send(ctx, data)
}

// Conns возвращает идентификаторы активных подключений.
func (t *WSServerTransport) Conns() []string {
	t.connsMu.RLock()
	defer t.connsMu.RUnlock()
	ids := make([]string, 0, len(t.conns))
	for id := range t.conns {
		ids = append(ids, id)
	}
	return ids
}

// Close корректно завершает работу транспорта.
func (t *WSServerTransport) Close() error {
	t.closeMu.Lock()
	if t.closed {
		t.closeMu.Unlock()
		return nil
	}
	t.closed = true
	close(t.done)
	t.closeMu.Unlock()

	// Закрываем все sink'и
	t.connsMu.Lock()
	for id, sink := range t.conns {
		_ = sink.Close()
		delete(t.conns, id)
	}
	t.connsMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if t.httpSrv != nil {
		_ = t.httpSrv.Shutdown(ctx)
	}

	t.wg.Wait()
	close(t.incoming)
	return nil
}

// handleWebhook обрабатывает HTTP-вебхук от Yandex API Gateway.
func (t *WSServerTransport) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	connID := r.Header.Get(HeaderConnectionID)
	event := strings.ToUpper(r.Header.Get(HeaderEventType))

	if connID == "" {
		http.Error(w, "missing connection id header", http.StatusBadRequest)
		return
	}

	switch event {
	case EventConnect, "":
		// CONNECT (или пусто — трактуем как connect для совместимости)
		if t.cfg.PushClient == nil {
			http.Error(w, "push client not configured", http.StatusServiceUnavailable)
			return
		}
		t.registerGatewayConn(connID)
		if t.cfg.Verbose {
			log.Printf("ws/webhook: client %s connected via API Gateway", connID)
		}
		w.WriteHeader(http.StatusOK)

	case EventMessage:
		if t.cfg.PushClient == nil {
			http.Error(w, "push client not configured", http.StatusServiceUnavailable)
			return
		}
		// Гарантируем регистрацию даже если CONNECT-хук не настроен.
		t.registerGatewayConn(connID)

		body, err := io.ReadAll(io.LimitReader(r.Body, WSMaxMessageSize+1))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(body) > WSMaxMessageSize {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}

		select {
		case t.incoming <- IncomingPacket{ConnID: connID, Data: body}:
		case <-t.done:
			http.Error(w, "server shutting down", http.StatusServiceUnavailable)
			return
		default:
			http.Error(w, "incoming queue is full", http.StatusServiceUnavailable)
			return
		}

		// Возвращаем пустой бинарный ответ. Yandex API Gateway отправит тело
		// ответа клиенту как одно сообщение, поэтому для VPN мы ничего синхронно
		// не отправляем — вся отдача идёт асинхронно через Connection API.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)

	case EventDisconnect:
		t.unregisterConn(connID)
		if t.cfg.Verbose {
			log.Printf("ws/webhook: client %s disconnected (status=%s reason=%s)",
				connID,
				r.Header.Get(HeaderDisconnectStatus),
				r.Header.Get(HeaderDisconnectReason))
		}
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "unknown event type: "+event, http.StatusBadRequest)
	}
}

// registerGatewayConn регистрирует клиента, подключённого через Yandex API Gateway.
func (t *WSServerTransport) registerGatewayConn(connID string) {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()
	if _, exists := t.conns[connID]; exists {
		return
	}
	t.conns[connID] = &gatewaySink{push: t.cfg.PushClient, connID: connID}
}

// unregisterConn удаляет клиента из таблицы подключений.
func (t *WSServerTransport) unregisterConn(connID string) {
	t.connsMu.Lock()
	sink, ok := t.conns[connID]
	if ok {
		delete(t.conns, connID)
	}
	t.connsMu.Unlock()
	if ok && sink != nil {
		_ = sink.Close()
	}
}

// handleDirectWS обрабатывает прямое WebSocket подключение (для локальной отладки).
func (t *WSServerTransport) handleDirectWS(w http.ResponseWriter, r *http.Request) {
	conn, err := t.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws/direct: upgrade failed: %v", err)
		return
	}

	// Используем remote-addr как ID соединения (просто, уникально на время сессии).
	connID := "direct:" + conn.RemoteAddr().String()

	conn.SetReadLimit(WSMaxMessageSize)
	if t.cfg.PongWait > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(t.cfg.PongWait))
		conn.SetPongHandler(func(string) error {
			_ = conn.SetReadDeadline(time.Now().Add(t.cfg.PongWait))
			return nil
		})
	}

	sink := &directWSSink{conn: conn, timeout: t.cfg.WriteTimeout}
	t.connsMu.Lock()
	t.conns[connID] = sink
	t.connsMu.Unlock()

	if t.cfg.Verbose {
		log.Printf("ws/direct: client %s connected", connID)
	}

	defer func() {
		t.unregisterConn(connID)
		if t.cfg.Verbose {
			log.Printf("ws/direct: client %s disconnected", connID)
		}
	}()

	for {
		select {
		case <-t.done:
			return
		default:
		}

		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				if t.cfg.Verbose {
					log.Printf("ws/direct: read error from %s: %v", connID, err)
				}
			}
			return
		}
		if msgType != websocket.BinaryMessage {
			continue
		}

		select {
		case t.incoming <- IncomingPacket{ConnID: connID, Data: payload}:
		case <-t.done:
			return
		}
	}
}
