package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// WSDefaultHandshakeTimeout таймаут на установление WebSocket соединения
	WSDefaultHandshakeTimeout = 30 * time.Second
	// WSDefaultPingInterval интервал отправки ping-фреймов на серверную сторону
	WSDefaultPingInterval = 30 * time.Second
	// WSDefaultWriteTimeout таймаут на запись одного WebSocket-сообщения
	WSDefaultWriteTimeout = 30 * time.Second
	// WSDefaultPongWait сколько ждём pong ответа от сервера. Yandex API Gateway
	// закрывает соединение по простою через 10 минут, держим сильно меньше.
	WSDefaultPongWait = 90 * time.Second
	// WSDefaultReconnectMin минимальная задержка перед переподключением
	WSDefaultReconnectMin = 1 * time.Second
	// WSDefaultReconnectMax максимальная задержка перед переподключением
	WSDefaultReconnectMax = 30 * time.Second
	// WSMaxMessageSize ограничение на входящее сообщение. Yandex API Gateway
	// разрешает до 128 КБ, но реальные пакеты VPN значительно меньше.
	WSMaxMessageSize = 128 * 1024
)

// WSClientConfig параметры WebSocket клиента
type WSClientConfig struct {
	// URL адрес WebSocket сервера / API Gateway, например wss://host/path
	URL string
	// Headers дополнительные HTTP заголовки для рукопожатия
	Headers http.Header
	// HandshakeTimeout таймаут на установление WS соединения. 0 = WSDefaultHandshakeTimeout
	HandshakeTimeout time.Duration
	// PingInterval интервал отправки ping-фреймов. 0 = WSDefaultPingInterval. <0 отключает.
	PingInterval time.Duration
	// PongWait сколько ждать pong / любого сообщения от сервера. 0 = WSDefaultPongWait. <0 отключает.
	PongWait time.Duration
	// WriteTimeout таймаут на запись сообщения. 0 = WSDefaultWriteTimeout.
	WriteTimeout time.Duration
	// InsecureSkipVerify отключает проверку TLS сертификата (только для отладки).
	InsecureSkipVerify bool
}

// WSClientTransport — WebSocket-транспорт для VPN клиента.
//
// Используется как двунаправленный канал поверх wss:// до Yandex API Gateway.
// Каждый VPN-пакет отправляется как одно бинарное WebSocket-сообщение.
type WSClientTransport struct {
	cfg    WSClientConfig
	conn   *websocket.Conn
	connMu sync.Mutex // защищает conn от параллельной перепривязки

	writeMu sync.Mutex // сериализует запись в conn (gorilla требует один writer)

	done   chan struct{}
	wg     sync.WaitGroup
	closed bool
	closeMu sync.Mutex
}

// NewWSClientTransport устанавливает WS соединение и возвращает готовый транспорт.
func NewWSClientTransport(cfg WSClientConfig) (*WSClientTransport, error) {
	if cfg.URL == "" {
		return nil, errors.New("websocket URL is required")
	}
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid websocket URL %q: %w", cfg.URL, err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "ws", "wss":
	default:
		return nil, fmt.Errorf("unsupported websocket scheme %q (use ws or wss)", parsed.Scheme)
	}

	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = WSDefaultHandshakeTimeout
	}
	if cfg.PingInterval == 0 {
		cfg.PingInterval = WSDefaultPingInterval
	}
	if cfg.PongWait == 0 {
		cfg.PongWait = WSDefaultPongWait
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = WSDefaultWriteTimeout
	}

	t := &WSClientTransport{
		cfg:  cfg,
		done: make(chan struct{}),
	}

	if err := t.dial(); err != nil {
		return nil, err
	}

	if cfg.PingInterval > 0 {
		t.wg.Add(1)
		go t.pingLoop()
	}

	return t, nil
}

// dial выполняет рукопожатие и сохраняет conn.
func (t *WSClientTransport) dial() error {
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = t.cfg.HandshakeTimeout
	if t.cfg.InsecureSkipVerify {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	conn, _, err := dialer.Dial(t.cfg.URL, t.cfg.Headers)
	if err != nil {
		return fmt.Errorf("websocket dial failed: %w", err)
	}

	conn.SetReadLimit(WSMaxMessageSize)
	if t.cfg.PongWait > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(t.cfg.PongWait))
		conn.SetPongHandler(func(string) error {
			_ = conn.SetReadDeadline(time.Now().Add(t.cfg.PongWait))
			return nil
		})
	}

	t.connMu.Lock()
	t.conn = conn
	t.connMu.Unlock()
	return nil
}

// Write отправляет одно бинарное WebSocket сообщение.
func (t *WSClientTransport) Write(data []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	t.connMu.Lock()
	conn := t.conn
	t.connMu.Unlock()
	if conn == nil {
		return 0, errors.New("websocket not connected")
	}

	if t.cfg.WriteTimeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(t.cfg.WriteTimeout))
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

// Read блокируется до получения следующего бинарного сообщения и копирует его в buf.
// Возвращает количество записанных в buf байт.
func (t *WSClientTransport) Read(buf []byte) (int, error) {
	t.connMu.Lock()
	conn := t.conn
	t.connMu.Unlock()
	if conn == nil {
		return 0, errors.New("websocket not connected")
	}

	for {
		select {
		case <-t.done:
			return 0, errors.New("websocket transport closed")
		default:
		}

		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		if msgType != websocket.BinaryMessage {
			// текстовые сообщения игнорируем — VPN использует только бинарный канал
			continue
		}
		if len(payload) > len(buf) {
			return 0, fmt.Errorf("websocket buffer too small: got %d bytes, buffer is %d", len(payload), len(buf))
		}
		n := copy(buf, payload)
		return n, nil
	}
}

// pingLoop периодически отправляет ping-фреймы, чтобы соединение не закрывалось по таймауту.
func (t *WSClientTransport) pingLoop() {
	defer t.wg.Done()

	ticker := time.NewTicker(t.cfg.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.connMu.Lock()
			conn := t.conn
			t.connMu.Unlock()
			if conn == nil {
				continue
			}
			t.writeMu.Lock()
			if t.cfg.WriteTimeout > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(t.cfg.WriteTimeout))
			}
			err := conn.WriteMessage(websocket.PingMessage, nil)
			t.writeMu.Unlock()
			if err != nil {
				// не закрываем явно — Read вернёт ошибку и наверху отработает reconnect/выход
				return
			}
		}
	}
}

// Close завершает работу транспорта.
func (t *WSClientTransport) Close() error {
	t.closeMu.Lock()
	if t.closed {
		t.closeMu.Unlock()
		return nil
	}
	t.closed = true
	close(t.done)
	t.closeMu.Unlock()

	t.connMu.Lock()
	conn := t.conn
	t.conn = nil
	t.connMu.Unlock()

	if conn != nil {
		// Best effort: посылаем close-фрейм и закрываем сокет
		t.writeMu.Lock()
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		t.writeMu.Unlock()
		_ = conn.Close()
	}

	t.wg.Wait()
	return nil
}
