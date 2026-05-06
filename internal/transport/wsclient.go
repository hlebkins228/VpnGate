package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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

// errClosed — sentinel-ошибка, возвращаемая Read/Write после Close.
var errClosed = errors.New("websocket transport closed")

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
	// ReconnectMin минимальная задержка между попытками переподключения. 0 = WSDefaultReconnectMin.
	// Установка <0 отключает автопереподключение (Read/Write вернут ошибку при разрыве).
	ReconnectMin time.Duration
	// ReconnectMax максимальная задержка между попытками. 0 = WSDefaultReconnectMax.
	ReconnectMax time.Duration
	// InsecureSkipVerify отключает проверку TLS сертификата (только для отладки).
	InsecureSkipVerify bool
	// Verbose подробное логирование (handshakes, reconnects).
	Verbose bool
	// BatchCoalesceWindow время ожидания соседних пакетов перед отправкой WS-сообщения.
	// 0 = DefaultBatchCoalesceWindow. <0 отключает батчинг (каждый пакет — отдельное WS-сообщение).
	BatchCoalesceWindow time.Duration
	// BatchMaxBytes максимальный размер одного батча в байтах. 0 = MaxBatchPayloadBytes.
	BatchMaxBytes int
}

// WSClientTransport — WebSocket-транспорт для VPN клиента.
//
// Используется как двунаправленный канал поверх wss:// до Yandex API Gateway.
// VPN-пакеты склеиваются в батчи (см. internal/transport/batch.go) и
// отправляются одним бинарным WebSocket-сообщением, что радикально снижает
// число вебхуков, генерируемых API Gateway на бэкенд.
//
// Транспорт самостоятельно переподключается при потере соединения с
// экспоненциальным backoff. Yandex API Gateway принудительно разрывает
// WebSocket через 60 минут, поэтому автоматическое переподключение —
// обязательное условие для долгоживущих VPN-сессий.
type WSClientTransport struct {
	cfg WSClientConfig

	// conn — атомарный указатель на текущее WebSocket-соединение. nil во
	// время переподключения. Read/Write подхватывают новое значение без
	// блокировок.
	conn atomic.Pointer[websocket.Conn]

	// reconnectMu сериализует попытки переподключения, не блокируя Read/Write.
	reconnectMu sync.Mutex
	// writeMu сериализует запись в текущий conn (gorilla требует один writer).
	writeMu sync.Mutex

	done    chan struct{}
	wg      sync.WaitGroup
	closed  bool
	closeMu sync.Mutex

	// reconnectEnabled = false → Read/Write возвращают ошибку при разрыве.
	reconnectEnabled bool

	// batcher склеивает исходящие VPN-пакеты в один WS-фрейм. nil при
	// BatchCoalesceWindow < 0 (тогда Write отправляет каждый пакет как отдельное
	// сообщение, для совместимости с тестами или отладки).
	batcher *batchedWriter

	// readMu защищает pending — буфер декодированных VPN-пакетов, ещё не
	// отданных через Read.
	readMu  sync.Mutex
	pending [][]byte
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

	reconnect := true
	if cfg.ReconnectMin < 0 || cfg.ReconnectMax < 0 {
		reconnect = false
	}
	if cfg.ReconnectMin == 0 {
		cfg.ReconnectMin = WSDefaultReconnectMin
	}
	if cfg.ReconnectMax == 0 {
		cfg.ReconnectMax = WSDefaultReconnectMax
	}
	if cfg.ReconnectMax < cfg.ReconnectMin {
		cfg.ReconnectMax = cfg.ReconnectMin
	}

	t := &WSClientTransport{
		cfg:              cfg,
		done:             make(chan struct{}),
		reconnectEnabled: reconnect,
	}

	coalesce := cfg.BatchCoalesceWindow
	if coalesce == 0 {
		coalesce = DefaultBatchCoalesceWindow
	}
	if coalesce >= 0 {
		t.batcher = newBatchedWriter(coalesce, cfg.BatchMaxBytes, t.flushBatch)
	}

	conn, err := t.dialNew()
	if err != nil {
		return nil, err
	}
	t.conn.Store(conn)

	if cfg.PingInterval > 0 {
		t.wg.Add(1)
		go t.pingLoop()
	}

	return t, nil
}

// dialNew выполняет одно WebSocket-рукопожатие и возвращает новое соединение.
// Не трогает t.conn — caller сам решает, как с ним поступить.
func (t *WSClientTransport) dialNew() (*websocket.Conn, error) {
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = t.cfg.HandshakeTimeout
	if t.cfg.InsecureSkipVerify {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	conn, _, err := dialer.Dial(t.cfg.URL, t.cfg.Headers)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}

	conn.SetReadLimit(WSMaxMessageSize)
	if t.cfg.PongWait > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(t.cfg.PongWait))
		conn.SetPongHandler(func(string) error {
			_ = conn.SetReadDeadline(time.Now().Add(t.cfg.PongWait))
			return nil
		})
	}
	return conn, nil
}

// reconnect закрывает сломанное соединение и устанавливает новое с
// экспоненциальным backoff. Возвращает nil после успешного переподключения,
// либо errClosed, если транспорт закрыт во время попыток.
//
// Несколько одновременных вызовов сериализуются через reconnectMu; повторные
// вызовы, заставшие уже актуальный t.conn (отличный от broken), сразу выходят.
func (t *WSClientTransport) reconnect(broken *websocket.Conn) error {
	t.reconnectMu.Lock()
	defer t.reconnectMu.Unlock()

	// Если кто-то уже успел переподключить раньше — выходим.
	if cur := t.conn.Load(); cur != nil && cur != broken {
		return nil
	}

	// Помечаем conn как nil, чтобы Read/Write увидели "переподключаемся".
	t.conn.Store(nil)

	// Закрываем сломанное соединение (если ещё не закрыто).
	if broken != nil {
		_ = broken.Close()
	}

	backoff := t.cfg.ReconnectMin
	for {
		select {
		case <-t.done:
			return errClosed
		default:
		}

		conn, err := t.dialNew()
		if err == nil {
			// Если Close() успел отработать, пока мы висели в dialNew — новое
			// соединение никому не принадлежит и должно быть закрыто, иначе TCP-сокет
			// и буферы gorilla/websocket останутся жить до GC.
			select {
			case <-t.done:
				_ = conn.Close()
				return errClosed
			default:
			}
			t.conn.Store(conn)
			// Повторная проверка: Close() мог сработать ровно между select'ом и
			// Store. В этом случае Close уже сделал Swap(nil) и вернулся, не зная
			// про нашу новую conn — забираем её обратно и закрываем сами.
			select {
			case <-t.done:
				if orphan := t.conn.Swap(nil); orphan != nil {
					_ = orphan.Close()
				}
				return errClosed
			default:
			}
			log.Printf("websocket: reconnected to %s", t.cfg.URL)
			return nil
		}

		log.Printf("websocket: reconnect failed: %v; retrying in %s", err, backoff)
		select {
		case <-t.done:
			return errClosed
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > t.cfg.ReconnectMax {
			backoff = t.cfg.ReconnectMax
		}
	}
}

// invalidateConn помечает conn как сломанное (closes it and clears t.conn).
// Безопасно вызывать при гонках: проверяет, что t.conn совпадает с broken.
func (t *WSClientTransport) invalidateConn(broken *websocket.Conn) {
	if t.conn.CompareAndSwap(broken, nil) {
		_ = broken.Close()
	}
}

// Write передаёт один VPN-пакет в батчер. Фактическая отправка по WebSocket
// выполняется при срабатывании окна склеивания или переполнении буфера.
//
// Для случая BatchCoalesceWindow < 0 батчер отключён, и Write отправляет пакет
// сразу одним WS-сообщением (length-prefix-framing сохраняется ради
// совместимости формата).
//
// Ошибки сети обрабатываются в flushBatch (соединение помечается сломанным,
// Read-горутина переподключит транспорт). VPN-пакет в этот момент «теряется»,
// но TCP внутри туннеля сам перешлёт.
func (t *WSClientTransport) Write(data []byte) (int, error) {
	select {
	case <-t.done:
		return 0, errClosed
	default:
	}

	if t.batcher != nil {
		if err := t.batcher.Add(data); err != nil {
			return 0, err
		}
		return len(data), nil
	}

	// Батчинг отключён — отправляем один пакет в своём WS-сообщении (но всё
	// равно с length-prefix-framing'ом, чтобы приёмная сторона ожидала единый формат).
	frame, err := AppendFrame(nil, data)
	if err != nil {
		return 0, err
	}
	t.flushBatch(frame)
	return len(data), nil
}

// flushBatch вызывается батчером при готовности батча. Пишет пакет одним
// бинарным WS-сообщением. Активная синхронизация с reconnect/Close идёт
// через writeMu и atomic conn.
func (t *WSClientTransport) flushBatch(payload []byte) {
	if len(payload) == 0 {
		return
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	select {
	case <-t.done:
		return
	default:
	}

	conn := t.conn.Load()
	if conn == nil {
		// Переподключаемся — молча дропаем батч.
		return
	}

	if t.cfg.WriteTimeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(t.cfg.WriteTimeout))
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		if t.reconnectEnabled {
			if t.cfg.Verbose {
				log.Printf("websocket: write error: %v; will reconnect on next read", err)
			}
			t.invalidateConn(conn)
		}
	}
}

// Read блокируется до получения следующего VPN-пакета и копирует его в buf.
// Возвращает количество записанных в buf байт.
//
// Одно WebSocket-сообщение может содержать несколько сбатченных VPN-пакетов;
// Read отдаёт их по одному на вызов, остальные хранятся в t.pending.
//
// При reconnectEnabled=true ошибки сети не возвращаются наверх: транспорт
// автоматически переподключается с backoff'ом. Read возвращает ошибку только
// после Close().
func (t *WSClientTransport) Read(buf []byte) (int, error) {
	for {
		select {
		case <-t.done:
			return 0, errClosed
		default:
		}

		// Сначала отдаём ожидающие пакеты из разобранного предыдущего батча.
		t.readMu.Lock()
		if len(t.pending) > 0 {
			frame := t.pending[0]
			t.pending = t.pending[1:]
			t.readMu.Unlock()
			if len(frame) > len(buf) {
				return 0, fmt.Errorf("websocket buffer too small: got %d bytes, buffer is %d", len(frame), len(buf))
			}
			return copy(buf, frame), nil
		}
		t.readMu.Unlock()

		conn := t.conn.Load()
		if conn == nil {
			if !t.reconnectEnabled {
				return 0, errors.New("websocket not connected")
			}
			if err := t.reconnect(nil); err != nil {
				return 0, err
			}
			continue
		}

		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			select {
			case <-t.done:
				return 0, errClosed
			default:
			}
			if !t.reconnectEnabled {
				return 0, err
			}
			log.Printf("websocket: read error: %v; reconnecting", err)
			if err := t.reconnect(conn); err != nil {
				return 0, err
			}
			continue
		}
		if msgType != websocket.BinaryMessage {
			// текстовые сообщения игнорируем — VPN использует только бинарный канал
			continue
		}

		// Разбираем батч на отдельные VPN-пакеты. gorilla переиспользует payload
		// между вызовами ReadMessage, поэтому каждый пакет копируем.
		var frames [][]byte
		if err := IterateFrames(payload, func(p []byte) error {
			frames = append(frames, append([]byte(nil), p...))
			return nil
		}); err != nil {
			log.Printf("websocket: malformed batch: %v; %d bytes dropped", err, len(payload))
			continue
		}
		if len(frames) == 0 {
			continue
		}

		t.readMu.Lock()
		t.pending = append(t.pending, frames...)
		t.readMu.Unlock()
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
			conn := t.conn.Load()
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
				if t.cfg.Verbose {
					log.Printf("websocket: ping error: %v", err)
				}
				if t.reconnectEnabled {
					t.invalidateConn(conn)
				}
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

	// Останавливаем батчер — не флашим накопленное: соединение всё равно закрываем.
	if t.batcher != nil {
		t.batcher.Close()
	}

	conn := t.conn.Swap(nil)

	if conn != nil {
		// Best effort: посылаем close-фрейм и закрываем сокет.
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
