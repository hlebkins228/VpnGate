package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Формат батча в одном WebSocket-сообщении:
//
//	[uint16 BE: len(pkt1)][pkt1 raw bytes][uint16 BE: len(pkt2)][pkt2 raw bytes]...
//
// Каждый pktN — уже закодированный VPN-пакет ([1 байт флаг сжатия][12 байт nonce][ChaCha20-Poly1305 ciphertext+tag]).
// Длина одного pktN ограничена 0xFFFF (65 535 байт) — далеко больше реального VPN-пакета (~1450 байт),
// но если пакет превышает лимит — он не попадает в батч (Add возвращает false).
//
// Батчинг сокращает количество вебхуков, которые Yandex API Gateway генерирует на бэкенд,
// и количество push-вызовов в Connection Management API. Yandex обрабатывает MESSAGE-вебхуки
// одного WS-соединения последовательно, поэтому максимальный темп обработки = 1/RTT
// сообщений в секунду. С батчингом N пакетов на сообщение получаем N×(1/RTT) пакетов в секунду.

const (
	// MaxBatchPayloadBytes максимальный размер одного WS-сообщения после батчинга.
	// Yandex API Gateway допускает 128 КБ на WS-сообщение, но Connection Management API
	// (push с сервера на клиента) — только 96 КБ. Берём 90 КБ с запасом, чтобы оставить
	// место под framing-overhead и не упереться в лимит из-за погрешности.
	MaxBatchPayloadBytes = 90 * 1024

	// MaxBatchEntryBytes максимальный размер одного пакета внутри батча
	// (задан 16-битным префиксом длины).
	MaxBatchEntryBytes = 0xFFFF

	// DefaultBatchCoalesceWindow время ожидания соседних пакетов перед принудительным flush'ом.
	// При характерных RTT клиент↔gateway↔сервер 30–60 мс это окно (≤ 5 мс) практически
	// не добавляет latency, но позволяет склеить десятки пакетов одного TCP-burst'а.
	DefaultBatchCoalesceWindow = 2 * time.Millisecond
)

// errBatchOverflow возвращается, если один пакет не помещается в один батч (превышает MaxBatchPayloadBytes-2).
var errBatchOverflow = errors.New("packet exceeds maximum batch payload size")

// AppendFrame добавляет один длино-префиксный фрейм к буферу dst и возвращает новый dst.
// Возвращает ошибку, если len(packet) выходит за разрешённые границы.
func AppendFrame(dst, packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return dst, errors.New("empty packet")
	}
	if len(packet) > MaxBatchEntryBytes {
		return dst, fmt.Errorf("packet too large for batch frame: %d > %d", len(packet), MaxBatchEntryBytes)
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(packet)))
	dst = append(dst, hdr[:]...)
	dst = append(dst, packet...)
	return dst, nil
}

// IterateFrames разбирает батч-пакет и вызывает fn для каждого пакета внутри.
// Возвращает ошибку при невалидном framing (обрезанный заголовок длины,
// заголовок указывает за пределы данных, лишние байты после последнего пакета).
//
// fn получает срез внутри data — если пакет должен жить дольше одного вызова,
// его нужно скопировать.
func IterateFrames(data []byte, fn func([]byte) error) error {
	for len(data) > 0 {
		if len(data) < 2 {
			return fmt.Errorf("truncated batch frame header: %d byte(s) remaining", len(data))
		}
		n := int(binary.BigEndian.Uint16(data[:2]))
		if n == 0 {
			return errors.New("zero-length frame in batch")
		}
		if 2+n > len(data) {
			return fmt.Errorf("truncated batch frame: header says %d, only %d byte(s) available", n, len(data)-2)
		}
		if err := fn(data[2 : 2+n]); err != nil {
			return err
		}
		data = data[2+n:]
	}
	return nil
}

// batchedWriter аккумулирует пакеты в один WS-фрейм и периодически вызывает flush.
//
// Безопасен для конкурентных вызовов Add из нескольких goroutine. flush вызывается
// без удержания внутреннего mutex'а, поэтому может выполнять блокирующие операции
// (сетевые записи, HTTP-запросы) без риска дедлоков.
type batchedWriter struct {
	mu             sync.Mutex
	buf            []byte
	timer          *time.Timer
	timerSet       bool
	closed         bool
	coalesceWindow time.Duration
	maxBytes       int
	flush          func([]byte) // вызывается без удержания mu
}

// newBatchedWriter создаёт writer.
//
// coalesceWindow ≤ 0 интерпретируется как "flush сразу" (без склеивания, для тестов или
// отладки). maxBytes ≤ 0 интерпретируется как MaxBatchPayloadBytes.
func newBatchedWriter(coalesceWindow time.Duration, maxBytes int, flush func([]byte)) *batchedWriter {
	if maxBytes <= 0 {
		maxBytes = MaxBatchPayloadBytes
	}
	return &batchedWriter{
		coalesceWindow: coalesceWindow,
		maxBytes:       maxBytes,
		flush:          flush,
	}
}

// Add добавляет пакет в батч. При необходимости (превышение лимита) сбрасывает
// текущий батч до добавления нового пакета. Возвращает ошибку, если пакет
// слишком большой для одного батча или writer уже закрыт.
func (b *batchedWriter) Add(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	if 2+len(packet) > b.maxBytes {
		return errBatchOverflow
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return errors.New("batched writer closed")
	}

	// Если новый пакет переполнит текущий буфер — сначала flush.
	if len(b.buf) > 0 && len(b.buf)+2+len(packet) > b.maxBytes {
		payload := b.buf
		b.buf = nil
		b.stopTimerLocked()
		b.mu.Unlock()
		b.flush(payload)
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			return errors.New("batched writer closed")
		}
	}

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(packet)))
	b.buf = append(b.buf, hdr[:]...)
	b.buf = append(b.buf, packet...)

	if b.coalesceWindow <= 0 {
		// Без окна склеивания — flush сразу.
		payload := b.buf
		b.buf = nil
		b.mu.Unlock()
		b.flush(payload)
		return nil
	}

	if !b.timerSet {
		b.timer = time.AfterFunc(b.coalesceWindow, b.onTimer)
		b.timerSet = true
	}
	b.mu.Unlock()
	return nil
}

// onTimer срабатывает по истечении окна склеивания.
func (b *batchedWriter) onTimer() {
	b.mu.Lock()
	if b.closed || len(b.buf) == 0 {
		b.timerSet = false
		b.mu.Unlock()
		return
	}
	payload := b.buf
	b.buf = nil
	b.timerSet = false
	b.mu.Unlock()
	b.flush(payload)
}

// Flush принудительно отправляет накопленный батч (если есть).
// Безопасно вызывать на закрытом writer'е (вернёт без действий).
func (b *batchedWriter) Flush() {
	b.mu.Lock()
	if len(b.buf) == 0 {
		b.stopTimerLocked()
		b.mu.Unlock()
		return
	}
	payload := b.buf
	b.buf = nil
	b.stopTimerLocked()
	b.mu.Unlock()
	b.flush(payload)
}

// Close останавливает таймер и сбрасывает буфер БЕЗ вызова flush.
//
// Используется при закрытии sink'а: накопленные VPN-пакеты в этот момент уже
// неактуальны (соединение разорвано или закрывается), а доставлять их через
// Connection API смысла нет — клиент их всё равно не получит. TCP внутри
// туннеля при необходимости повторит передачу при восстановлении соединения.
func (b *batchedWriter) Close() {
	b.mu.Lock()
	b.closed = true
	b.buf = nil
	b.stopTimerLocked()
	b.mu.Unlock()
}

func (b *batchedWriter) stopTimerLocked() {
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	b.timerSet = false
}
