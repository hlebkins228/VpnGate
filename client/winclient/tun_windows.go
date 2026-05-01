//go:build windows

// Package winclient содержит реализацию VPN-клиента для Windows.
//
// На Windows нет /dev/net/tun, поэтому используется драйвер Wintun
// (https://www.wintun.net/) от проекта WireGuard. Сам Go-код общается
// с Wintun через wintun.dll, которую нужно положить рядом с .exe файлом.
package winclient

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const (
	// AdapterName имя сетевого адаптера, видимое в Windows.
	AdapterName = "MyVPN"
	// TunnelType тип Wintun-адаптера (для группировки в реестре).
	TunnelType = "MyVPN"
	// RingCapacity размер кольцевого буфера (8 МиБ).
	RingCapacity = 0x800000
)

// TUN обёртка над Wintun-адаптером с обычным Read/Write API.
type TUN struct {
	adapter   *wintun.Adapter
	session   wintun.Session
	readEvent windows.Handle // event, который Wintun сигналит при появлении пакетов
	closeEv   windows.Handle // event, который мы сами сигналим при Close()
	closed    atomic.Bool
	closeOnce sync.Once
	luid      uint64
}

// NewTUN создаёт новый Wintun-адаптер с заданным IP/маской.
//
// Adapter создаётся "с нуля" каждый раз; если адаптер с таким именем уже
// существует, он будет открыт повторно.
func NewTUN(name, clientIP string) (*TUN, error) {
	if name == "" {
		name = AdapterName
	}

	// Сначала пробуем открыть существующий адаптер (например, после рестарта),
	// если не получается — создаём новый.
	adapter, err := wintun.OpenAdapter(name)
	if err != nil {
		adapter, err = wintun.CreateAdapter(name, TunnelType, nil)
		if err != nil {
			return nil, fmt.Errorf("create wintun adapter %q: %w (is wintun.dll next to the binary?)", name, err)
		}
	}

	session, err := adapter.StartSession(RingCapacity)
	if err != nil {
		_ = adapter.Close()
		return nil, fmt.Errorf("start wintun session: %w", err)
	}

	closeEv, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		session.End()
		_ = adapter.Close()
		return nil, fmt.Errorf("create close event: %w", err)
	}

	t := &TUN{
		adapter:   adapter,
		session:   session,
		readEvent: session.ReadWaitEvent(),
		closeEv:   closeEv,
		luid:      adapter.LUID(),
	}

	if err := configureInterface(name, clientIP); err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("configure %q: %w", name, err)
	}

	return t, nil
}

// Read читает один IP-пакет из адаптера. Блокируется до появления данных
// или закрытия (Close возвращает io.EOF).
func (t *TUN) Read(buf []byte) (int, error) {
	for {
		if t.closed.Load() {
			return 0, errClosed
		}

		packet, err := t.session.ReceivePacket()
		if err == nil {
			n := copy(buf, packet)
			t.session.ReleaseReceivePacket(packet)
			return n, nil
		}

		// ERROR_NO_MORE_ITEMS = "буфер пока пуст, нужно подождать ивента"
		if !errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return 0, fmt.Errorf("wintun receive: %w", err)
		}

		// Ждём либо новых пакетов, либо сигнала закрытия.
		events := []windows.Handle{t.readEvent, t.closeEv}
		r, werr := windows.WaitForMultipleObjects(events, false, windows.INFINITE)
		if werr != nil {
			return 0, fmt.Errorf("wait for read event: %w", werr)
		}
		switch r {
		case windows.WAIT_OBJECT_0:
			// есть пакеты — повторяем приём
			continue
		case windows.WAIT_OBJECT_0 + 1:
			return 0, errClosed
		default:
			return 0, fmt.Errorf("unexpected wait result: 0x%x", r)
		}
	}
}

// Write отправляет один IP-пакет в адаптер.
func (t *TUN) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if t.closed.Load() {
		return 0, errClosed
	}
	packet, err := t.session.AllocateSendPacket(len(data))
	if err != nil {
		return 0, fmt.Errorf("wintun allocate: %w", err)
	}
	copy(packet, data)
	t.session.SendPacket(packet)
	return len(data), nil
}

// Name возвращает имя адаптера, под которым он виден в системе.
func (t *TUN) Name() string {
	return AdapterName
}

// LUID возвращает Windows-LUID адаптера (используется для управления маршрутами).
func (t *TUN) LUID() uint64 {
	return t.luid
}

// Close закрывает Wintun-сессию и удаляет адаптер.
func (t *TUN) Close() error {
	var firstErr error
	t.closeOnce.Do(func() {
		t.closed.Store(true)
		_ = windows.SetEvent(t.closeEv)
		t.session.End()
		if err := t.adapter.Close(); err != nil {
			firstErr = fmt.Errorf("close wintun adapter: %w", err)
		}
		_ = windows.CloseHandle(t.closeEv)
	})
	return firstErr
}

// errClosed возвращается из Read/Write после Close.
var errClosed = errors.New("wintun: adapter closed")
