package client

import (
	"errors"
	"fmt"
	"io"
	"log"

	"golang.zx2c4.com/wireguard/tun"

	"myvpn/internal"
)

// TUNInterfaceName имя TUN-интерфейса по умолчанию.
//
// На Linux это будет имя устройства в /sys/class/net/, на Windows — имя
// Wintun-адаптера, видимое в "Network Connections".
const TUNInterfaceName = "myvpn0"

// TUN — кросс-платформенная обёртка над tun.Device из библиотеки WireGuard.
//
// Внутри использует:
//   - на Linux: /dev/net/tun (стандартный механизм TUN/TAP);
//   - на Windows: драйвер Wintun (требуется wintun.dll).
//
// Снаружи предоставляет привычный пакетно-ориентированный Read/Write API
// без батчинга — батчинг WireGuard-а здесь не нужен наружу, потому что
// далее трафик уходит в один WebSocket. Однако ВНУТРИ Read мы ВЫНУЖДЕНЫ
// делать батчевые вызовы tun.Device.Read: на Linux ядро может прислать
// "super-packet" (TSO/GRO offload), который библиотека режет на N
// MTU-сегментов и складывает в outBuffs. Если outBuffs всего один, при
// первом же TCP/UDP-флоу вылетает tun.ErrTooManySegments и читалка
// останавливается. Поэтому мы выделяем batchSize слотов и отдаём сегменты
// наружу по одному из последовательных Read'ов.
//
// rdBufs — буферы с резервом internal.TUNOffset байт перед пакетом
// (требование tun.Device на Linux с IFF_VNET_HDR; см. internal.TUNOffset).
// Read и Write вызываются из разных горутин, поэтому буфера не пересекаются
// и мьютекс не нужен.
type TUN struct {
	dev  tun.Device
	name string

	// rdBufs — слоты для tun.Device.Read; rdSizes — соответствующие размеры.
	// rdAvail — сколько слотов из rdBufs[0:rdAvail] прочитал последний
	// dev.Read; rdNext — индекс следующего сегмента, который вернёт Read.
	rdBufs  [][]byte
	rdSizes []int
	rdAvail int
	rdNext  int

	wrScratch []byte
}

// NewTUN создаёт TUN-интерфейс с заданным именем и IP/маской.
//
// Под Linux требуется CAP_NET_ADMIN (обычно — root). Под Windows требуется
// административный доступ и wintun.dll, лежащая рядом с .exe или в System32.
func NewTUN(name, clientIP string) (*TUN, error) {
	if name == "" {
		name = TUNInterfaceName
	}
	dev, err := tun.CreateTUN(name, internal.TUNMTU)
	if err != nil {
		return nil, fmt.Errorf("create TUN %q: %w", name, err)
	}

	// На Linux имя могло быть изменено ядром (например при коллизии).
	actualName, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("get TUN name: %w", err)
	}

	batchSize := dev.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}
	rdBufs := make([][]byte, batchSize)
	for i := range rdBufs {
		rdBufs[i] = make([]byte, internal.TUNOffset+internal.TUNMTU)
	}

	t := &TUN{
		dev:       dev,
		name:      actualName,
		rdBufs:    rdBufs,
		rdSizes:   make([]int, batchSize),
		wrScratch: make([]byte, internal.TUNOffset+internal.TUNMTU),
	}

	if err := configureInterface(t, clientIP); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("configure %q: %w", actualName, err)
	}

	return t, nil
}

// Read читает один IP-пакет из TUN-интерфейса. Блокируется до появления
// данных или закрытия. После Close возвращает io.EOF.
//
// Если последний батчевый Read вернул несколько сегментов (TSO/GRO super-
// packet, разбитый библиотекой), эта функция отдаёт их по одному; сетевой
// dev.Read будет повторно вызван, только когда очередь сегментов опустеет.
func (t *TUN) Read(buf []byte) (int, error) {
	if t.rdNext >= t.rdAvail {
		n, err := t.dev.Read(t.rdBufs, t.rdSizes, internal.TUNOffset)
		if err != nil {
			// ErrTooManySegments — рекомендуется не прекращать чтение
			// (см. wireguard/tun/errors.go). Сегменты, которые УСПЕЛИ
			// поместиться в наши буфера, всё ещё валидны и доступны
			// в rdBufs[0:n]; обработаем их и пойдём дальше.
			if errors.Is(err, tun.ErrTooManySegments) {
				log.Printf("TUN: dropped TSO/GRO super-packet (got %d segments, batch=%d)",
					n, len(t.rdBufs))
				if n <= 0 {
					return 0, nil
				}
				// fallthrough: отдадим n сегментов по одному.
			} else if isClosedErr(err) {
				return 0, io.EOF
			} else {
				return 0, err
			}
		}
		if n <= 0 {
			return 0, nil
		}
		t.rdAvail = n
		t.rdNext = 0
	}

	idx := t.rdNext
	t.rdNext++
	size := t.rdSizes[idx]
	if size <= 0 {
		return 0, nil
	}
	if size > len(buf) {
		return 0, fmt.Errorf("packet of %d bytes does not fit into %d-byte buffer", size, len(buf))
	}
	copy(buf, t.rdBufs[idx][internal.TUNOffset:internal.TUNOffset+size])
	return size, nil
}

// Write отправляет один IP-пакет в TUN-интерфейс.
func (t *TUN) Write(packet []byte) (int, error) {
	if len(packet) == 0 {
		return 0, nil
	}
	need := internal.TUNOffset + len(packet)
	if cap(t.wrScratch) < need {
		t.wrScratch = make([]byte, need)
	} else {
		t.wrScratch = t.wrScratch[:need]
	}
	// Обнуляем зону virtio_net_hdr, чтобы туда не попадали остатки от
	// предыдущих записей разной длины.
	for i := 0; i < internal.TUNOffset; i++ {
		t.wrScratch[i] = 0
	}
	copy(t.wrScratch[internal.TUNOffset:], packet)
	bufs := [][]byte{t.wrScratch}
	if _, err := t.dev.Write(bufs, internal.TUNOffset); err != nil {
		return 0, err
	}
	return len(packet), nil
}

// Name возвращает фактическое имя интерфейса.
func (t *TUN) Name() string { return t.name }

// Close закрывает TUN-интерфейс и освобождает связанные ресурсы.
func (t *TUN) Close() error { return t.dev.Close() }
