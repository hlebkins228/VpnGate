//go:build linux

package server

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"

	"myvpn/internal"
)

// TUNInterfaceName имя TUN-интерфейса VPN-сервера.
const TUNInterfaceName = "myvpn0"

// TUN — обёртка над tun.Device из библиотеки WireGuard.
//
// Использует /dev/net/tun (тот же путь, что любой другой VPN-софт),
// но без ручных ioctl: вся низкоуровневая работа делегирована
// golang.zx2c4.com/wireguard/tun.
//
// rdBufs — внутренние батчевые буфера: на Linux с включённым TSO/GRO
// offload ядро может прислать один "super-packet" (до 64 КБ), который
// библиотека сегментирует на N MTU-сегментов и складывает в bufs[0:n].
// Если bufs всего один — при первом же реальном TCP-флоу выпадет
// tun.ErrTooManySegments и читалка завершится. Выделяем сразу
// dev.BatchSize() слотов (на Linux обычно 128) и отдаём пакеты наружу
// по одному из rdBufs.
//
// Read и Write сериализуются на уровне вызывающей логики (по одной
// горутине на направление), поэтому защищать буфера мьютексом не нужно.
type TUN struct {
	dev  tun.Device
	name string

	rdBufs  [][]byte
	rdSizes []int
	rdAvail int
	rdNext  int

	wrScratch []byte
}

// NewTUN создаёт TUN-интерфейс с заданным именем и поднимает его с адресом
// 10.0.0.1/24. Требует CAP_NET_ADMIN (обычно — root).
func NewTUN(name string) (*TUN, error) {
	if name == "" {
		name = TUNInterfaceName
	}
	dev, err := tun.CreateTUN(name, internal.TUNMTU)
	if err != nil {
		return nil, fmt.Errorf("create TUN %q: %w", name, err)
	}

	actualName, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("get TUN name: %w", err)
	}

	if err := setupServerInterface(actualName); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("setup %q: %w", actualName, err)
	}

	batchSize := dev.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}
	rdBufs := make([][]byte, batchSize)
	for i := range rdBufs {
		rdBufs[i] = make([]byte, internal.TUNOffset+internal.TUNMTU)
	}

	return &TUN{
		dev:       dev,
		name:      actualName,
		rdBufs:    rdBufs,
		rdSizes:   make([]int, batchSize),
		wrScratch: make([]byte, internal.TUNOffset+internal.TUNMTU),
	}, nil
}

// Read возвращает один IP-пакет. Если предыдущий батчевый dev.Read получил
// несколько сегментов, отдаёт их последовательно из внутренней очереди и
// только после её исчерпания снова идёт в ядро.
func (t *TUN) Read(buf []byte) (int, error) {
	if t.rdNext >= t.rdAvail {
		n, err := t.dev.Read(t.rdBufs, t.rdSizes, internal.TUNOffset)
		if err != nil {
			// ErrTooManySegments — рекомендация библиотеки: читалку не
			// останавливать (см. wireguard/tun/errors.go). Сегменты, которые
			// УСПЕЛИ влезть в наши буфера, валидны и доступны в bufs[0:n].
			if errors.Is(err, tun.ErrTooManySegments) {
				log.Printf("TUN: dropped TSO/GRO super-packet (got %d segments, batch=%d)",
					n, len(t.rdBufs))
				if n <= 0 {
					return 0, nil
				}
				// fallthrough: отдадим n сегментов по одному.
			} else if errors.Is(err, fs.ErrClosed) {
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

// Write отправляет один IP-пакет.
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
	// Обнуляем зону virtio_net_hdr, чтобы в неё не попадали остатки от
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

// Name возвращает имя интерфейса (может отличаться от запрошенного, если
// ядро Linux переименовало).
func (t *TUN) Name() string { return t.name }

// Close освобождает ресурсы. После Close любой Read возвращает io.EOF.
func (t *TUN) Close() error { return t.dev.Close() }

// setupServerInterface назначает 10.0.0.1/24, ставит MTU и поднимает интерфейс.
func setupServerInterface(name string) error {
	if err := runIP("addr", "add", "10.0.0.1/24", "dev", name); err != nil {
		return fmt.Errorf("set IP: %w", err)
	}
	if err := runIP("link", "set", "dev", name, "mtu", fmt.Sprintf("%d", internal.TUNMTU)); err != nil {
		return fmt.Errorf("set MTU: %w", err)
	}
	if err := runIP("link", "set", "dev", name, "up"); err != nil {
		return fmt.Errorf("bring up: %w", err)
	}
	return nil
}

func runIP(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v: %w (output: %s)", args, err, out)
	}
	return nil
}
