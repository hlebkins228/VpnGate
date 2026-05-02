//go:build linux

package server

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"

	"myvpn/internal"
)

// TUNInterfaceName имя TUN-интерфейса VPN-сервера.
const TUNInterfaceName = "myvpn0"

// TUN — обёртка над tun.Device из библиотеки WireGuard.
//
// На Linux использует /dev/net/tun (тот же путь, что и любой другой VPN-софт),
// но без ручных ioctl: вся низкоуровневая работа делегирована
// golang.zx2c4.com/wireguard/tun.
//
// rdScratch и wrScratch — внутренние буферы с резервом internal.TUNOffset
// байт перед пакетом. Это требование tun.Device на Linux (см. TUNOffset).
// Read/Write сериализуются на уровне вызывающей логики (по одной горутине
// на направление), поэтому защищать буферы мьютексом не нужно.
type TUN struct {
	dev      tun.Device
	name     string
	rdScratch []byte
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

	return &TUN{
		dev:       dev,
		name:      actualName,
		rdScratch: make([]byte, internal.TUNOffset+internal.TUNMTU),
		wrScratch: make([]byte, internal.TUNOffset+internal.TUNMTU),
	}, nil
}

// Read читает один IP-пакет.
func (t *TUN) Read(buf []byte) (int, error) {
	bufs := [][]byte{t.rdScratch}
	sizes := []int{0}
	n, err := t.dev.Read(bufs, sizes, internal.TUNOffset)
	if err != nil {
		// При закрытии возвращаем io.EOF, чтобы цикл чтения вышел тихо.
		if errors.Is(err, fs.ErrClosed) {
			return 0, io.EOF
		}
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	size := sizes[0]
	if size > len(buf) {
		return 0, fmt.Errorf("packet of %d bytes does not fit into %d-byte buffer", size, len(buf))
	}
	copy(buf, t.rdScratch[internal.TUNOffset:internal.TUNOffset+size])
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
