package client

import (
	"errors"
	"fmt"
	"io"

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
// без батчинга — батчинг WireGuard-а здесь не нужен, потому что трафик
// далее уходит в один WebSocket.
type TUN struct {
	dev  tun.Device
	name string
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

	if err := configureInterface(actualName, clientIP); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("configure %q: %w", actualName, err)
	}

	return &TUN{dev: dev, name: actualName}, nil
}

// Read читает один IP-пакет из TUN-интерфейса. Блокируется до появления
// данных или закрытия. После Close возвращает io.EOF.
func (t *TUN) Read(buf []byte) (int, error) {
	bufs := [][]byte{buf}
	sizes := []int{0}
	n, err := t.dev.Read(bufs, sizes, 0)
	if err != nil {
		if errors.Is(err, tun.ErrTooManySegments) {
			return 0, fmt.Errorf("tun read: %w", err)
		}
		// На закрытии Wintun возвращает специфические ошибки, нам они не важны
		// — сводим к io.EOF, чтобы клиент аккуратно завершил работу.
		if isClosedErr(err) {
			return 0, io.EOF
		}
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return sizes[0], nil
}

// Write отправляет один IP-пакет в TUN-интерфейс.
func (t *TUN) Write(packet []byte) (int, error) {
	if len(packet) == 0 {
		return 0, nil
	}
	bufs := [][]byte{packet}
	if _, err := t.dev.Write(bufs, 0); err != nil {
		return 0, err
	}
	return len(packet), nil
}

// Name возвращает фактическое имя интерфейса.
func (t *TUN) Name() string { return t.name }

// Close закрывает TUN-интерфейс и освобождает связанные ресурсы.
func (t *TUN) Close() error { return t.dev.Close() }
