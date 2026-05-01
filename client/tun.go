//go:build linux

package client

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"myvpn/internal"
)

const (
	// TUNInterfaceName имя TUN интерфейса на клиенте
	TUNInterfaceName = "myvpn0"
)

// TUN представляет TUN интерфейс на клиенте
type TUN struct {
	file *os.File
	name string
}

// NewTUN создает новый TUN интерфейс на клиенте
func NewTUN(name string, clientIP string) (*TUN, error) {
	// Открываем файл устройства TUN
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open TUN device: %w", err)
	}

	// Настраиваем TUN интерфейс
	ifreq, err := createInterfaceRequest(name)
	if err != nil {
		file.Close()
		return nil, err
	}

	// Выполняем ioctl для создания интерфейса
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		file.Fd(),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifreq[0])),
	)

	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("failed to create TUN interface: %v", errno)
	}

	// Получаем реальное имя интерфейса
	actualName := getInterfaceName(ifreq)

	tun := &TUN{
		file: file,
		name: actualName,
	}

	// Настраиваем интерфейс
	if err := tun.setup(clientIP); err != nil {
		tun.Close()
		return nil, fmt.Errorf("failed to setup TUN interface: %w", err)
	}

	return tun, nil
}

// createInterfaceRequest создает структуру ifreq для ioctl
func createInterfaceRequest(name string) ([unix.IFNAMSIZ + 64]byte, error) {
	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], name)
	// Устанавливаем флаг IFF_TUN (без IFF_NO_PI для получения чистых IP пакетов)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = unix.IFF_TUN | unix.IFF_NO_PI
	return ifr, nil
}

// getInterfaceName извлекает имя интерфейса из ifreq
func getInterfaceName(ifr [unix.IFNAMSIZ + 64]byte) string {
	// Имя интерфейса находится в первых IFNAMSIZ байтах
	name := make([]byte, 0, unix.IFNAMSIZ)
	for i := 0; i < unix.IFNAMSIZ; i++ {
		if ifr[i] == 0 {
			break
		}
		name = append(name, ifr[i])
	}
	return string(name)
}

// setup настраивает TUN интерфейс (IP адрес, MTU, поднимает интерфейс)
func (t *TUN) setup(clientIP string) error {
	// Настраиваем IP адрес интерфейса
	cmd := exec.Command("ip", "addr", "add", clientIP+"/24", "dev", t.name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP address: %w", err)
	}

	// Устанавливаем MTU
	cmd = exec.Command("ip", "link", "set", "dev", t.name, "mtu", fmt.Sprintf("%d", internal.TUNMTU))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	// Поднимаем интерфейс
	cmd = exec.Command("ip", "link", "set", "dev", t.name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	return nil
}

// Read читает IP пакет из TUN интерфейса
func (t *TUN) Read(packet []byte) (int, error) {
	return t.file.Read(packet)
}

// Write записывает IP пакет в TUN интерфейс
func (t *TUN) Write(packet []byte) (int, error) {
	return t.file.Write(packet)
}

// Name возвращает имя интерфейса
func (t *TUN) Name() string {
	return t.name
}

// Close закрывает TUN интерфейс
func (t *TUN) Close() error {
	if t.file != nil {
		return t.file.Close()
	}
	return nil
}

// File возвращает файловый дескриптор для использования в select/poll
func (t *TUN) File() *os.File {
	return t.file
}
