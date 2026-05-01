//go:build linux

package client

import (
	"errors"
	"fmt"
	"io/fs"
	"os/exec"

	"myvpn/internal"
)

// configureInterface назначает Linux-TUN адресу маску /24, ставит MTU и поднимает интерфейс.
func configureInterface(name, clientIP string) error {
	if err := runIP("addr", "add", clientIP+"/24", "dev", name); err != nil {
		return fmt.Errorf("set IP %s: %w", clientIP, err)
	}
	if err := runIP("link", "set", "dev", name, "mtu", fmt.Sprintf("%d", internal.TUNMTU)); err != nil {
		return fmt.Errorf("set MTU: %w", err)
	}
	if err := runIP("link", "set", "dev", name, "up"); err != nil {
		return fmt.Errorf("bring %s up: %w", name, err)
	}
	return nil
}

// runIP запускает `ip <args...>`. Возвращает stderr+stdout в составе ошибки.
func runIP(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v: %w (output: %s)", args, err, out)
	}
	return nil
}

// isClosedErr — Linux TUN при Close возвращает обычный *fs.PathError (file
// already closed) либо io.EOF. На обоих случаях завершаем чтение тихо.
func isClosedErr(err error) bool {
	if errors.Is(err, fs.ErrClosed) {
		return true
	}
	return false
}
