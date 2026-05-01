//go:build windows

package client

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"

	"myvpn/internal"
)

// configureInterface настраивает IP-адрес и MTU Wintun-адаптера через netsh.
func configureInterface(name, clientIP string) error {
	if err := runNetsh(
		"interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", name),
		"static", clientIP, "255.255.255.0",
	); err != nil {
		return fmt.Errorf("set IP %s: %w", clientIP, err)
	}
	if err := runNetsh(
		"interface", "ipv4", "set", "subinterface",
		name,
		fmt.Sprintf("mtu=%d", internal.TUNMTU),
		"store=active",
	); err != nil {
		// MTU не критичен — логируем, но не падаем.
		log.Printf("warning: failed to set MTU on %s: %v", name, err)
	}
	return nil
}

// runNetsh запускает netsh.exe с переданными аргументами.
func runNetsh(args ...string) error {
	out, err := exec.Command("netsh.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %w (output: %s)",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// isClosedErr — Wintun после Close возвращает ERROR_HANDLE_EOF /
// ERROR_INVALID_DATA. Сводим всё это к io.EOF в верхнем слое.
func isClosedErr(err error) bool {
	if errors.Is(err, windows.ERROR_HANDLE_EOF) ||
		errors.Is(err, windows.ERROR_NO_MORE_ITEMS) ||
		errors.Is(err, windows.ERROR_INVALID_DATA) {
		return true
	}
	return false
}
