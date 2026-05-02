//go:build windows

package client

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"myvpn/internal"
)

// configureInterface назначает Wintun-адаптеру IP и MTU через WinAPI
// (winipcfg). Подход тот же, что использует сам WireGuard: никаких
// внешних команд (netsh / route.exe) — все вызовы через GetIpInterfaceEntry,
// SetIpInterfaceEntry и CreateUnicastIpAddressEntry.
//
// Если netsh не успел "увидеть" свежесозданный Wintun-адаптер (бывает,
// драйвер ещё не до конца поднял интерфейс), то старая реализация молча
// возвращала "OK" и трафик не ходил. WinAPI делает это синхронно через LUID.
func configureInterface(t *TUN, clientIP string) error {
	luid := t.winLUID()
	if luid == 0 {
		return errors.New("could not obtain Wintun adapter LUID")
	}

	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return fmt.Errorf("parse client IP %q: %w", clientIP, err)
	}
	if !addr.Is4() {
		return fmt.Errorf("client IP must be IPv4: %q", clientIP)
	}
	prefix := netip.PrefixFrom(addr, 24)

	// Заменяем все ранее назначенные IPv4-адреса на адаптере на наш единственный.
	if err := luid.SetIPAddresses([]netip.Prefix{prefix}); err != nil {
		return fmt.Errorf("set IPv4 address %s: %w", prefix, err)
	}

	// MTU выставляем напрямую через MibIPInterfaceRow.NLMTU.
	row, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return fmt.Errorf("get IPv4 interface entry: %w", err)
	}
	row.NLMTU = uint32(internal.TUNMTU)
	// Метрика по умолчанию пусть остаётся "автоматическая" — split default
	// route и так выигрывает по длине префикса, а возиться с UseAutomaticMetric
	// руками это лишний риск.
	row.UseAutomaticMetric = true
	if err := row.Set(); err != nil {
		return fmt.Errorf("set IPv4 interface entry: %w", err)
	}

	// IPv6 на адаптере выключаем — мы по нему всё равно не проксируем.
	if row6, err := luid.IPInterface(windows.AF_INET6); err == nil {
		row6.NLMTU = uint32(internal.TUNMTU)
		_ = row6.Set()
	}

	return nil
}

// winLUID возвращает LUID Wintun-адаптера, к которому привязан t.dev.
// На любом другом backend-е tun.Device возвращается 0.
func (t *TUN) winLUID() winipcfg.LUID {
	nt, ok := t.dev.(*wgtun.NativeTun)
	if !ok {
		return 0
	}
	return winipcfg.LUID(nt.LUID())
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
