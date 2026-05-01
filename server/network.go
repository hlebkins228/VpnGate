//go:build linux

package server

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

const (
	// VPNNetwork VPN подсеть
	VPNNetwork = "10.0.0.0/24"
)

// NetworkManager управляет сетевыми настройками сервера
type NetworkManager struct {
	tunInterface      string
	externalInterface string
	vpnNetwork        string
	ipForwardingWasOn bool
	rulesAdded        []iptablesRule
}

type iptablesRule struct {
	table string
	chain string
	args  []string
}

// NewNetworkManager создает новый менеджер сетевых настроек
func NewNetworkManager(tunInterface string) (*NetworkManager, error) {
	// Определяем внешний интерфейс
	externalIF, err := getExternalInterface()
	if err != nil {
		return nil, fmt.Errorf("failed to get external interface: %w", err)
	}

	return &NetworkManager{
		tunInterface:      tunInterface,
		externalInterface: externalIF,
		vpnNetwork:        VPNNetwork,
		rulesAdded:        make([]iptablesRule, 0),
	}, nil
}

// Setup настраивает IP forwarding, NAT и firewall правила
func (nm *NetworkManager) Setup() error {
	// 1. Включаем IP forwarding
	if err := nm.enableIPForwarding(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// 2. Настраиваем NAT (MASQUERADE)
	if err := nm.setupNAT(); err != nil {
		return fmt.Errorf("failed to setup NAT: %w", err)
	}

	// 3. Настраиваем FORWARD правила
	if err := nm.setupForwardRules(); err != nil {
		return fmt.Errorf("failed to setup forward rules: %w", err)
	}

	log.Printf("✓ Network configured: IP forwarding enabled, NAT via %s", nm.externalInterface)
	return nil
}

// Cleanup восстанавливает сетевые настройки
func (nm *NetworkManager) Cleanup() error {
	var errs []error

	// Удаляем добавленные правила в обратном порядке
	for i := len(nm.rulesAdded) - 1; i >= 0; i-- {
		rule := nm.rulesAdded[i]
		if err := nm.deleteIptablesRule(rule); err != nil {
			errs = append(errs, err)
		}
	}

	// Восстанавливаем IP forwarding если был выключен
	if !nm.ipForwardingWasOn {
		if err := nm.disableIPForwarding(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during cleanup: %v", errs)
	}

	log.Println("✓ Network settings restored")
	return nil
}

// enableIPForwarding включает IP forwarding
func (nm *NetworkManager) enableIPForwarding() error {
	// Проверяем текущее состояние
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return err
	}

	currentValue := strings.TrimSpace(string(data))
	nm.ipForwardingWasOn = currentValue == "1"

	if nm.ipForwardingWasOn {
		log.Println("✓ IP forwarding already enabled")
		return nil
	}

	// Включаем IP forwarding
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return err
	}

	log.Println("✓ IP forwarding enabled")
	return nil
}

// disableIPForwarding выключает IP forwarding
func (nm *NetworkManager) disableIPForwarding() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0"), 0644); err != nil {
		return err
	}
	log.Println("✓ IP forwarding disabled")
	return nil
}

// setupNAT настраивает NAT (MASQUERADE)
func (nm *NetworkManager) setupNAT() error {
	rule := iptablesRule{
		table: "nat",
		chain: "POSTROUTING",
		args:  []string{"-s", nm.vpnNetwork, "-o", nm.externalInterface, "-j", "MASQUERADE"},
	}

	// Проверяем, существует ли уже правило
	if nm.iptablesRuleExists(rule) {
		log.Println("✓ NAT rule already exists")
		return nil
	}

	// Добавляем правило
	if err := nm.addIptablesRule(rule); err != nil {
		return err
	}

	nm.rulesAdded = append(nm.rulesAdded, rule)
	log.Println("✓ NAT rule added")
	return nil
}

// setupForwardRules настраивает FORWARD правила
func (nm *NetworkManager) setupForwardRules() error {
	// Правило для исходящего трафика из VPN
	outRule := iptablesRule{
		table: "filter",
		chain: "FORWARD",
		args:  []string{"-s", nm.vpnNetwork, "-j", "ACCEPT"},
	}

	if !nm.iptablesRuleExists(outRule) {
		if err := nm.insertIptablesRule(outRule); err != nil {
			return err
		}
		nm.rulesAdded = append(nm.rulesAdded, outRule)
		log.Println("✓ FORWARD rule (outgoing) added")
	} else {
		log.Println("✓ FORWARD rule (outgoing) already exists")
	}

	// Правило для входящего трафика в VPN
	inRule := iptablesRule{
		table: "filter",
		chain: "FORWARD",
		args:  []string{"-d", nm.vpnNetwork, "-j", "ACCEPT"},
	}

	if !nm.iptablesRuleExists(inRule) {
		if err := nm.insertIptablesRule(inRule); err != nil {
			return err
		}
		nm.rulesAdded = append(nm.rulesAdded, inRule)
		log.Println("✓ FORWARD rule (incoming) added")
	} else {
		log.Println("✓ FORWARD rule (incoming) already exists")
	}

	return nil
}

// iptablesRuleExists проверяет существование правила
func (nm *NetworkManager) iptablesRuleExists(rule iptablesRule) bool {
	args := []string{"-t", rule.table, "-C", rule.chain}
	args = append(args, rule.args...)

	cmd := exec.Command("iptables", args...)
	return cmd.Run() == nil
}

// addIptablesRule добавляет правило iptables (в конец цепочки)
func (nm *NetworkManager) addIptablesRule(rule iptablesRule) error {
	args := []string{"-t", rule.table, "-A", rule.chain}
	args = append(args, rule.args...)

	cmd := exec.Command("iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables error: %s", string(output))
	}
	return nil
}

// insertIptablesRule вставляет правило iptables (в начало цепочки)
func (nm *NetworkManager) insertIptablesRule(rule iptablesRule) error {
	args := []string{"-t", rule.table, "-I", rule.chain}
	args = append(args, rule.args...)

	cmd := exec.Command("iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables error: %s", string(output))
	}
	return nil
}

// deleteIptablesRule удаляет правило iptables
func (nm *NetworkManager) deleteIptablesRule(rule iptablesRule) error {
	args := []string{"-t", rule.table, "-D", rule.chain}
	args = append(args, rule.args...)

	cmd := exec.Command("iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Игнорируем ошибки если правило не существует
		if !strings.Contains(string(output), "does a matching rule exist") {
			return fmt.Errorf("iptables delete error: %s", string(output))
		}
	}
	return nil
}

// getExternalInterface определяет внешний интерфейс
func getExternalInterface() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return "", fmt.Errorf("no default route found")
	}

	// Парсим строку вида "default via 192.168.1.1 dev eth0"
	parts := strings.Fields(lines[0])
	for i, part := range parts {
		if part == "dev" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}

	return "", fmt.Errorf("failed to parse default route: %s", lines[0])
}
