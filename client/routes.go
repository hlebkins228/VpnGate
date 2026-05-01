//go:build linux

package client

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// RouteManager управляет маршрутизацией через VPN
type RouteManager struct {
	tunInterface string
	serverIP     string
	oldGateway   string
	oldInterface string
	routesAdded  []string
}

// NewRouteManager создает новый менеджер маршрутов
func NewRouteManager(tunInterface, serverAddr string) (*RouteManager, error) {
	// Извлекаем IP адрес сервера из адреса
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		// Если нет порта, возможно это просто IP
		host = serverAddr
	}

	// Разрешаем IP адрес если это доменное имя
	serverIP, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server address: %w", err)
	}

	return &RouteManager{
		tunInterface: tunInterface,
		serverIP:     serverIP.IP.String(),
		routesAdded:  make([]string, 0),
	}, nil
}

// SetupRoutes настраивает маршрутизацию всего трафика через VPN
func (rm *RouteManager) SetupRoutes() error {
	// Получаем текущий default route
	if err := rm.getCurrentDefaultRoute(); err != nil {
		return fmt.Errorf("failed to get current default route: %w", err)
	}

	// Добавляем маршрут к VPN серверу через старый шлюз
	// Это важно чтобы не потерять соединение с VPN после смены default route
	serverRoute := fmt.Sprintf("%s via %s dev %s", rm.serverIP, rm.oldGateway, rm.oldInterface)
	if err := rm.addRoute(serverRoute); err != nil {
		return fmt.Errorf("failed to add server route: %w", err)
	}
	rm.routesAdded = append(rm.routesAdded, serverRoute)

	// Удаляем старый default route
	if err := rm.deleteRoute("default"); err != nil {
		// Игнорируем ошибку если маршрута нет
	}

	// Добавляем новый default route через VPN
	defaultRoute := fmt.Sprintf("default dev %s", rm.tunInterface)
	if err := rm.addRoute(defaultRoute); err != nil {
		return fmt.Errorf("failed to add default route: %w", err)
	}
	rm.routesAdded = append(rm.routesAdded, defaultRoute)

	return nil
}

// RestoreRoutes восстанавливает старые маршруты
func (rm *RouteManager) RestoreRoutes() error {
	var errs []error

	// Удаляем все добавленные маршруты в обратном порядке
	for i := len(rm.routesAdded) - 1; i >= 0; i-- {
		if err := rm.deleteRoute(rm.routesAdded[i]); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete route %s: %w", rm.routesAdded[i], err))
		}
	}

	// Восстанавливаем старый default route если он был
	if rm.oldInterface != "" {
		var oldDefaultRoute string
		if rm.oldGateway != "" {
			oldDefaultRoute = fmt.Sprintf("default via %s dev %s", rm.oldGateway, rm.oldInterface)
		} else {
			oldDefaultRoute = fmt.Sprintf("default dev %s", rm.oldInterface)
		}
		if err := rm.addRoute(oldDefaultRoute); err != nil {
			errs = append(errs, fmt.Errorf("failed to restore default route: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors restoring routes: %v", errs)
	}

	return nil
}

// getCurrentDefaultRoute получает текущий default route
func (rm *RouteManager) getCurrentDefaultRoute() error {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return fmt.Errorf("no default route found")
	}

	// Парсим строку вида "default via 192.168.1.1 dev eth0"
	parts := strings.Fields(lines[0])
	for i, part := range parts {
		if part == "via" && i+1 < len(parts) {
			rm.oldGateway = parts[i+1]
		}
		if part == "dev" && i+1 < len(parts) {
			rm.oldInterface = parts[i+1]
		}
	}

	if rm.oldGateway == "" || rm.oldInterface == "" {
		return fmt.Errorf("failed to parse default route: %s", lines[0])
	}

	return nil
}

// addRoute добавляет маршрут
func (rm *RouteManager) addRoute(route string) error {
	parts := strings.Fields(route)
	cmd := exec.Command("ip", append([]string{"route", "add"}, parts...)...)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Игнорируем ошибку "File exists" - маршрут уже существует
		if !strings.Contains(string(output), "File exists") {
			return fmt.Errorf("failed to add route %s: %w (output: %s)", route, err, string(output))
		}
	}
	return nil
}

// deleteRoute удаляет маршрут
func (rm *RouteManager) deleteRoute(route string) error {
	parts := strings.Fields(route)
	cmd := exec.Command("ip", append([]string{"route", "del"}, parts...)...)
	if err := cmd.Run(); err != nil {
		// Игнорируем ошибку если маршрута нет
		return nil
	}
	return nil
}
