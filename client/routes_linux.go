//go:build linux

package client

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// RouteManager перенаправляет весь трафик клиента в VPN.
//
// Алгоритм:
//  1. Запоминает текущий default route (`ip route show default`).
//  2. Добавляет host-маршрут к серверу через прежний шлюз (чтобы туннель сам
//     себя не перекрыл, когда default route переедет в TUN).
//  3. Удаляет старый default и добавляет новый через TUN-интерфейс.
//
// При RestoreRoutes маршруты возвращаются в исходное состояние.
type RouteManager struct {
	tunInterface string
	serverIP     string
	oldGateway   string
	oldInterface string
	routesAdded  []string
}

// NewRouteManager резолвит hostname сервера в IP и подготавливает менеджер.
func NewRouteManager(tunInterface, serverAddr string) (*RouteManager, error) {
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}
	addr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	return &RouteManager{tunInterface: tunInterface, serverIP: addr.IP.String()}, nil
}

// SetupRoutes перестраивает таблицу маршрутизации.
func (rm *RouteManager) SetupRoutes() error {
	if err := rm.readDefaultRoute(); err != nil {
		return fmt.Errorf("read default route: %w", err)
	}

	serverRoute := fmt.Sprintf("%s via %s dev %s", rm.serverIP, rm.oldGateway, rm.oldInterface)
	if err := rm.addRoute(serverRoute); err != nil {
		return fmt.Errorf("add server route: %w", err)
	}
	rm.routesAdded = append(rm.routesAdded, serverRoute)

	// Старый default удалить нужно до добавления нового, иначе ядро откажется
	// добавлять конфликтующий маршрут.
	_ = rm.deleteRoute("default")

	defaultRoute := fmt.Sprintf("default dev %s", rm.tunInterface)
	if err := rm.addRoute(defaultRoute); err != nil {
		return fmt.Errorf("add default route: %w", err)
	}
	rm.routesAdded = append(rm.routesAdded, defaultRoute)

	return nil
}

// RestoreRoutes возвращает таблицу маршрутизации в исходное состояние.
func (rm *RouteManager) RestoreRoutes() error {
	var errs []error
	for i := len(rm.routesAdded) - 1; i >= 0; i-- {
		if err := rm.deleteRoute(rm.routesAdded[i]); err != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", rm.routesAdded[i], err))
		}
	}
	rm.routesAdded = nil

	if rm.oldInterface != "" {
		var route string
		if rm.oldGateway != "" {
			route = fmt.Sprintf("default via %s dev %s", rm.oldGateway, rm.oldInterface)
		} else {
			route = fmt.Sprintf("default dev %s", rm.oldInterface)
		}
		if err := rm.addRoute(route); err != nil {
			errs = append(errs, fmt.Errorf("restore default route: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("restore routes: %v", errs)
	}
	return nil
}

func (rm *RouteManager) readDefaultRoute() error {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return fmt.Errorf("no default route found")
	}
	parts := strings.Fields(lines[0])
	for i, p := range parts {
		switch p {
		case "via":
			if i+1 < len(parts) {
				rm.oldGateway = parts[i+1]
			}
		case "dev":
			if i+1 < len(parts) {
				rm.oldInterface = parts[i+1]
			}
		}
	}
	if rm.oldInterface == "" {
		return fmt.Errorf("could not parse default route: %q", lines[0])
	}
	return nil
}

func (rm *RouteManager) addRoute(route string) error {
	out, err := exec.Command("ip", append([]string{"route", "add"}, strings.Fields(route)...)...).CombinedOutput()
	if err != nil {
		// Маршрут уже существует — это OK.
		if strings.Contains(string(out), "File exists") {
			return nil
		}
		return fmt.Errorf("ip route add %s: %w (output: %s)", route, err, out)
	}
	return nil
}

func (rm *RouteManager) deleteRoute(route string) error {
	if err := exec.Command("ip", append([]string{"route", "del"}, strings.Fields(route)...)...).Run(); err != nil {
		// Если маршрута нет, считаем это успехом.
		return nil
	}
	return nil
}
