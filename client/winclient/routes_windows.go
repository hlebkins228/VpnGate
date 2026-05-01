//go:build windows

package winclient

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strings"

	"myvpn/internal"
)

// configureInterface назначает Wintun-адаптеру статический IPv4 и MTU.
//
// Используется netsh, потому что он умеет дождаться, пока стек поднимет
// интерфейс, и сразу применить параметры (важно для свежесозданного Wintun).
func configureInterface(name, clientIP string) error {
	// netsh ожидает имя адаптера в кавычках, exec.Command экранирует сам.
	if err := runNetsh(
		"interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", name),
		"static",
		clientIP, "255.255.255.0",
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

// RouteManager управляет маршрутизацией всего трафика через VPN на Windows.
//
// Используется паттерн «split default route»:
//   - 0.0.0.0/1 → через TUN
//   - 128.0.0.0/1 → через TUN
//
// Это перекрывает весь IPv4-адресный простор по более длинным префиксам, чем
// исходный 0.0.0.0/0, поэтому Windows предпочтёт их без удаления оригинального
// дефолта. Плюс host-маршрут к API Gateway через старый шлюз, чтобы туннель
// сам себя не перекрыл.
type RouteManager struct {
	tunName     string // имя Wintun-адаптера (например MyVPN)
	tunGateway  string // gateway, через который маршрут пойдёт по TUN; адрес сервера в туннеле (10.0.0.1)
	serverIP    string // публичный IP API Gateway / сервера
	origGateway string // прежний дефолтный шлюз
	added       []routeRow
}

type routeRow struct {
	dest    string
	mask    string
	gateway string
}

// NewRouteManager разрешает hostname сервера в IP и подготавливает менеджер
// маршрутов. tunGateway — адрес, который выступает «шлюзом» внутри VPN
// (по соглашению — IP сервера в подсети туннеля, например 10.0.0.1).
func NewRouteManager(tunName, serverHost, tunGateway string) (*RouteManager, error) {
	if serverHost == "" {
		return nil, fmt.Errorf("server host is empty")
	}

	// Если передали host:port — отрезаем порт.
	host, _, err := net.SplitHostPort(serverHost)
	if err != nil {
		host = serverHost
	}

	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}

	// Берём первый IPv4 (Wintun настроен на v4).
	var serverIP string
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip != nil && ip.To4() != nil {
			serverIP = ip.String()
			break
		}
	}
	if serverIP == "" {
		return nil, fmt.Errorf("no IPv4 address for %q", host)
	}

	if tunGateway == "" {
		tunGateway = "10.0.0.1"
	}

	return &RouteManager{
		tunName:    tunName,
		tunGateway: tunGateway,
		serverIP:   serverIP,
	}, nil
}

// SetupRoutes добавляет маршруты для проксирования всего трафика через VPN.
func (rm *RouteManager) SetupRoutes() error {
	gw, err := defaultGateway()
	if err != nil {
		return fmt.Errorf("read default gateway: %w", err)
	}
	rm.origGateway = gw

	// Сначала host-маршрут к серверу через старый шлюз.
	host := routeRow{rm.serverIP, "255.255.255.255", rm.origGateway}
	if err := addRoute(host); err != nil {
		return fmt.Errorf("add server host route: %w", err)
	}
	rm.added = append(rm.added, host)

	// Теперь два half-default через туннель.
	half1 := routeRow{"0.0.0.0", "128.0.0.0", rm.tunGateway}
	half2 := routeRow{"128.0.0.0", "128.0.0.0", rm.tunGateway}
	for _, r := range []routeRow{half1, half2} {
		if err := addRoute(r); err != nil {
			return fmt.Errorf("add tunnel route %s/%s: %w", r.dest, r.mask, err)
		}
		rm.added = append(rm.added, r)
	}

	return nil
}

// RestoreRoutes удаляет маршруты, добавленные SetupRoutes.
func (rm *RouteManager) RestoreRoutes() error {
	var firstErr error
	// Удаляем в обратном порядке.
	for i := len(rm.added) - 1; i >= 0; i-- {
		if err := deleteRoute(rm.added[i]); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	rm.added = nil
	return firstErr
}

// runNetsh запускает `netsh.exe` с переданными аргументами.
func runNetsh(args ...string) error {
	out, err := exec.Command("netsh.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %w (output: %s)",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runRoute запускает `route.exe` с аргументами и возвращает CombinedOutput.
func runRoute(args ...string) (string, error) {
	out, err := exec.Command("route.exe", args...).CombinedOutput()
	return string(out), err
}

func addRoute(r routeRow) error {
	out, err := runRoute("ADD", r.dest, "MASK", r.mask, r.gateway, "METRIC", "1")
	if err != nil {
		// Если маршрут уже есть, route выдаёт "The route addition failed: The object already exists."
		if strings.Contains(out, "already exists") {
			return nil
		}
		return fmt.Errorf("route add %s mask %s %s: %w (output: %s)",
			r.dest, r.mask, r.gateway, err, strings.TrimSpace(out))
	}
	return nil
}

func deleteRoute(r routeRow) error {
	if _, err := runRoute("DELETE", r.dest, "MASK", r.mask, r.gateway); err != nil {
		// route delete может вернуть ошибку, если маршрута уже нет — это OK.
		return nil
	}
	return nil
}

// defaultGateway парсит вывод `route print -4 0.0.0.0` и возвращает текущий
// дефолтный шлюз IPv4.
//
// Ищется первая строка вида "0.0.0.0  0.0.0.0  <gw>  <iface-ip>  <metric>".
// Парсинг устойчив к локализации, потому что IP-адреса формат universal.
var defaultRouteRe = regexp.MustCompile(
	`^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+\S+\s+\d+\s*$`,
)

func defaultGateway() (string, error) {
	out, err := runRoute("PRINT", "-4", "0.0.0.0")
	if err != nil {
		return "", fmt.Errorf("route print: %w (output: %s)", err, strings.TrimSpace(out))
	}
	for _, line := range strings.Split(out, "\n") {
		m := defaultRouteRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		gw := strings.TrimSpace(m[1])
		// Игнорируем "On-link" — это не gateway, а особая отметка.
		if strings.EqualFold(gw, "On-link") {
			continue
		}
		if net.ParseIP(gw) == nil {
			continue
		}
		return gw, nil
	}
	return "", fmt.Errorf("default IPv4 route not found in `route print` output")
}
