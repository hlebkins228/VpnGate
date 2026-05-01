//go:build windows

package client

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

// RouteManager перенаправляет весь трафик клиента в VPN на Windows.
//
// Алгоритм — split default route:
//
//   - Добавляется host-маршрут к серверу VPN через прежний default gateway,
//     чтобы туннель сам себя не перекрыл.
//   - Добавляются два маршрута 0.0.0.0/1 и 128.0.0.0/1 через next-hop туннеля
//     (по умолчанию 10.0.0.1). По более длинному префиксу Windows выберет их
//     вместо оригинального 0.0.0.0/0 — переписывать default route не нужно,
//     откат при выходе сводится к удалению трёх добавленных строк.
type RouteManager struct {
	tunInterface string // имя Wintun-адаптера (для информации; маршруты не привязываются к нему)
	tunGateway   string // IP сервера в туннеле, выступает next-hop'ом для split default
	serverIP     string // публичный IP сервера VPN
	origGateway  string // прежний default gateway
	added        []routeRow
}

type routeRow struct{ dest, mask, gateway string }

// NewRouteManager резолвит hostname сервера в IPv4 и подготавливает менеджер.
// tunGateway по умолчанию равен "10.0.0.1" (адрес сервера внутри туннеля).
func NewRouteManager(tunInterface, serverAddr string) (*RouteManager, error) {
	return NewRouteManagerWithGateway(tunInterface, serverAddr, "10.0.0.1")
}

// NewRouteManagerWithGateway — то же, что NewRouteManager, но позволяет
// явно задать tunGateway (используется как next-hop для split default route).
func NewRouteManagerWithGateway(tunInterface, serverAddr, tunGateway string) (*RouteManager, error) {
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	var serverIP string
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
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
		tunInterface: tunInterface,
		tunGateway:   tunGateway,
		serverIP:     serverIP,
	}, nil
}

// SetupRoutes добавляет маршруты для проксирования всего трафика через VPN.
func (rm *RouteManager) SetupRoutes() error {
	gw, err := defaultGateway()
	if err != nil {
		return fmt.Errorf("read default gateway: %w", err)
	}
	rm.origGateway = gw

	host := routeRow{rm.serverIP, "255.255.255.255", rm.origGateway}
	if err := addRoute(host); err != nil {
		return fmt.Errorf("add server host route: %w", err)
	}
	rm.added = append(rm.added, host)

	for _, r := range []routeRow{
		{"0.0.0.0", "128.0.0.0", rm.tunGateway},
		{"128.0.0.0", "128.0.0.0", rm.tunGateway},
	} {
		if err := addRoute(r); err != nil {
			return fmt.Errorf("add tunnel route %s/%s: %w", r.dest, r.mask, err)
		}
		rm.added = append(rm.added, r)
	}

	return nil
}

// RestoreRoutes удаляет маршруты, добавленные SetupRoutes.
func (rm *RouteManager) RestoreRoutes() error {
	for i := len(rm.added) - 1; i >= 0; i-- {
		_ = deleteRoute(rm.added[i])
	}
	rm.added = nil
	return nil
}

func runRoute(args ...string) (string, error) {
	out, err := exec.Command("route.exe", args...).CombinedOutput()
	return string(out), err
}

func addRoute(r routeRow) error {
	out, err := runRoute("ADD", r.dest, "MASK", r.mask, r.gateway, "METRIC", "1")
	if err != nil {
		if strings.Contains(out, "already exists") {
			return nil
		}
		return fmt.Errorf("route add %s mask %s %s: %w (output: %s)",
			r.dest, r.mask, r.gateway, err, strings.TrimSpace(out))
	}
	return nil
}

func deleteRoute(r routeRow) error {
	_, _ = runRoute("DELETE", r.dest, "MASK", r.mask, r.gateway)
	return nil
}

// defaultRouteRe вытягивает gateway из строки `route print -4 0.0.0.0`.
// IP-адреса в Windows route print имеют одинаковый формат во всех локалях.
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
