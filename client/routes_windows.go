//go:build windows

package client

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// RouteManager перенаправляет весь трафик клиента в VPN на Windows через
// прямые вызовы Win32 API (winipcfg / Iphlpapi). Старая реализация шеллила
// route.exe и netsh — это работает в подавляющем большинстве случаев, но
// иногда даёт молчаливые сбои (route ADD возвращает 0, а маршрут на самом
// деле не работает потому что Windows не привязал его к Wintun-адаптеру).
// WinAPI делает всё детерминированно: маршрут жёстко привязывается к LUID
// Wintun-адаптера через MIB_IPFORWARD_ROW2.
//
// Алгоритм — split default route:
//
//   - Добавляется host-маршрут к серверу VPN через прежний default-шлюз
//     (через старый интерфейс), чтобы сам туннель не перекрыл свой transport.
//   - Добавляются 0.0.0.0/1 и 128.0.0.0/1 через next-hop туннеля (10.0.0.1)
//     на Wintun-адаптере. По длине префикса они выигрывают у настоящего
//     0.0.0.0/0, поэтому переписывать существующий default не нужно. На
//     выходе достаточно удалить три добавленные записи — система сама
//     "вернётся" к старому default.
type RouteManager struct {
	tun        *TUN
	tunGateway netip.Addr   // адрес сервера в туннеле (next-hop split default route)
	serverIP   netip.Addr   // публичный IP VPN-сервера (host-маршрут)
	wintunLUID winipcfg.LUID
	verbose    bool

	origGatewayIPv4   netip.Addr      // прежний default gateway (для лога)
	origInterfaceLUID winipcfg.LUID   // LUID интерфейса, через который работал прежний default
	added             []addedRoute
}

type addedRoute struct {
	luid winipcfg.LUID
	dest netip.Prefix
	hop  netip.Addr
}

// NewRouteManager резолвит hostname сервера в IPv4 и подготавливает менеджер.
// tunGateway по умолчанию равен 10.0.0.1 (адрес сервера внутри туннеля).
func NewRouteManager(t *TUN, serverAddr string) (*RouteManager, error) {
	return NewRouteManagerWithGateway(t, serverAddr, "10.0.0.1")
}

// NewRouteManagerWithGateway — то же, что NewRouteManager, но позволяет
// явно задать tunGateway (используется как next-hop для split default route).
func NewRouteManagerWithGateway(t *TUN, serverAddr, tunGateway string) (*RouteManager, error) {
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	var serverIP netip.Addr
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || ip.To4() == nil {
			continue
		}
		serverIP, _ = netip.AddrFromSlice(ip.To4())
		break
	}
	if !serverIP.IsValid() {
		return nil, fmt.Errorf("no IPv4 address for %q", host)
	}
	if tunGateway == "" {
		tunGateway = "10.0.0.1"
	}
	gw, err := netip.ParseAddr(tunGateway)
	if err != nil || !gw.Is4() {
		return nil, fmt.Errorf("parse tunGateway %q: %w", tunGateway, err)
	}

	luid := t.winLUID()
	if luid == 0 {
		return nil, fmt.Errorf("could not obtain Wintun LUID")
	}

	return &RouteManager{
		tun:        t,
		tunGateway: gw,
		serverIP:   serverIP,
		wintunLUID: luid,
	}, nil
}

// SetVerbose включает подробный лог в SetupRoutes/RestoreRoutes.
// Выставляется из VPNClientConfig.Verbose.
func (rm *RouteManager) SetVerbose(v bool) { rm.verbose = v }

// SetupRoutes добавляет маршруты для проксирования всего трафика через VPN.
func (rm *RouteManager) SetupRoutes() error {
	log.Printf("Routes: setting up split default via Wintun LUID 0x%x, tun gateway %s, server %s",
		uint64(rm.wintunLUID), rm.tunGateway, rm.serverIP)

	// 1. Найти текущий "выходящий в интернет" default route и его шлюз —
	// чтобы добавить host-маршрут к VPN-серверу через ТОТ ЖЕ шлюз и
	// тот же физический интерфейс (иначе туннель сам себя перекроет).
	gw, gwLUID, err := rm.findOriginalDefaultIPv4()
	if err != nil {
		return fmt.Errorf("find original IPv4 default route: %w", err)
	}
	rm.origGatewayIPv4 = gw
	rm.origInterfaceLUID = gwLUID
	log.Printf("Routes: original IPv4 default route via %s (LUID 0x%x)",
		gw, uint64(gwLUID))

	// 2. Host-маршрут к VPN-серверу через старый шлюз/интерфейс.
	hostPrefix := netip.PrefixFrom(rm.serverIP, 32)
	if err := rm.addRoute(gwLUID, hostPrefix, gw, 1); err != nil {
		return fmt.Errorf("add host route to %s via %s: %w", rm.serverIP, gw, err)
	}

	// 3. Split default routes 0.0.0.0/1 и 128.0.0.0/1 через Wintun.
	for _, p := range splitDefaultPrefixes() {
		if err := rm.addRoute(rm.wintunLUID, p, rm.tunGateway, 1); err != nil {
			return fmt.Errorf("add tunnel route %s: %w", p, err)
		}
	}

	log.Printf("Routes: configured (added %d routes)", len(rm.added))
	if rm.verbose {
		rm.dumpIPv4Routes("after setup")
	}
	return nil
}

// RestoreRoutes удаляет маршруты, добавленные SetupRoutes.
func (rm *RouteManager) RestoreRoutes() error {
	if rm.verbose {
		rm.dumpIPv4Routes("before restore")
	}
	var firstErr error
	for i := len(rm.added) - 1; i >= 0; i-- {
		ar := rm.added[i]
		if err := ar.luid.DeleteRoute(ar.dest, ar.hop); err != nil && firstErr == nil {
			firstErr = err
		}
		log.Printf("Routes: deleted %s via %s on LUID 0x%x", ar.dest, ar.hop, uint64(ar.luid))
	}
	rm.added = nil
	return firstErr
}

func (rm *RouteManager) addRoute(luid winipcfg.LUID, dest netip.Prefix, hop netip.Addr, metric uint32) error {
	if err := luid.AddRoute(dest, hop, metric); err != nil {
		return fmt.Errorf("AddRoute %s via %s on LUID 0x%x: %w",
			dest, hop, uint64(luid), err)
	}
	rm.added = append(rm.added, addedRoute{luid: luid, dest: dest, hop: hop})
	log.Printf("Routes: added %s via %s on LUID 0x%x (metric %d)",
		dest, hop, uint64(luid), metric)
	return nil
}

// findOriginalDefaultIPv4 ищет в IPv4 forwarding table запись 0.0.0.0/0,
// которая НЕ принадлежит нашему Wintun-адаптеру и имеет ненулевой next-hop.
// Возвращает gateway и LUID интерфейса, через который этот шлюз достижим.
//
// Если default-маршрутов несколько (multi-homed: Wi-Fi + Ethernet), берём
// тот, у которого ниже эффективная метрика — Windows точно так же выбирает
// "основной" outgoing default route.
func (rm *RouteManager) findOriginalDefaultIPv4() (netip.Addr, winipcfg.LUID, error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("GetIPForwardTable2: %w", err)
	}

	type cand struct {
		gw     netip.Addr
		luid   winipcfg.LUID
		metric uint32
	}
	var candidates []cand
	for i := range rows {
		r := &rows[i]
		dest := r.DestinationPrefix.Prefix()
		if !dest.IsValid() || dest.Bits() != 0 || !dest.Addr().Is4() {
			continue
		}
		if r.InterfaceLUID == rm.wintunLUID {
			continue
		}
		gw := r.NextHop.Addr()
		if !gw.IsValid() || gw.IsUnspecified() {
			continue
		}
		// Эффективная метрика = метрика маршрута + метрика интерфейса.
		ifMetric := uint32(0)
		if row, err := r.InterfaceLUID.IPInterface(windows.AF_INET); err == nil {
			ifMetric = row.Metric
		}
		candidates = append(candidates, cand{
			gw:     gw,
			luid:   r.InterfaceLUID,
			metric: r.Metric + ifMetric,
		})
	}
	if len(candidates) == 0 {
		return netip.Addr{}, 0, fmt.Errorf("no IPv4 default route with explicit gateway found")
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].metric < candidates[j].metric
	})
	c := candidates[0]
	return c.gw, c.luid, nil
}

// splitDefaultPrefixes — два полупрефикса, которые вместе покрывают весь
// IPv4-адресный space, но имеют /1 — длиннее, чем настоящий default 0.0.0.0/0.
func splitDefaultPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.PrefixFrom(netip.IPv4Unspecified(), 1),                  // 0.0.0.0/1
		netip.PrefixFrom(netip.AddrFrom4([4]byte{128, 0, 0, 0}), 1),   // 128.0.0.0/1
	}
}

// dumpIPv4Routes — отладочный лог IPv4 routing table (только в verbose).
func (rm *RouteManager) dumpIPv4Routes(tag string) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		log.Printf("Routes: dump (%s): %v", tag, err)
		return
	}
	log.Printf("Routes: IPv4 forwarding table (%s, %d entries):", tag, len(rows))
	for i := range rows {
		r := &rows[i]
		dest := r.DestinationPrefix.Prefix()
		hop := r.NextHop.Addr()
		log.Printf("  %s via %s LUID 0x%x metric %d",
			dest, hop, uint64(r.InterfaceLUID), r.Metric)
	}
}
