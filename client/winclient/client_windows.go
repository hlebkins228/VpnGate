//go:build windows

package winclient

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"myvpn/internal"
	"myvpn/internal/compress"
	"myvpn/internal/transport"
)

// VPNClient — VPN-клиент под Windows. Логика идентична Linux-клиенту в
// пакете myvpn/client, но использует Wintun вместо /dev/net/tun и
// netsh/route вместо `ip` команд.
type VPNClient struct {
	cfg          VPNClientConfig
	tun          *TUN
	crypto       *internal.Crypto
	transport    *transport.WSClientTransport
	routeManager *RouteManager

	done chan struct{}
	wg   sync.WaitGroup
}

// VPNClientConfig — параметры клиента (совпадают с Linux-версией).
type VPNClientConfig struct {
	ServerURL          string
	Key                []byte
	ClientIP           string // IP клиента в туннеле (default 10.0.0.2)
	TunGateway         string // IP сервера в туннеле (default 10.0.0.1)
	Verbose            bool
	AutoRoutes         bool
	ExtraHeaders       http.Header
	InsecureSkipVerify bool
}

// NewVPNClient создаёт VPN-клиент: открывает Wintun-адаптер, создаёт crypto
// и (при AutoRoutes=true) подготавливает менеджер маршрутов.
func NewVPNClient(cfg VPNClientConfig) (*VPNClient, error) {
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("server URL is required")
	}
	if cfg.ClientIP == "" {
		cfg.ClientIP = "10.0.0.2"
	}
	if cfg.TunGateway == "" {
		cfg.TunGateway = "10.0.0.1"
	}

	tun, err := NewTUN(AdapterName, cfg.ClientIP)
	if err != nil {
		return nil, fmt.Errorf("create wintun: %w", err)
	}

	crypto, err := internal.NewCrypto(cfg.Key)
	if err != nil {
		_ = tun.Close()
		return nil, fmt.Errorf("create crypto: %w", err)
	}

	var rm *RouteManager
	if cfg.AutoRoutes {
		host, err := extractServerHost(cfg.ServerURL)
		if err != nil {
			_ = tun.Close()
			return nil, fmt.Errorf("extract host from %q: %w", cfg.ServerURL, err)
		}
		rm, err = NewRouteManager(tun.Name(), host, cfg.TunGateway)
		if err != nil {
			_ = tun.Close()
			return nil, fmt.Errorf("create route manager: %w", err)
		}
	}

	return &VPNClient{
		cfg:          cfg,
		tun:          tun,
		crypto:       crypto,
		routeManager: rm,
		done:         make(chan struct{}),
	}, nil
}

// Connect устанавливает WebSocket-соединение с сервером и начинает обмен
// пакетами. Блокируется до получения ошибки или вызова Close.
func (c *VPNClient) Connect() error {
	wsTransport, err := transport.NewWSClientTransport(transport.WSClientConfig{
		URL:                c.cfg.ServerURL,
		Headers:            c.cfg.ExtraHeaders,
		InsecureSkipVerify: c.cfg.InsecureSkipVerify,
	})
	if err != nil {
		return fmt.Errorf("create WebSocket transport: %w", err)
	}
	c.transport = wsTransport

	log.Printf("Connected to VPN server at %s", c.cfg.ServerURL)
	log.Printf("TUN interface: %s (Wintun)", c.tun.Name())

	if c.cfg.AutoRoutes && c.routeManager != nil {
		if err := c.routeManager.SetupRoutes(); err != nil {
			log.Printf("Warning: failed to setup routes: %v", err)
			log.Println("You may need to configure routes manually")
		} else {
			log.Println("Routes configured: all traffic now goes through VPN")
		}
	}

	c.wg.Add(2)
	go c.handleTunToServer()
	go c.handleServerToTun()
	c.wg.Wait()

	log.Println("Disconnected from VPN server")
	return nil
}

// handleTunToServer читает пакеты из Wintun-адаптера и отправляет на сервер.
func (c *VPNClient) handleTunToServer() {
	defer c.wg.Done()
	buf := make([]byte, internal.TUNMTU)

	for {
		select {
		case <-c.done:
			return
		default:
		}

		n, err := c.tun.Read(buf)
		if err != nil {
			select {
			case <-c.done:
				return
			default:
				if err != io.EOF {
					log.Printf("Error reading from TUN: %v", err)
				}
				_ = c.Close()
				return
			}
		}
		if n == 0 {
			continue
		}

		if c.cfg.Verbose {
			log.Printf("Read %d bytes from TUN, sending to server", n)
		}
		if err := c.sendPacket(buf[:n]); err != nil {
			log.Printf("Error sending packet to server: %v", err)
			_ = c.Close()
			return
		}
	}
}

// sendPacket — сжатие LZ4 + ChaCha20-Poly1305 + один WebSocket-фрейм.
func (c *VPNClient) sendPacket(packet []byte) error {
	compressed, isCompressed, err := compress.Compress(packet)
	if err != nil {
		return fmt.Errorf("compression: %w", err)
	}
	encrypted, err := c.crypto.Encrypt(compressed)
	if err != nil {
		return err
	}

	out := make([]byte, 1+len(encrypted))
	if isCompressed {
		out[0] = internal.FlagCompressed
	}
	copy(out[1:], encrypted)

	if len(out) > transport.WSMaxMessageSize {
		return fmt.Errorf("packet too large: %d bytes (max %d)", len(out), transport.WSMaxMessageSize)
	}

	_, err = c.transport.Write(out)
	return err
}

// handleServerToTun читает пакеты от сервера и пишет в Wintun.
func (c *VPNClient) handleServerToTun() {
	defer c.wg.Done()
	buf := make([]byte, transport.WSMaxMessageSize)

	for {
		select {
		case <-c.done:
			return
		default:
		}

		n, err := c.transport.Read(buf)
		if err != nil {
			select {
			case <-c.done:
				return
			default:
				log.Printf("Error receiving packet from server: %v", err)
				_ = c.Close()
				return
			}
		}
		if n < 1 {
			continue
		}

		isCompressed := (buf[0] & internal.FlagCompressed) != 0
		plain, err := c.crypto.Decrypt(buf[1:n])
		if err != nil {
			log.Printf("Error decrypting packet: %v", err)
			continue
		}
		if isCompressed {
			plain, err = compress.Decompress(plain, true)
			if err != nil {
				log.Printf("Error decompressing packet: %v", err)
				continue
			}
		}

		if len(plain) == 0 {
			continue
		}
		if c.cfg.Verbose {
			log.Printf("Received %d bytes from server, writing to TUN", len(plain))
		}
		if _, err := c.tun.Write(plain); err != nil {
			log.Printf("Error writing to TUN: %v", err)
			_ = c.Close()
			return
		}
	}
}

// Close завершает работу клиента: восстанавливает маршруты, закрывает
// транспорт и Wintun-адаптер.
func (c *VPNClient) Close() error {
	select {
	case <-c.done:
		return nil
	default:
		close(c.done)
	}

	var errs []error

	if c.routeManager != nil {
		if err := c.routeManager.RestoreRoutes(); err != nil {
			log.Printf("Warning: failed to restore routes: %v", err)
			errs = append(errs, err)
		} else {
			log.Println("Routes restored to original state")
		}
	}

	if c.transport != nil {
		if err := c.transport.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if c.tun != nil {
		if err := c.tun.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}

// extractServerHost вытаскивает hostname из ws/wss URL.
func extractServerHost(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("URL has no host: %q", rawURL)
	}
	return host, nil
}
