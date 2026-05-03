// Package client содержит VPN-клиента поверх WebSocket-транспорта (Yandex API
// Gateway или прямой WS-эндпоинт сервера). Кросс-платформенный: на Linux
// использует /dev/net/tun, на Windows — Wintun (через golang.zx2c4.com/wireguard/tun).
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"myvpn/internal"
	"myvpn/internal/compress"
	"myvpn/internal/transport"
)

// VPNClient — VPN-клиент поверх WebSocket-транспорта.
type VPNClient struct {
	cfg          VPNClientConfig
	tun          *TUN
	crypto       *internal.Crypto
	transport    *transport.WSClientTransport
	routeManager *RouteManager

	stopOnce sync.Once
	done     chan struct{}
	wg       sync.WaitGroup
}

// VPNClientConfig — параметры VPN-клиента.
type VPNClientConfig struct {
	// ServerURL WebSocket-URL Yandex API Gateway или прямого эндпоинта сервера.
	ServerURL string
	// Key 32-байтный ключ ChaCha20-Poly1305.
	Key []byte
	// ClientIP IP клиента в туннеле (например 10.0.0.2).
	ClientIP string
	// Verbose подробное логирование.
	Verbose bool
	// AutoRoutes автоматически перенаправлять весь трафик в VPN.
	AutoRoutes bool
	// ExtraHeaders дополнительные HTTP-заголовки рукопожатия (опционально).
	ExtraHeaders http.Header
	// InsecureSkipVerify отключает проверку TLS-сертификата (для отладки).
	InsecureSkipVerify bool
}

// NewVPNClient создаёт нового клиента: открывает TUN, подготавливает crypto
// и (при AutoRoutes=true) менеджер маршрутов.
func NewVPNClient(cfg VPNClientConfig) (*VPNClient, error) {
	if cfg.ServerURL == "" {
		return nil, errors.New("server URL is required")
	}
	if cfg.ClientIP == "" {
		cfg.ClientIP = "10.0.0.2"
	}

	tun, err := NewTUN(TUNInterfaceName, cfg.ClientIP)
	if err != nil {
		return nil, fmt.Errorf("create TUN: %w", err)
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
		rm, err = NewRouteManager(tun, host)
		if err != nil {
			_ = tun.Close()
			return nil, fmt.Errorf("create route manager: %w", err)
		}
		rm.SetVerbose(cfg.Verbose)
	}

	return &VPNClient{
		cfg:          cfg,
		tun:          tun,
		crypto:       crypto,
		routeManager: rm,
		done:         make(chan struct{}),
	}, nil
}

// Connect подключается к VPN-серверу через WebSocket и обрабатывает пакеты
// до отмены ctx или вызова Close.
//
// При обрыве WebSocket'а (например, по 60-минутному лимиту Yandex API Gateway
// или транзиентной сетевой ошибке) транспорт сам переподключается с
// экспоненциальным backoff'ом — VPN-клиент при этом не выходит, пакеты в
// момент разрыва просто дропаются (TCP внутри туннеля их перешлёт).
func (c *VPNClient) Connect(ctx context.Context) error {
	wsTransport, err := transport.NewWSClientTransport(transport.WSClientConfig{
		URL:                c.cfg.ServerURL,
		Headers:            c.cfg.ExtraHeaders,
		InsecureSkipVerify: c.cfg.InsecureSkipVerify,
		Verbose:            c.cfg.Verbose,
	})
	if err != nil {
		return fmt.Errorf("create WebSocket transport: %w", err)
	}
	c.transport = wsTransport

	log.Printf("Connected to VPN server at %s", c.cfg.ServerURL)
	log.Printf("TUN interface: %s", c.tun.Name())

	switch {
	case !c.cfg.AutoRoutes:
		log.Println("Routes: AutoRoutes is disabled (MYVPN_AUTO_ROUTES=false). " +
			"Only traffic explicitly routed through this TUN will use the VPN.")
	case c.routeManager == nil:
		log.Println("Routes: WARNING — AutoRoutes requested but no route manager " +
			"was created. VPN traffic will not be routed.")
	default:
		log.Println("Routes: AutoRoutes enabled, configuring split default route...")
		if err := c.routeManager.SetupRoutes(); err != nil {
			log.Printf("Routes: ERROR setting up routes: %v", err)
			log.Println("Routes: VPN traffic will NOT flow until this is fixed " +
				"(usually: insufficient privileges, or another VPN already owns the default route)")
		} else {
			log.Println("Routes: configured — all IPv4 traffic now flows through the VPN")
		}
	}

	c.wg.Add(2)
	go c.handleTunToServer()
	go c.handleServerToTun()

	// Ждём отмены контекста или окончания работы goroutine'ов (например при
	// разрыве соединения).
	doneCh := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(doneCh)
	}()
	select {
	case <-ctx.Done():
	case <-doneCh:
	}

	log.Println("Disconnected from VPN server")
	return nil
}

// handleTunToServer читает пакеты из TUN и отправляет на сервер.
func (c *VPNClient) handleTunToServer() {
	defer c.wg.Done()
	buf := make([]byte, internal.TUNMTU)

	for {
		n, err := c.tun.Read(buf)
		if err != nil {
			select {
			case <-c.done:
				return
			default:
				if err != io.EOF {
					log.Printf("Error reading from TUN: %v", err)
				}
				_ = c.shutdown()
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
			select {
			case <-c.done:
				return
			default:
				log.Printf("Error sending packet to server: %v", err)
				_ = c.shutdown()
				return
			}
		}
	}
}

// sendPacket: LZ4 + ChaCha20-Poly1305 + один WS-фрейм.
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

// handleServerToTun читает сообщения от сервера и пишет пакеты в TUN.
func (c *VPNClient) handleServerToTun() {
	defer c.wg.Done()
	buf := make([]byte, transport.WSMaxMessageSize)

	for {
		n, err := c.transport.Read(buf)
		if err != nil {
			select {
			case <-c.done:
				return
			default:
				log.Printf("Error receiving packet from server: %v", err)
				_ = c.shutdown()
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
			select {
			case <-c.done:
				return
			default:
				log.Printf("Error writing to TUN: %v", err)
				_ = c.shutdown()
				return
			}
		}
	}
}

// Close корректно завершает работу клиента: восстанавливает маршруты,
// закрывает транспорт и TUN, ждёт окончания goroutine.
func (c *VPNClient) Close() error {
	return c.shutdownWithTimeout(5 * time.Second)
}

// shutdown инициирует завершение работы из голоса goroutine, не блокируя надолго.
func (c *VPNClient) shutdown() error {
	return c.shutdownWithTimeout(2 * time.Second)
}

func (c *VPNClient) shutdownWithTimeout(wait time.Duration) error {
	var firstErr error
	c.stopOnce.Do(func() {
		close(c.done)

		if c.routeManager != nil {
			if err := c.routeManager.RestoreRoutes(); err != nil {
				log.Printf("Warning: failed to restore routes: %v", err)
				firstErr = err
			} else {
				log.Println("Routes restored to original state")
			}
		}

		// Сначала закрываем TUN, чтобы handleTunToServer вышел из блокирующего Read.
		if c.tun != nil {
			if err := c.tun.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}

		// Затем транспорт — handleServerToTun увидит ошибку чтения и тоже выйдет.
		if c.transport != nil {
			if err := c.transport.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}

		// Ждём завершения goroutine'ов с таймаутом.
		done := make(chan struct{})
		go func() {
			c.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(wait):
			log.Printf("Warning: VPN client goroutines did not finish within %s", wait)
		}
	})
	return firstErr
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
