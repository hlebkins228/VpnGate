//go:build linux

package client

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

// VPNClient — VPN-клиент, использующий WebSocket-транспорт до Yandex API Gateway.
type VPNClient struct {
	serverURL    string
	tun          *TUN
	crypto       *internal.Crypto
	protocol     *internal.Protocol
	transport    *transport.WSClientTransport
	routeManager *RouteManager
	done         chan struct{}
	wg           sync.WaitGroup
	verbose      bool
	autoRoutes   bool

	// extraHeaders дополнительные HTTP заголовки для рукопожатия (опционально)
	extraHeaders http.Header
	// insecureSkipVerify отключает проверку TLS сертификата (для отладки)
	insecureSkipVerify bool
}

// VPNClientConfig параметры VPN клиента.
type VPNClientConfig struct {
	// ServerURL WebSocket URL (wss://... или ws://...) Yandex API Gateway или
	// прямого WS-эндпоинта VPN-сервера.
	ServerURL string
	// Key 32-байтный ключ ChaCha20-Poly1305.
	Key []byte
	// ClientIP IP-адрес для TUN-интерфейса клиента (например 10.0.0.2).
	ClientIP string
	// Verbose подробное логирование.
	Verbose bool
	// AutoRoutes автоматическая настройка маршрутов всего трафика через VPN.
	AutoRoutes bool
	// ExtraHeaders дополнительные заголовки рукопожатия (опционально).
	ExtraHeaders http.Header
	// InsecureSkipVerify отключает проверку TLS-сертификата (только для отладки).
	InsecureSkipVerify bool
}

// NewVPNClient создаёт новый VPN клиент.
func NewVPNClient(cfg VPNClientConfig) (*VPNClient, error) {
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("server URL is required")
	}

	// Создаем TUN интерфейс
	tun, err := NewTUN(TUNInterfaceName, cfg.ClientIP)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	crypto, err := internal.NewCrypto(cfg.Key)
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("failed to create crypto: %w", err)
	}

	protocol := internal.NewProtocol(crypto)

	// Создаем менеджер маршрутов только если включена автоматическая настройка
	var routeManager *RouteManager
	if cfg.AutoRoutes {
		host, err := extractServerHost(cfg.ServerURL)
		if err != nil {
			tun.Close()
			return nil, fmt.Errorf("failed to extract server host from %q: %w", cfg.ServerURL, err)
		}
		routeManager, err = NewRouteManager(TUNInterfaceName, host)
		if err != nil {
			tun.Close()
			return nil, fmt.Errorf("failed to create route manager: %w", err)
		}
	}

	return &VPNClient{
		serverURL:          cfg.ServerURL,
		tun:                tun,
		crypto:             crypto,
		protocol:           protocol,
		routeManager:       routeManager,
		done:               make(chan struct{}),
		verbose:            cfg.Verbose,
		autoRoutes:         cfg.AutoRoutes,
		extraHeaders:       cfg.ExtraHeaders,
		insecureSkipVerify: cfg.InsecureSkipVerify,
	}, nil
}

// Connect подключается к VPN серверу через WebSocket и начинает обмен пакетами.
func (c *VPNClient) Connect() error {
	wsTransport, err := transport.NewWSClientTransport(transport.WSClientConfig{
		URL:                c.serverURL,
		Headers:            c.extraHeaders,
		InsecureSkipVerify: c.insecureSkipVerify,
	})
	if err != nil {
		return fmt.Errorf("failed to create WebSocket transport: %w", err)
	}

	c.transport = wsTransport
	log.Printf("Connected to VPN server at %s", c.serverURL)
	log.Printf("TUN interface: %s", c.tun.Name())

	// Настраиваем маршрутизацию всего трафика через VPN
	if c.autoRoutes && c.routeManager != nil {
		if err := c.routeManager.SetupRoutes(); err != nil {
			log.Printf("Warning: failed to setup routes: %v", err)
			log.Println("You may need to configure routes manually")
		} else {
			log.Println("✓ Routes configured: all traffic now goes through VPN")
		}
	}

	c.wg.Add(1)
	go c.handleTunToServer()

	c.wg.Add(1)
	go c.handleServerToTun()

	c.wg.Wait()
	log.Println("Disconnected from VPN server")

	return nil
}

// handleTunToServer читает пакеты из TUN и отправляет на сервер.
func (c *VPNClient) handleTunToServer() {
	defer c.wg.Done()

	packet := make([]byte, internal.TUNMTU)

	for {
		select {
		case <-c.done:
			log.Println("handleTunToServer: done signal received")
			return
		default:
		}

		n, err := c.tun.Read(packet)
		if err != nil {
			select {
			case <-c.done:
				return
			default:
				if err != io.EOF {
					log.Printf("Error reading from TUN: %v", err)
				} else {
					log.Println("TUN interface closed (EOF)")
				}
				c.Close()
				return
			}
		}

		if n > 0 {
			if c.verbose {
				log.Printf("Read %d bytes from TUN, sending to server", n)
			}
			if err := c.sendPacket(packet[:n]); err != nil {
				log.Printf("Error sending packet to server: %v", err)
				c.Close()
				return
			}
		}
	}
}

// sendPacket сжимает, шифрует и отправляет пакет через WebSocket.
//
// Формат отправляемого WebSocket сообщения:
//
//	[флаг сжатия (1 байт)] [nonce (12 байт)] [ciphertext + tag (n байт)]
func (c *VPNClient) sendPacket(packet []byte) error {
	compressed, isCompressed, err := compress.Compress(packet)
	if err != nil {
		return fmt.Errorf("compression failed: %w", err)
	}

	encrypted, err := c.crypto.Encrypt(compressed)
	if err != nil {
		return err
	}

	// Префиксируем 1 байтом флагов (бит 0 — сжатие)
	result := make([]byte, 1+len(encrypted))
	if isCompressed {
		result[0] = internal.FlagCompressed
	} else {
		result[0] = 0
	}
	copy(result[1:], encrypted)

	if len(result) > transport.WSMaxMessageSize {
		return fmt.Errorf("packet too large after encryption: %d bytes (max %d), original: %d bytes",
			len(result), transport.WSMaxMessageSize, len(packet))
	}

	_, err = c.transport.Write(result)
	return err
}

// handleServerToTun читает пакеты от сервера и записывает в TUN.
func (c *VPNClient) handleServerToTun() {
	defer c.wg.Done()

	// WebSocket сообщение целиком приходит в буфер. Делаем буфер с запасом.
	buf := make([]byte, transport.WSMaxMessageSize)

	for {
		select {
		case <-c.done:
			log.Println("handleServerToTun: done signal received")
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
				c.Close()
				return
			}
		}

		if n < 1 {
			continue
		}

		// Извлекаем флаг сжатия
		flags := buf[0]
		isCompressed := (flags & internal.FlagCompressed) != 0

		encrypted := buf[1:n]
		packet, err := c.crypto.Decrypt(encrypted)
		if err != nil {
			log.Printf("Error decrypting packet: %v", err)
			continue
		}

		if isCompressed {
			packet, err = compress.Decompress(packet, true)
			if err != nil {
				log.Printf("Error decompressing packet: %v", err)
				continue
			}
		}

		if len(packet) > 0 {
			if c.verbose {
				log.Printf("Received %d bytes from server, writing to TUN", len(packet))
			}
			if _, err := c.tun.Write(packet); err != nil {
				log.Printf("Error writing packet to TUN: %v", err)
				c.Close()
				return
			}
		}
	}
}

// Close закрывает соединение и TUN интерфейс.
func (c *VPNClient) Close() error {
	select {
	case <-c.done:
		return nil
	default:
		close(c.done)
	}

	var errs []error

	// Восстанавливаем старые маршруты
	if c.routeManager != nil {
		if err := c.routeManager.RestoreRoutes(); err != nil {
			log.Printf("Warning: failed to restore routes: %v", err)
			errs = append(errs, fmt.Errorf("failed to restore routes: %w", err))
		} else {
			log.Println("✓ Routes restored to original state")
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
		return fmt.Errorf("errors closing client: %v", errs)
	}

	return nil
}

// extractServerHost извлекает hostname из WebSocket URL для добавления маршрута.
//
// Возвращает либо доменное имя, либо IP-литерал.
func extractServerHost(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("URL has no host: %q", rawURL)
	}
	// На всякий случай отбрасываем порт и trailing slashes
	host = strings.TrimSpace(host)
	return host, nil
}
