package server

import (
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"myvpn/internal"
	"myvpn/internal/compress"
	"myvpn/internal/transport"
)

// ServerConfig параметры VPN-сервера.
type ServerConfig struct {
	// Listen адрес HTTP-сервера, на который Yandex API Gateway шлёт webhook'и.
	Listen string
	// WebhookPath путь webhook (должен совпадать с URL в OpenAPI спецификации API Gateway).
	WebhookPath string
	// DirectWSPath путь для прямого WebSocket-эндпоинта (для локальной отладки).
	// Если пусто — прямой режим выключен.
	DirectWSPath string
	// Key 32-байтный ключ ChaCha20-Poly1305.
	Key []byte
	// Verbose подробное логирование.
	Verbose bool
	// PushClient клиент Connection Management API. Обязателен, если включён
	// webhook-режим (т.е. требуется отправлять данные обратно через API Gateway).
	PushClient *transport.YCPushClient
}

// Server — VPN-сервер поверх WebSocket / HTTP webhook.
//
// Список активных клиентов хранит транспорт (см. transport.WSServerTransport),
// поэтому здесь нет своей карты подключений — это устраняет утечку памяти при
// разрыве соединений и гонки между webhook'ами CONNECT/MESSAGE/DISCONNECT.
type Server struct {
	cfg ServerConfig

	tun            *TUN
	crypto         *internal.Crypto
	transport      *transport.WSServerTransport
	networkManager *NetworkManager

	done chan struct{}
	wg   sync.WaitGroup
}

// NewServer создаёт новый VPN-сервер.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Listen == "" {
		return nil, errors.New("listen address is required")
	}
	if cfg.WebhookPath == "" {
		cfg.WebhookPath = "/ws"
	}

	tun, err := NewTUN(TUNInterfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	crypto, err := internal.NewCrypto(cfg.Key)
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("failed to create crypto: %w", err)
	}

	networkManager, err := NewNetworkManager(TUNInterfaceName)
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("failed to create network manager: %w", err)
	}

	return &Server{
		cfg:            cfg,
		tun:            tun,
		crypto:         crypto,
		networkManager: networkManager,
		done:           make(chan struct{}),
	}, nil
}

// Start запускает сервер.
func (s *Server) Start() error {
	if err := s.networkManager.Setup(); err != nil {
		return fmt.Errorf("failed to setup network: %w", err)
	}

	wsTransport, err := transport.NewWSServerTransport(transport.WSServerConfig{
		Listen:       s.cfg.Listen,
		WebhookPath:  s.cfg.WebhookPath,
		DirectWSPath: s.cfg.DirectWSPath,
		PushClient:   s.cfg.PushClient,
		Verbose:      s.cfg.Verbose,
	})
	if err != nil {
		_ = s.networkManager.Cleanup()
		return fmt.Errorf("failed to create WebSocket transport: %w", err)
	}

	s.transport = wsTransport

	log.Printf("VPN server listening on %s (HTTP)", s.cfg.Listen)
	log.Printf("  webhook path:  %s", s.cfg.WebhookPath)
	if s.cfg.DirectWSPath != "" {
		log.Printf("  direct WS:     %s (debug only)", s.cfg.DirectWSPath)
	}
	log.Printf("  TUN interface: %s", s.tun.Name())

	s.wg.Add(1)
	go s.handleTunToClients()

	s.wg.Add(1)
	go s.handleClientsToTun()

	return nil
}

// handleTunToClients читает пакеты из TUN и рассылает всем подключённым клиентам.
func (s *Server) handleTunToClients() {
	defer s.wg.Done()

	packet := make([]byte, TUNMTU)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		n, err := s.tun.Read(packet)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				if err != io.EOF {
					log.Printf("Error reading from TUN: %v", err)
				}
				continue
			}
		}

		if n <= 0 {
			continue
		}

		s.broadcastPacket(packet[:n])
	}
}

// broadcastPacket шифрует пакет и отправляет всем активным клиентам транспорта.
func (s *Server) broadcastPacket(packet []byte) {
	encoded, err := s.encodePacket(packet)
	if err != nil {
		log.Printf("Error encoding packet: %v", err)
		return
	}

	connIDs := s.transport.Conns()
	if s.cfg.Verbose {
		log.Printf("TUN: %d bytes -> %d client(s)", len(packet), len(connIDs))
	}
	if len(connIDs) == 0 {
		if s.cfg.Verbose {
			log.Printf("Warning: no clients to send TUN packet to (dropped %d bytes)", len(packet))
		}
		return
	}

	for _, connID := range connIDs {
		if err := s.transport.Send(connID, encoded); err != nil {
			if s.cfg.Verbose {
				log.Printf("Error sending packet to client %s: %v", connID, err)
			}
		}
	}
}

// encodePacket сжимает, шифрует и префиксует флагом сжатия.
//
// Формат: [флаг сжатия (1 байт)] [nonce (12 байт)] [ciphertext + tag]
func (s *Server) encodePacket(packet []byte) ([]byte, error) {
	compressed, isCompressed, err := compress.Compress(packet)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	encrypted, err := s.crypto.Encrypt(compressed)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 1+len(encrypted))
	if isCompressed {
		result[0] = internal.FlagCompressed
	} else {
		result[0] = 0
	}
	copy(result[1:], encrypted)
	return result, nil
}

// handleClientsToTun читает пакеты от клиентов и записывает их в TUN.
func (s *Server) handleClientsToTun() {
	defer s.wg.Done()

	for {
		select {
		case <-s.done:
			return
		default:
		}

		pkt, err := s.transport.Recv()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				log.Printf("Error reading from transport: %v", err)
				continue
			}
		}

		if len(pkt.Data) < 1 {
			continue
		}

		flags := pkt.Data[0]
		isCompressed := (flags & internal.FlagCompressed) != 0
		encrypted := pkt.Data[1:]

		decoded, err := s.crypto.Decrypt(encrypted)
		if err != nil {
			log.Printf("Error decrypting packet from %s: %v", pkt.ConnID, err)
			continue
		}

		if isCompressed {
			decoded, err = compress.Decompress(decoded, true)
			if err != nil {
				log.Printf("Error decompressing packet from %s: %v", pkt.ConnID, err)
				continue
			}
		}

		if len(decoded) > 0 {
			if s.cfg.Verbose {
				log.Printf("Received %d bytes from client %s, writing to TUN", len(decoded), pkt.ConnID)
			}
			if _, err := s.tun.Write(decoded); err != nil {
				log.Printf("Error writing packet to TUN: %v", err)
			}
		}
	}
}

// Stop останавливает сервер.
func (s *Server) Stop() error {
	select {
	case <-s.done:
		return nil
	default:
		close(s.done)
	}

	var errs []error

	if s.transport != nil {
		if err := s.transport.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// Дадим горутинам завершиться, ограниченное время
	doneCh := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(5 * time.Second):
	}

	if s.networkManager != nil {
		if err := s.networkManager.Cleanup(); err != nil {
			errs = append(errs, err)
		}
	}

	if s.tun != nil {
		if err := s.tun.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors stopping server: %v", errs)
	}

	return nil
}
