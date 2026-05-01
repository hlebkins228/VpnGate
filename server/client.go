//go:build linux

// Package server содержит VPN-сервер поверх WebSocket-транспорта (HTTP-вебхук
// от Yandex API Gateway или прямой WS-эндпоинт). Linux-only из-за iptables/NAT
// и /dev/net/tun, но низкоуровневый TUN-доступ делегирован
// golang.zx2c4.com/wireguard/tun.
package server

import (
	"context"
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

// ServerConfig — параметры VPN-сервера.
type ServerConfig struct {
	// Listen адрес HTTP-сервера, на который Yandex API Gateway шлёт webhook'и.
	Listen string
	// WebhookPath путь webhook (должен совпадать с URL в OpenAPI спецификации
	// API Gateway). По умолчанию "/ws".
	WebhookPath string
	// DirectWSPath путь для прямого WebSocket-эндпоинта (для локальной отладки).
	// Если пусто — прямой режим выключен.
	DirectWSPath string
	// Key 32-байтный ключ ChaCha20-Poly1305.
	Key []byte
	// Verbose подробное логирование.
	Verbose bool
	// PushClient клиент Connection Management API. Обязателен, если включён
	// webhook-режим (т.е. сервер должен отправлять данные обратно через API Gateway).
	PushClient *transport.YCPushClient
}

// Server — VPN-сервер поверх WebSocket / HTTP webhook.
//
// Список активных клиентов хранит транспорт (transport.WSServerTransport),
// поэтому здесь нет своей карты подключений — это устраняет утечку памяти
// при разрыве соединений и гонки между webhook'ами CONNECT/MESSAGE/DISCONNECT.
type Server struct {
	cfg ServerConfig

	tun            *TUN
	crypto         *internal.Crypto
	transport      *transport.WSServerTransport
	networkManager *NetworkManager

	stopOnce sync.Once
	done     chan struct{}
	wg       sync.WaitGroup
}

// NewServer создаёт VPN-сервер: открывает TUN, готовит crypto и
// NetworkManager. HTTP-сервер запускается в Start.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Listen == "" {
		return nil, errors.New("listen address is required")
	}
	if cfg.WebhookPath == "" {
		cfg.WebhookPath = "/ws"
	}

	tun, err := NewTUN(TUNInterfaceName)
	if err != nil {
		return nil, fmt.Errorf("create TUN: %w", err)
	}

	crypto, err := internal.NewCrypto(cfg.Key)
	if err != nil {
		_ = tun.Close()
		return nil, fmt.Errorf("create crypto: %w", err)
	}

	networkManager, err := NewNetworkManager(tun.Name())
	if err != nil {
		_ = tun.Close()
		return nil, fmt.Errorf("create network manager: %w", err)
	}

	return &Server{
		cfg:            cfg,
		tun:            tun,
		crypto:         crypto,
		networkManager: networkManager,
		done:           make(chan struct{}),
	}, nil
}

// Start настраивает сеть, запускает HTTP-сервер и goroutine'ы маршрутизации
// пакетов. Возвращает управление сразу же после успешного старта.
func (s *Server) Start() error {
	if err := s.networkManager.Setup(); err != nil {
		return fmt.Errorf("setup network: %w", err)
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
		return fmt.Errorf("create WebSocket transport: %w", err)
	}
	s.transport = wsTransport

	log.Printf("VPN server listening on %s (HTTP)", s.cfg.Listen)
	log.Printf("  webhook path:  %s", s.cfg.WebhookPath)
	if s.cfg.DirectWSPath != "" {
		log.Printf("  direct WS:     %s (debug only)", s.cfg.DirectWSPath)
	}
	log.Printf("  TUN interface: %s", s.tun.Name())

	s.wg.Add(2)
	go s.handleTunToClients()
	go s.handleClientsToTun()

	return nil
}

// handleTunToClients читает пакеты из TUN и рассылает всем подключённым клиентам.
func (s *Server) handleTunToClients() {
	defer s.wg.Done()
	buf := make([]byte, internal.TUNMTU)

	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				if err != io.EOF {
					log.Printf("Error reading from TUN: %v", err)
				}
				return
			}
		}
		if n <= 0 {
			continue
		}
		s.broadcastPacket(buf[:n])
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

// encodePacket: LZ4 + ChaCha20-Poly1305, на выходе [флаг(1)] [nonce(12)] [ciphertext+tag].
func (s *Server) encodePacket(packet []byte) ([]byte, error) {
	compressed, isCompressed, err := compress.Compress(packet)
	if err != nil {
		return nil, fmt.Errorf("compression: %w", err)
	}
	encrypted, err := s.crypto.Encrypt(compressed)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(encrypted))
	if isCompressed {
		out[0] = internal.FlagCompressed
	}
	copy(out[1:], encrypted)
	return out, nil
}

// handleClientsToTun читает пакеты от клиентов и записывает их в TUN.
func (s *Server) handleClientsToTun() {
	defer s.wg.Done()

	for {
		pkt, err := s.transport.Recv()
		if err != nil {
			// Recv возвращает ошибку только при остановке транспорта.
			return
		}
		if len(pkt.Data) < 1 {
			continue
		}

		isCompressed := (pkt.Data[0] & internal.FlagCompressed) != 0
		decoded, err := s.crypto.Decrypt(pkt.Data[1:])
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
		if len(decoded) == 0 {
			continue
		}

		if s.cfg.Verbose {
			log.Printf("Received %d bytes from client %s, writing to TUN", len(decoded), pkt.ConnID)
		}
		if _, err := s.tun.Write(decoded); err != nil {
			log.Printf("Error writing packet to TUN: %v", err)
		}
	}
}

// Stop корректно завершает работу сервера с таймаутом 10 секунд.
//
// Эквивалентно Shutdown(timeout=10s).
func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.Shutdown(ctx)
}

// Shutdown — graceful-завершение сервера.
//
// Порядок:
//  1. signal горутинам остановиться;
//  2. закрыть TUN — это разблокирует handleTunToClients, который висит в Read;
//  3. graceful-Shutdown WS-транспорта (close-фреймы клиентам, http.Shutdown,
//     wait на handleDirectWS-горутины) — это разблокирует
//     handleClientsToTun, висящий в transport.Recv;
//  4. подождать сами goroutine сервера, ограниченные ctx;
//  5. убрать iptables/NAT правила и вернуть ip_forward.
//
// Если ctx истекает раньше — продолжаем последовательность всё равно: ресурсы,
// особенно iptables-правила, нужно почистить даже на жёстком таймауте.
func (s *Server) Shutdown(ctx context.Context) error {
	var firstErr error
	s.stopOnce.Do(func() {
		close(s.done)

		if s.tun != nil {
			if err := s.tun.Close(); err != nil {
				firstErr = err
			}
		}

		if s.transport != nil {
			if err := s.transport.Shutdown(ctx); err != nil && firstErr == nil {
				firstErr = err
			}
		}

		doneCh := make(chan struct{})
		go func() {
			s.wg.Wait()
			close(doneCh)
		}()
		select {
		case <-doneCh:
		case <-ctx.Done():
			log.Printf("Warning: server goroutines did not finish before deadline")
		}

		if s.networkManager != nil {
			if err := s.networkManager.Cleanup(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	})
	return firstErr
}
