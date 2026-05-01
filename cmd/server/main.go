//go:build linux

// Command myvpn-server — VPN-сервер для Linux.
//
// Транспорт — WebSocket: HTTP-вебхук Yandex API Gateway (POST /ws) и/или
// прямой WS-эндпоинт для локальной отладки. TUN использует
// golang.zx2c4.com/wireguard/tun, NAT — iptables MASQUERADE.
//
// Конфигурация: основные параметры доступны как флагами, так и переменными
// окружения. Редко меняемое — только через переменные окружения.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"myvpn/internal/envcfg"
	"myvpn/internal/transport"
	"myvpn/server"
)

// shutdownTimeout — максимальное время на graceful shutdown.
//
// За это время сервер должен:
//   - закрыть TUN (мгновенно);
//   - отправить close-фреймы активным WS-клиентам и дождаться их закрытия;
//   - завершить in-flight webhook'и от Yandex API Gateway;
//   - откатить iptables/NAT.
const shutdownTimeout = 10 * time.Second

func main() {
	var (
		keyFile = flag.String("key", envcfg.String("MYVPN_KEY", ""),
			"Path to encryption key file (32 bytes). If empty, a random key will be generated. Env: MYVPN_KEY.")
		listenAddr = flag.String("listen", envcfg.String("MYVPN_LISTEN", ":8080"),
			"Address to listen on (HTTP webhook + optional direct WS). Env: MYVPN_LISTEN.")
		directWS = flag.Bool("direct-ws", envcfg.Bool("MYVPN_DIRECT_WS", false),
			"Enable a local direct WebSocket endpoint (path from MYVPN_DIRECT_WS_PATH, default /ws-direct) for testing without API Gateway. Env: MYVPN_DIRECT_WS.")
		verbose = flag.Bool("verbose", envcfg.Bool("MYVPN_VERBOSE", false),
			"Enable verbose logging (logs every packet). Env: MYVPN_VERBOSE.")
	)
	flag.Parse()

	webhookPath := envcfg.String("MYVPN_WEBHOOK_PATH", "/ws")
	directWSPath := ""
	if *directWS {
		directWSPath = envcfg.String("MYVPN_DIRECT_WS_PATH", "/ws-direct")
	}
	pprofAddr := envcfg.String("MYVPN_PPROF_ADDR", "")
	disableYC := envcfg.Bool("MYVPN_DISABLE_YANDEX_API", false)
	iamTokenFile := envcfg.String("MYVPN_IAM_TOKEN_FILE", "")
	iamMetadataURL := envcfg.String("YC_METADATA_URL", transport.YCMetadataTokenURL)
	yandexAPIBase := envcfg.String("YC_CONNECTIONS_API_URL", transport.YCDefaultConnectionsAPIBase)

	if disableYC && directWSPath == "" {
		log.Fatal("With MYVPN_DISABLE_YANDEX_API=true you must enable -direct-ws " +
			"(otherwise the server has no way to talk to clients).")
	}

	key, err := loadOrGenerateKey(*keyFile)
	if err != nil {
		log.Fatalf("Failed to load/generate key: %v", err)
	}

	var pushClient *transport.YCPushClient
	if !disableYC {
		tokens, err := transport.LoadIAMTokenProvider(
			iamTokenFile,
			"", // -iam-token флаг убран; чувствительные значения только из env
			"YC_IAM_TOKEN",
			iamMetadataURL,
		)
		if err != nil {
			log.Fatalf("Failed to set up IAM token provider: %v\n"+
				"Hint: set YC_IAM_TOKEN env var, MYVPN_IAM_TOKEN_FILE env var, "+
				"or run on a Yandex Cloud VM with a service account attached. "+
				"For local testing without IAM, set MYVPN_DISABLE_YANDEX_API=true and pass -direct-ws.", err)
		}
		pushClient, err = transport.NewYCPushClient(transport.YCPushClientConfig{
			BaseURL:       yandexAPIBase,
			TokenProvider: tokens,
		})
		if err != nil {
			log.Fatalf("Failed to create Yandex push client: %v", err)
		}
	}

	srv, err := server.NewServer(server.ServerConfig{
		Listen:       *listenAddr,
		WebhookPath:  webhookPath,
		DirectWSPath: directWSPath,
		Key:          key,
		Verbose:      *verbose,
		PushClient:   pushClient,
	})
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	if pprofAddr != "" {
		go func() {
			log.Printf("Starting pprof server on %s", pprofAddr)
			log.Println(http.ListenAndServe(pprofAddr, nil))
		}()
	}

	// Первый сигнал → graceful shutdown с таймаутом.
	// Второй сигнал → форсированный выход.
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	log.Println("VPN server started. Press Ctrl+C to stop (twice to force quit).")
	<-sigChan
	log.Printf("Shutting down server (graceful timeout %s)...", shutdownTimeout)

	go func() {
		<-sigChan
		log.Fatalf("Forced shutdown — exiting immediately")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	log.Println("Server stopped.")
}

// loadOrGenerateKey загружает ключ из файла или генерирует случайный.
//
// Принимаются те же два формата, что и у клиента: 32 байта бинарных данных
// или 64 hex-символа. Без этой симметрии один и тот же key.bin не работал бы
// одновременно на сервере и клиенте.
func loadOrGenerateKey(keyFile string) ([]byte, error) {
	const (
		keySize    = 32
		hexKeySize = 64
	)

	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		switch len(data) {
		case keySize:
			return data, nil
		case hexKeySize:
			decoded, err := hex.DecodeString(string(data))
			if err != nil {
				return nil, fmt.Errorf("decode hex key: %w", err)
			}
			log.Println("Key file detected as hex format, converted to binary")
			return decoded, nil
		default:
			return nil, fmt.Errorf("invalid key size: got %d, want %d (binary) or %d (hex)",
				len(data), keySize, hexKeySize)
		}
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}
	log.Printf("Generated random key. Hex: %x", key)
	log.Println("Save this key and pass it to clients via -key (binary) or set MYVPN_KEY.")
	return key, nil
}
