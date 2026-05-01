//go:build linux

package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"myvpn/internal/envcfg"
	"myvpn/internal/transport"
	"myvpn/server"
)

// Конфигурация сервера максимально лаконична: основные параметры доступны
// одновременно как флаги и как переменные окружения, остальное — переменные
// окружения с разумными значениями по умолчанию.
//
// Флаги:
//
//	-key       путь к файлу с ключом (если не задан — будет сгенерирован случайный) (env MYVPN_KEY)
//	-listen    адрес HTTP-сервера                                                   (env MYVPN_LISTEN, default :8080)
//	-direct-ws включить локальный WS endpoint для отладки без API Gateway           (env MYVPN_DIRECT_WS)
//	-verbose   подробное логирование                                                (env MYVPN_VERBOSE)
//
// Переменные окружения (без дублирующих флагов):
//
//	YC_IAM_TOKEN              статический IAM-токен Yandex Cloud (sensitive — env-only)
//	MYVPN_IAM_TOKEN_FILE      путь к файлу с IAM-токеном (читается периодически)
//	MYVPN_PPROF_ADDR          адрес pprof HTTP сервера (пусто = выключен)
//	MYVPN_WEBHOOK_PATH        путь webhook (default /ws)
//	MYVPN_DIRECT_WS_PATH      путь прямого WS (default /ws-direct, действует при -direct-ws)
//	MYVPN_DISABLE_YANDEX_API  true|false — выключить Yandex API push (только direct WS)
//	YC_METADATA_URL           переопределить URL metadata-сервиса
//	YC_CONNECTIONS_API_URL    переопределить базовый URL Connection Management API
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
			"", // -iam-token flag is gone; sensitive values come from env only
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

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	log.Println("VPN server started. Press Ctrl+C to stop.")
	<-sigChan

	log.Println("Shutting down server...")
	if err := srv.Stop(); err != nil {
		log.Printf("Error stopping server: %v", err)
	}

	log.Println("Server stopped.")
}

// loadOrGenerateKey загружает ключ из файла или генерирует новый.
func loadOrGenerateKey(keyFile string) ([]byte, error) {
	const keySize = 32 // 32 байта для ChaCha20-Poly1305

	if keyFile != "" {
		key, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}

		if len(key) != keySize {
			return nil, fmt.Errorf("invalid key size: expected %d bytes, got %d", keySize, len(key))
		}

		return key, nil
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	log.Println("Generated random encryption key. Save it for client configuration!")
	log.Printf("Key (hex): %x\n", key)

	return key, nil
}
