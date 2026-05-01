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
	"time"

	"myvpn/internal/transport"
	"myvpn/server"
)

func main() {
	var (
		listenAddr   = flag.String("listen", ":8080", "Address to listen on (HTTP webhook + optional direct WS)")
		webhookPath  = flag.String("webhook-path", "/ws", "URL path for Yandex API Gateway webhook")
		directWSPath = flag.String("direct-ws-path", "", "Optional direct WebSocket path for local testing without API Gateway (e.g. /ws-direct). Empty disables direct mode.")
		keyFile      = flag.String("key", "", "Path to encryption key file (32 bytes). If not provided, a random key will be generated")
		verbose      = flag.Bool("verbose", false, "Enable verbose logging (logs every packet)")
		pprofAddr    = flag.String("pprof", ":6060", "Address for pprof HTTP server (empty to disable)")
		metricsAddr  = flag.String("metrics", ":6061", "Address for metrics HTTP server (empty to disable)")

		// Yandex Cloud authentication for the Connection Management API
		// (used to push packets back to clients via API Gateway).
		iamTokenFile = flag.String("iam-token-file", "",
			"Path to a file containing a Yandex Cloud IAM token (refreshed periodically). "+
				"Use this when running outside Yandex Cloud and refreshing the token externally.")
		iamTokenValue = flag.String("iam-token", "",
			"Yandex Cloud IAM token (static). For long-running servers prefer -iam-token-file or metadata service.")
		iamMetadataURL = flag.String("iam-metadata-url", transport.YCMetadataTokenURL,
			"URL of the Yandex Cloud metadata service for fetching IAM tokens. "+
				"Used when no static token / token file is provided. Empty disables metadata lookup.")
		yandexAPIBase = flag.String("yc-connections-api", transport.YCDefaultConnectionsAPIBase,
			"Base URL of the Yandex API Gateway Connection Management API")
		disableYC = flag.Bool("disable-yandex-api", false,
			"Disable Yandex API Gateway integration (only -direct-ws-path will work). Useful for local testing.")
	)
	flag.Parse()

	if *directWSPath == "" && *disableYC {
		log.Fatal("With -disable-yandex-api you must also provide -direct-ws-path " +
			"(otherwise the server has no way to talk to clients).")
	}

	key, err := loadOrGenerateKey(*keyFile)
	if err != nil {
		log.Fatalf("Failed to load/generate key: %v", err)
	}

	var pushClient *transport.YCPushClient
	if !*disableYC {
		tokens, err := transport.LoadIAMTokenProvider(
			*iamTokenFile,
			*iamTokenValue,
			"YC_IAM_TOKEN",
			*iamMetadataURL,
		)
		if err != nil {
			log.Fatalf("Failed to set up IAM token provider: %v\n"+
				"Hint: provide one of -iam-token, -iam-token-file, YC_IAM_TOKEN env var, "+
				"or run on a Yandex Cloud VM with a service account attached.", err)
		}
		pushClient, err = transport.NewYCPushClient(transport.YCPushClientConfig{
			BaseURL:       *yandexAPIBase,
			TokenProvider: tokens,
		})
		if err != nil {
			log.Fatalf("Failed to create Yandex push client: %v", err)
		}
	}

	srv, err := server.NewServer(server.ServerConfig{
		Listen:       *listenAddr,
		WebhookPath:  *webhookPath,
		DirectWSPath: *directWSPath,
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

	if *pprofAddr != "" {
		go func() {
			log.Printf("Starting pprof server on %s", *pprofAddr)
			log.Println(http.ListenAndServe(*pprofAddr, nil))
		}()
	}

	if *metricsAddr != "" {
		go startMetricsServer(*metricsAddr)
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

// loadOrGenerateKey загружает ключ из файла или генерирует новый
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

// startMetricsServer запускает HTTP сервер для метрик
func startMetricsServer(addr string) {
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "# VPN Server Metrics\n")
		fmt.Fprintf(w, "# Time: %s\n\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(w, "metrics_endpoint_active 1\n")
	})

	log.Printf("Starting metrics server on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Printf("Metrics server error: %v", err)
	}
}
