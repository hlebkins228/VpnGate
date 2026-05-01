package main

import (
	"encoding/hex"
	"flag"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"myvpn/client"
	"myvpn/internal/envcfg"
)

// Конфигурация клиента максимально лаконична: обязательные параметры можно
// задать как флагами, так и переменными окружения, остальное — переменные
// окружения с разумными значениями по умолчанию.
//
// Флаги:
//
//	-server   wss://... URL сервера / Yandex API Gateway (env MYVPN_SERVER)
//	-key      путь к файлу с ключом                       (env MYVPN_KEY)
//	-ip       IP адрес TUN-интерфейса клиента             (env MYVPN_CLIENT_IP, default 10.0.0.2)
//	-verbose  подробное логирование                       (env MYVPN_VERBOSE)
//
// Переменные окружения (без дублирующих флагов):
//
//	MYVPN_AUTO_ROUTES   true|false (default true) — направлять весь трафик в VPN
//	MYVPN_INSECURE_TLS  true|false (default false) — пропускать проверку TLS-сертификата
//	MYVPN_PPROF_ADDR    адрес pprof HTTP сервера (пусто = выключен)
//	MYVPN_WS_HEADERS    "Key1: Val1, Key2: Val2" — доп. заголовки WebSocket-рукопожатия
func main() {
	var (
		serverURL = flag.String("server", envcfg.String("MYVPN_SERVER", ""),
			"VPN server WebSocket URL (e.g. wss://...apigw.yandexcloud.net/ws). Env: MYVPN_SERVER.")
		keyFile = flag.String("key", envcfg.String("MYVPN_KEY", ""),
			"Path to encryption key file (32 bytes binary or 64 hex chars). Env: MYVPN_KEY.")
		clientIP = flag.String("ip", envcfg.String("MYVPN_CLIENT_IP", "10.0.0.2"),
			"Client IP address for TUN interface. Env: MYVPN_CLIENT_IP.")
		verbose = flag.Bool("verbose", envcfg.Bool("MYVPN_VERBOSE", false),
			"Enable verbose logging (logs every packet). Env: MYVPN_VERBOSE.")
	)
	flag.Parse()

	autoRoutes := envcfg.Bool("MYVPN_AUTO_ROUTES", true)
	insecureTLS := envcfg.Bool("MYVPN_INSECURE_TLS", false)
	pprofAddr := envcfg.String("MYVPN_PPROF_ADDR", "")
	wsHeadersRaw := envcfg.String("MYVPN_WS_HEADERS", "")

	if *serverURL == "" {
		log.Fatal("Server URL is required. Pass -server wss://... or set MYVPN_SERVER env var.")
	}
	if *keyFile == "" {
		log.Fatal("Key file is required. Pass -key /path/to/key or set MYVPN_KEY env var.")
	}

	keyData, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatalf("Failed to read key file: %v", err)
	}

	// Определяем формат ключа и конвертируем при необходимости
	var key []byte
	const keySize = 32
	const hexKeySize = 64 // 32 байта в hex = 64 символа

	if len(keyData) == hexKeySize {
		key, err = hex.DecodeString(string(keyData))
		if err != nil {
			log.Fatalf("Failed to decode hex key: %v", err)
		}
		if len(key) != keySize {
			log.Fatalf("Invalid hex key: decoded to %d bytes, expected %d", len(key), keySize)
		}
		log.Println("Key file detected as hex format, converted to binary")
	} else if len(keyData) == keySize {
		key = keyData
	} else {
		log.Fatalf("Invalid key size: expected %d bytes (binary) or %d chars (hex), got %d",
			keySize, hexKeySize, len(keyData))
	}

	// Парсим дополнительные заголовки рукопожатия (если заданы)
	headers, err := parseHeaders(wsHeadersRaw)
	if err != nil {
		log.Fatalf("Failed to parse MYVPN_WS_HEADERS: %v", err)
	}

	vpnClient, err := client.NewVPNClient(client.VPNClientConfig{
		ServerURL:          *serverURL,
		Key:                key,
		ClientIP:           *clientIP,
		Verbose:            *verbose,
		AutoRoutes:         autoRoutes,
		ExtraHeaders:       headers,
		InsecureSkipVerify: insecureTLS,
	})
	if err != nil {
		log.Fatalf("Failed to create VPN client: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	if pprofAddr != "" {
		go func() {
			log.Printf("Starting pprof server on %s", pprofAddr)
			log.Println(http.ListenAndServe(pprofAddr, nil))
		}()
	}

	errChan := make(chan error, 1)
	go func() {
		if err := vpnClient.Connect(); err != nil {
			errChan <- err
		}
	}()

	log.Println("VPN client started. Press Ctrl+C to stop.")

	select {
	case <-sigChan:
		log.Println("Shutting down client...")
	case err := <-errChan:
		log.Printf("Connection error: %v", err)
	}

	if err := vpnClient.Close(); err != nil {
		log.Printf("Error closing client: %v", err)
	}

	log.Println("Client stopped.")
}

// parseHeaders преобразует строку "Key1: Value1, Key2: Value2" в http.Header.
func parseHeaders(raw string) (http.Header, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	headers := http.Header{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		idx := strings.Index(item, ":")
		if idx <= 0 {
			return nil, &headerParseError{Raw: item}
		}
		k := strings.TrimSpace(item[:idx])
		v := strings.TrimSpace(item[idx+1:])
		if k == "" {
			return nil, &headerParseError{Raw: item}
		}
		headers.Add(k, v)
	}
	return headers, nil
}

type headerParseError struct {
	Raw string
}

func (e *headerParseError) Error() string {
	return "expected 'Key: Value' header, got: " + e.Raw
}
