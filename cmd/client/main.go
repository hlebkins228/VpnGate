// Command myvpn-client — кросс-платформенный VPN-клиент.
//
// Поддерживается Linux (через /dev/net/tun) и Windows 10/11 (через драйвер
// Wintun, https://www.wintun.net/). Транспорт — WebSocket к Yandex API
// Gateway или к прямому WS-эндпоинту сервера.
//
// На Linux требует CAP_NET_ADMIN (обычно — root). На Windows запускать от
// администратора и положить wintun.dll нужной разрядности рядом с .exe.
//
// Конфигурация: основные параметры доступны как флагами, так и переменными
// окружения. Редко меняемое — только через переменные окружения.
package main

import (
	"context"
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

func main() {
	var (
		serverURL = flag.String("server", envcfg.String("MYVPN_SERVER", ""),
			"VPN server WebSocket URL (e.g. wss://...apigw.yandexcloud.net/ws). Env: MYVPN_SERVER.")
		keyFile = flag.String("key", envcfg.String("MYVPN_KEY", ""),
			"Path to encryption key file (32 bytes binary or 64 hex chars). Env: MYVPN_KEY.")
		clientIP = flag.String("ip", envcfg.String("MYVPN_CLIENT_IP", "10.0.0.2"),
			"Client IP address inside the tunnel. Env: MYVPN_CLIENT_IP.")
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

	key, err := loadKey(*keyFile)
	if err != nil {
		log.Fatalf("Failed to load key: %v", err)
	}

	headers, err := parseHeaders(wsHeadersRaw)
	if err != nil {
		log.Fatalf("Failed to parse MYVPN_WS_HEADERS: %v", err)
	}

	vpn, err := client.NewVPNClient(client.VPNClientConfig{
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

	if pprofAddr != "" {
		go func() {
			log.Printf("Starting pprof server on %s", pprofAddr)
			log.Println(http.ListenAndServe(pprofAddr, nil))
		}()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Println("VPN client started. Press Ctrl+C to stop.")

	connectErr := make(chan error, 1)
	go func() { connectErr <- vpn.Connect(ctx) }()

	select {
	case <-ctx.Done():
		log.Println("Shutting down client...")
	case err := <-connectErr:
		if err != nil {
			log.Printf("Connection error: %v", err)
		}
	}

	if err := vpn.Close(); err != nil {
		log.Printf("Error closing client: %v", err)
	}
	log.Println("Client stopped.")
}

// loadKey читает ключ из файла. Поддерживается как сырой бинарный формат
// (ровно 32 байта), так и hex (64 шестнадцатеричных символа).
func loadKey(path string) ([]byte, error) {
	const keySize = 32
	const hexKeySize = 64

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch len(data) {
	case hexKeySize:
		key, err := hex.DecodeString(string(data))
		if err != nil {
			return nil, err
		}
		log.Println("Key file detected as hex format, converted to binary")
		return key, nil
	case keySize:
		return data, nil
	default:
		return nil, &keyFormatError{Got: len(data)}
	}
}

type keyFormatError struct{ Got int }

func (e *keyFormatError) Error() string {
	return "invalid key size: expected 32 bytes (binary) or 64 chars (hex)"
}

// parseHeaders преобразует строку "Key1: Val1, Key2: Val2" в http.Header.
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

type headerParseError struct{ Raw string }

func (e *headerParseError) Error() string {
	return "expected 'Key: Value' header, got: " + e.Raw
}
