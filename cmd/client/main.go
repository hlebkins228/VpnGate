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
)

func main() {
	var (
		serverURL          = flag.String("server", "", "VPN server WebSocket URL (e.g., wss://d5d...apigw.yandexcloud.net/ws)")
		keyFile            = flag.String("key", "", "Path to encryption key file (32 bytes binary or 64 hex chars)")
		clientIP           = flag.String("ip", "10.0.0.2", "Client IP address for TUN interface")
		verbose            = flag.Bool("verbose", false, "Enable verbose logging (logs every packet)")
		pprofAddr          = flag.String("pprof", ":6060", "Address for pprof HTTP server (empty to disable)")
		autoRoutes         = flag.Bool("auto-routes", true, "Automatically configure routes (redirect all traffic through VPN)")
		insecureTLS        = flag.Bool("insecure-tls", false, "Skip TLS certificate verification (debug only)")
		extraHeaders       = flag.String("ws-headers", "", "Comma-separated extra WebSocket handshake headers in 'Key: Value' form")
	)
	flag.Parse()

	if *serverURL == "" {
		log.Fatal("Server URL is required. Use -server flag (e.g. wss://...apigw.yandexcloud.net/ws)")
	}

	if *keyFile == "" {
		log.Fatal("Key file is required. Use -key flag")
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
	headers, err := parseHeaders(*extraHeaders)
	if err != nil {
		log.Fatalf("Failed to parse -ws-headers: %v", err)
	}

	vpnClient, err := client.NewVPNClient(client.VPNClientConfig{
		ServerURL:          *serverURL,
		Key:                key,
		ClientIP:           *clientIP,
		Verbose:            *verbose,
		AutoRoutes:         *autoRoutes,
		ExtraHeaders:       headers,
		InsecureSkipVerify: *insecureTLS,
	})
	if err != nil {
		log.Fatalf("Failed to create VPN client: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	if *pprofAddr != "" {
		go func() {
			log.Printf("Starting pprof server on %s", *pprofAddr)
			log.Println(http.ListenAndServe(*pprofAddr, nil))
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
