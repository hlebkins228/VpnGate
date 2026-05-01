package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// YCDefaultConnectionsAPIBase базовый URL Connection Management API
	// Yandex API Gateway (REST) для отправки данных в WebSocket-соединение.
	//
	// Реальный публичный домен: apigateway-connections.api.cloud.yandex.net
	YCDefaultConnectionsAPIBase = "https://apigateway-connections.api.cloud.yandex.net"

	// ycSendPath шаблон пути для отправки данных в конкретное соединение.
	ycSendPath = "/apigateways/websocket/v1/connections/%s:send"

	// YCMaxSendDataBytes максимальный размер тела (после base64-кодирования)
	// согласно ограничениям Yandex API Gateway (131072 символа).
	// Это ~96 КБ исходных бинарных данных.
	YCMaxSendDataBytes = 96 * 1024

	// pushDefaultTimeout таймаут на одну отправку.
	pushDefaultTimeout = 10 * time.Second
)

// YCPushClient клиент для отправки данных в WebSocket-соединение Yandex API Gateway.
type YCPushClient struct {
	baseURL string
	tokens  IAMTokenProvider
	client  *http.Client
}

// YCPushClientConfig параметры YCPushClient.
type YCPushClientConfig struct {
	// BaseURL базовый URL Connection Management API. Если пусто — YCDefaultConnectionsAPIBase.
	BaseURL string
	// TokenProvider провайдер IAM-токенов. Обязателен.
	TokenProvider IAMTokenProvider
	// Timeout таймаут на один запрос. 0 = pushDefaultTimeout.
	Timeout time.Duration
}

// NewYCPushClient создаёт клиент Connection Management API.
func NewYCPushClient(cfg YCPushClientConfig) (*YCPushClient, error) {
	if cfg.TokenProvider == nil {
		return nil, errors.New("IAM token provider is required")
	}
	base := cfg.BaseURL
	if base == "" {
		base = YCDefaultConnectionsAPIBase
	}
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("invalid Connection API base URL %q: %w", base, err)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = pushDefaultTimeout
	}
	return &YCPushClient{
		baseURL: strings.TrimRight(base, "/"),
		tokens:  cfg.TokenProvider,
		client:  &http.Client{Timeout: timeout},
	}, nil
}

// SendBinary отправляет бинарные данные клиенту по идентификатору соединения.
func (c *YCPushClient) SendBinary(ctx context.Context, connectionID string, data []byte) error {
	if connectionID == "" {
		return errors.New("connection ID is empty")
	}
	if len(data) > YCMaxSendDataBytes {
		return fmt.Errorf("payload too large: %d bytes (max %d)", len(data), YCMaxSendDataBytes)
	}

	body, err := json.Marshal(struct {
		Data string `json:"data"`
		Type string `json:"type"`
	}{
		Data: base64.StdEncoding.EncodeToString(data),
		Type: "BINARY",
	})
	if err != nil {
		return fmt.Errorf("marshal send body: %w", err)
	}

	target := c.baseURL + fmt.Sprintf(ycSendPath, url.PathEscape(connectionID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}

	token, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("get IAM token: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("send to connection %s: %w", connectionID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
		return fmt.Errorf("send to connection %s: HTTP %d: %s",
			connectionID, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
