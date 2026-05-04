package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// YCMetadataTokenURL стандартный URL метадата сервиса Yandex Cloud,
	// возвращающий IAM-токен сервисного аккаунта, привязанного к ВМ.
	YCMetadataTokenURL = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

	// metadataRefreshSafetyMargin запас по времени для обновления токена
	// до его истечения (метадата выдаёт TTL ~12 часов).
	metadataRefreshSafetyMargin = 5 * time.Minute

	// fileTokenRefreshInterval как часто перечитывать токен из файла.
	fileTokenRefreshInterval = 5 * time.Minute
)

// IAMTokenProvider возвращает актуальный IAM-токен Yandex Cloud.
//
// Реализации обязаны быть потокобезопасными.
type IAMTokenProvider interface {
	Token(ctx context.Context) (string, error)
}

// StaticIAMToken — простой провайдер с фиксированным токеном.
//
// Полезен для коротких сессий: токен из `yc iam create-token` живёт ~12 часов.
type StaticIAMToken struct {
	value string
}

// NewStaticIAMToken создаёт провайдер с заданным токеном.
func NewStaticIAMToken(token string) (*StaticIAMToken, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("static IAM token is empty")
	}
	return &StaticIAMToken{value: token}, nil
}

// Token возвращает заранее заданный IAM-токен.
func (s *StaticIAMToken) Token(_ context.Context) (string, error) {
	return s.value, nil
}

// FileIAMToken читает IAM токен из файла и периодически перечитывает его.
//
// Используется в связке с внешним обновлением токена (cron / systemd timer,
// например `yc iam create-token > /run/yc-iam-token` каждый час).
type FileIAMToken struct {
	path     string
	interval time.Duration

	mu       sync.RWMutex
	token    string
	loadedAt time.Time
}

// NewFileIAMToken создаёт провайдер, читающий токен из файла.
//
// При interval == 0 используется fileTokenRefreshInterval.
func NewFileIAMToken(path string, interval time.Duration) (*FileIAMToken, error) {
	if path == "" {
		return nil, errors.New("IAM token file path is empty")
	}
	if interval <= 0 {
		interval = fileTokenRefreshInterval
	}
	p := &FileIAMToken{path: path, interval: interval}
	if err := p.refresh(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *FileIAMToken) refresh() error {
	data, err := os.ReadFile(p.path)
	if err != nil {
		return fmt.Errorf("read IAM token file %q: %w", p.path, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return fmt.Errorf("IAM token file %q is empty", p.path)
	}
	p.mu.Lock()
	p.token = token
	p.loadedAt = time.Now()
	p.mu.Unlock()
	return nil
}

// Token возвращает текущий IAM-токен, перечитывая файл при необходимости.
func (p *FileIAMToken) Token(_ context.Context) (string, error) {
	p.mu.RLock()
	tok := p.token
	loadedAt := p.loadedAt
	p.mu.RUnlock()

	if time.Since(loadedAt) >= p.interval {
		if err := p.refresh(); err != nil {
			// Возвращаем уже загруженное значение, лог-ошибку проксируем наверх
			if tok != "" {
				return tok, nil
			}
			return "", err
		}
		p.mu.RLock()
		tok = p.token
		p.mu.RUnlock()
	}
	if tok == "" {
		return "", errors.New("IAM token is empty")
	}
	return tok, nil
}

// MetadataIAMToken получает IAM токен из metadata-сервиса Yandex Cloud
// (работает на ВМ Compute Cloud / Serverless Containers с привязанным SA).
type MetadataIAMToken struct {
	url    string
	client *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// NewMetadataIAMToken создаёт metadata-провайдер.
//
// Если url пустой, используется YCMetadataTokenURL.
func NewMetadataIAMToken(url string) *MetadataIAMToken {
	if url == "" {
		url = YCMetadataTokenURL
	}
	return &MetadataIAMToken{
		url:    url,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Token возвращает IAM-токен, обновляя его при необходимости.
func (p *MetadataIAMToken) Token(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.token != "" && time.Until(p.expiresAt) > metadataRefreshSafetyMargin {
		return p.token, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata IAM token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("metadata IAM token: status %d: %s", resp.StatusCode, string(body))
	}

	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("metadata IAM token decode: %w", err)
	}
	if payload.AccessToken == "" {
		return "", errors.New("metadata IAM token: empty access_token")
	}

	p.token = payload.AccessToken
	if payload.ExpiresIn > 0 {
		p.expiresAt = time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second)
	} else {
		p.expiresAt = time.Now().Add(time.Hour)
	}
	return p.token, nil
}

// LoadIAMTokenProvider выбирает источник IAM токена по конфигурации.
//
// Приоритет:
//  1. iamTokenFile (если задан) — провайдер из файла.
//  2. iamTokenValue (если задан) — статический токен.
//  3. envName (если задан и переменная не пустая) — статический из ENV.
//  4. metadataURL (если задан) — metadata-сервис.
//
// Если ни один источник не указан, возвращается ошибка. Возвращает также
// человекочитаемое описание выбранного источника — для информативного
// логирования при старте сервера.
func LoadIAMTokenProvider(iamTokenFile, iamTokenValue, envName, metadataURL string) (IAMTokenProvider, string, error) {
	if iamTokenFile != "" {
		p, err := NewFileIAMToken(iamTokenFile, 0)
		if err != nil {
			return nil, "", err
		}
		return p, fmt.Sprintf("file %q", iamTokenFile), nil
	}
	if iamTokenValue != "" {
		p, err := NewStaticIAMToken(iamTokenValue)
		if err != nil {
			return nil, "", err
		}
		return p, "static value", nil
	}
	if envName != "" {
		if v := strings.TrimSpace(os.Getenv(envName)); v != "" {
			p, err := NewStaticIAMToken(v)
			if err != nil {
				return nil, "", err
			}
			return p, fmt.Sprintf("env %s", envName), nil
		}
	}
	if metadataURL != "" {
		return NewMetadataIAMToken(metadataURL), fmt.Sprintf("compute metadata service (%s)", metadataURL), nil
	}
	return nil, "", errors.New("no IAM token source configured (use -iam-token, -iam-token-file or -iam-metadata)")
}
