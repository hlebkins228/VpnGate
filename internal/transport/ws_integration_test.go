package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestDirectWSRoundTrip проверяет, что прямой WS-режим серверного транспорта
// корректно принимает и отправляет бинарные сообщения.
func TestDirectWSRoundTrip(t *testing.T) {
	srv, err := NewWSServerTransport(WSServerConfig{
		Listen:       "127.0.0.1:0",
		WebhookPath:  "/ws",
		DirectWSPath: "/ws-direct",
	})
	if err != nil {
		t.Fatalf("NewWSServerTransport: %v", err)
	}
	defer srv.Close()

	addr := srv.Addr().String()
	wsURL := "ws://" + addr + "/ws-direct"

	cli, err := NewWSClientTransport(WSClientConfig{
		URL:          wsURL,
		PingInterval: -1,
		PongWait:     -1,
	})
	if err != nil {
		t.Fatalf("NewWSClientTransport: %v", err)
	}
	defer cli.Close()

	want := []byte("hello, vpn over websocket")

	if _, err := cli.Write(want); err != nil {
		t.Fatalf("client Write: %v", err)
	}

	pkt, err := readWithTimeout(srv, 2*time.Second)
	if err != nil {
		t.Fatalf("server Recv: %v", err)
	}
	if !bytes.Equal(pkt.Data, want) {
		t.Fatalf("server got %q, want %q", pkt.Data, want)
	}
	if !strings.HasPrefix(pkt.ConnID, "direct:") {
		t.Fatalf("server got connID %q, expected direct: prefix", pkt.ConnID)
	}

	reply := []byte("ack from server")
	if err := srv.Send(pkt.ConnID, reply); err != nil {
		t.Fatalf("server Send: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatalf("client Read: %v", err)
	}
	if !bytes.Equal(buf[:n], reply) {
		t.Fatalf("client got %q, want %q", buf[:n], reply)
	}
}

// TestWebhookFlow имитирует Yandex API Gateway: посылает webhook'и в серверный
// транспорт и проверяет, что Send() ходит в Connection Management API
// (тоже подменённый на httptest сервер).
func TestWebhookFlow(t *testing.T) {
	// Подменяем Yandex Connection Management API на наш httptest-сервер.
	rec := newRecordingConnAPI()
	apiSrv := httptest.NewServer(rec)
	defer apiSrv.Close()

	tokens, err := NewStaticIAMToken("test-iam-token")
	if err != nil {
		t.Fatalf("NewStaticIAMToken: %v", err)
	}
	push, err := NewYCPushClient(YCPushClientConfig{
		BaseURL:       apiSrv.URL,
		TokenProvider: tokens,
	})
	if err != nil {
		t.Fatalf("NewYCPushClient: %v", err)
	}

	srv, err := NewWSServerTransport(WSServerConfig{
		Listen:      "127.0.0.1:0",
		WebhookPath: "/ws",
		PushClient:  push,
	})
	if err != nil {
		t.Fatalf("NewWSServerTransport: %v", err)
	}
	defer srv.Close()

	gwBase := "http://" + srv.Addr().String() + "/ws"
	connID := "test-conn-1"

	doWebhook(t, gwBase, connID, "CONNECT", nil)

	payload := []byte("encrypted-packet")
	framed, err := AppendFrame(nil, payload)
	if err != nil {
		t.Fatalf("AppendFrame: %v", err)
	}
	doWebhook(t, gwBase, connID, "MESSAGE", framed)

	pkt, err := readWithTimeout(srv, 2*time.Second)
	if err != nil {
		t.Fatalf("server Recv: %v", err)
	}
	if pkt.ConnID != connID {
		t.Fatalf("server got connID %q, want %q", pkt.ConnID, connID)
	}
	if !bytes.Equal(pkt.Data, payload) {
		t.Fatalf("server got %q, want %q", pkt.Data, payload)
	}

	reply := []byte("encrypted-reply")
	if err := srv.Send(connID, reply); err != nil {
		t.Fatalf("server Send: %v", err)
	}

	// Send в новом транспорте складывает пакет в батчер; фактический push
	// произойдёт после окна склеивания (DefaultBatchCoalesceWindow). Ждём,
	// пока запись долетит до httptest-сервера Connection API.
	if err := waitForCondition(2*time.Second, func() bool {
		return len(rec.sent(connID)) >= 1
	}); err != nil {
		t.Fatalf("waiting for push: %v", err)
	}

	got := rec.sent(connID)
	// Каждый сеанс flush'а — это один батч, содержащий N сбатченных VPN-пакетов.
	// В этом тесте одна Send-операция → один батч → одна push-запись.
	expectFramed, err := AppendFrame(nil, reply)
	if err != nil {
		t.Fatalf("AppendFrame reply: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0], expectFramed) {
		t.Fatalf("push API got %v, want [%q]", got, expectFramed)
	}
	if rec.lastAuthHeader() != "Bearer test-iam-token" {
		t.Fatalf("push API got Authorization %q, want %q", rec.lastAuthHeader(), "Bearer test-iam-token")
	}

	doWebhook(t, gwBase, connID, "DISCONNECT", nil)

	if err := srv.Send(connID, reply); err == nil {
		t.Fatalf("expected Send to fail after disconnect")
	}
}

// waitForCondition polls cond() с интервалом 5 мс до d или до выполнения условия.
func waitForCondition(d time.Duration, cond func() bool) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	if cond() {
		return nil
	}
	return errTimeout("condition not met within timeout")
}

// doWebhook отправляет HTTP-вебхук в серверный транспорт, имитируя Yandex API Gateway.
func doWebhook(t *testing.T, urlStr, connID, eventType string, body []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build webhook request: %v", err)
	}
	req.Header.Set(HeaderConnectionID, connID)
	req.Header.Set(HeaderEventType, eventType)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("webhook request %s: %v", eventType, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("webhook %s: status %d, body %q", eventType, resp.StatusCode, respBody)
	}
}

// readWithTimeout получает следующий входящий пакет с ограничением по времени.
func readWithTimeout(srv *WSServerTransport, d time.Duration) (IncomingPacket, error) {
	ch := make(chan IncomingPacket, 1)
	errCh := make(chan error, 1)
	go func() {
		pkt, err := srv.Recv()
		if err != nil {
			errCh <- err
			return
		}
		ch <- pkt
	}()
	select {
	case pkt := <-ch:
		return pkt, nil
	case err := <-errCh:
		return IncomingPacket{}, err
	case <-time.After(d):
		return IncomingPacket{}, errTimeout("timeout waiting for packet")
	}
}

type errTimeout string

func (e errTimeout) Error() string { return string(e) }

// recordingConnAPI имитирует Yandex Connection Management API.
type recordingConnAPI struct {
	mu         sync.Mutex
	sentByConn map[string][][]byte
	lastAuth   string
}

func newRecordingConnAPI() *recordingConnAPI {
	return &recordingConnAPI{sentByConn: make(map[string][][]byte)}
}

func (r *recordingConnAPI) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Path вида /apigateways/websocket/v1/connections/{id}:send
	const prefix = "/apigateways/websocket/v1/connections/"
	if !strings.HasPrefix(req.URL.Path, prefix) {
		http.Error(w, "wrong path", http.StatusNotFound)
		return
	}
	rest := strings.TrimPrefix(req.URL.Path, prefix)
	idx := strings.LastIndex(rest, ":")
	if idx < 0 {
		http.Error(w, "missing :send suffix", http.StatusBadRequest)
		return
	}
	rawID := rest[:idx]
	connID, err := url.PathUnescape(rawID)
	if err != nil {
		http.Error(w, "bad connection id", http.StatusBadRequest)
		return
	}

	body, _ := io.ReadAll(req.Body)
	var payload struct {
		Data string `json:"data"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	data, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		http.Error(w, "bad base64", http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	r.sentByConn[connID] = append(r.sentByConn[connID], data)
	r.lastAuth = req.Header.Get("Authorization")
	r.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func (r *recordingConnAPI) sent(connID string) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.sentByConn[connID]))
	copy(out, r.sentByConn[connID])
	return out
}

func (r *recordingConnAPI) lastAuthHeader() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastAuth
}
