package transport

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// TestClientReconnectsAfterServerRestart проверяет, что WSClientTransport
// автоматически переподключается, когда серверный transport закрыт и поднят
// заново на том же порту.
func TestClientReconnectsAfterServerRestart(t *testing.T) {
	srv1, err := NewWSServerTransport(WSServerConfig{
		Listen:       "127.0.0.1:0",
		WebhookPath:  "/ws",
		DirectWSPath: "/ws-direct",
	})
	if err != nil {
		t.Fatalf("NewWSServerTransport (1): %v", err)
	}
	addr := srv1.Addr().String()
	wsURL := "ws://" + addr + "/ws-direct"

	cli, err := NewWSClientTransport(WSClientConfig{
		URL:          wsURL,
		PingInterval: -1,
		PongWait:     -1,
		// Быстрый backoff, чтобы тест не тупил.
		ReconnectMin: 50 * time.Millisecond,
		ReconnectMax: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWSClientTransport: %v", err)
	}
	defer cli.Close()

	// 1) Первое сообщение проходит туда-обратно через srv1.
	want1 := []byte("hello before restart")
	if _, err := cli.Write(want1); err != nil {
		t.Fatalf("client Write 1: %v", err)
	}
	pkt, err := readWithTimeout(srv1, 2*time.Second)
	if err != nil {
		t.Fatalf("server Recv 1: %v", err)
	}
	if !bytes.Equal(pkt.Data, want1) {
		t.Fatalf("server got %q, want %q", pkt.Data, want1)
	}

	// 2) Запускаем фоновый Read на клиенте и роняем сервер.
	readDone := make(chan struct {
		n   int
		err error
		buf []byte
	}, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := cli.Read(buf)
		readDone <- struct {
			n   int
			err error
			buf []byte
		}{n, err, buf}
	}()

	// Принудительно роняем srv1 — клиентский Read должен увидеть ошибку и начать reconnect.
	_ = srv1.Close()

	// 3) Поднимаем НА ТОМ ЖЕ адресе новый серверный транспорт.
	// Чтобы переиспользовать порт надёжно, выберем :0 → новый случайный порт
	// и создадим клиент заново — это всё-таки Linux-only fly. Но в этом тесте
	// мы на это не идём, чтобы не плодить второго клиента; тестируем
	// исключительно reconnect к тому же URL. Поэтому сразу же запускаем srv2
	// на тот же addr.
	var srv2 *WSServerTransport
	for i := 0; i < 50; i++ {
		srv2, err = NewWSServerTransport(WSServerConfig{
			Listen:       addr,
			WebhookPath:  "/ws",
			DirectWSPath: "/ws-direct",
		})
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if srv2 == nil {
		t.Fatalf("could not bind srv2 on %s after server restart: %v", addr, err)
	}
	defer srv2.Close()

	// 4) Клиент должен переподключиться. Шлём пакет с серверной стороны;
	// клиент должен его получить из ожидающего Read'а.
	// Чтобы Send смог найти клиента — дождёмся CONNECT в srv2 (он приходит,
	// когда клиент успешно переподключится).
	deadline := time.After(5 * time.Second)
	var connID string
	for {
		ids := srv2.Conns()
		if len(ids) > 0 {
			connID = ids[0]
			break
		}
		select {
		case <-deadline:
			t.Fatalf("client did not reconnect to srv2 within 5s")
		case <-time.After(50 * time.Millisecond):
		}
	}

	wantReply := []byte("hello after restart")
	if err := srv2.Send(connID, wantReply); err != nil {
		t.Fatalf("srv2 Send: %v", err)
	}

	select {
	case res := <-readDone:
		if res.err != nil {
			t.Fatalf("client Read after reconnect: %v", res.err)
		}
		if !bytes.Equal(res.buf[:res.n], wantReply) {
			t.Fatalf("client got %q, want %q", res.buf[:res.n], wantReply)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("client did not deliver Read within 3s after server restart")
	}
}

// TestClientWriteDuringReconnectDropsSilently проверяет, что Write во время
// переподключения дропает пакет (и не блокируется), не возвращая ошибку.
// Это важно для VPN: TCP внутри туннеля сам перешлёт потерянные сегменты, а
// блокировка/ошибка в Write вызвала бы лавинообразный shutdown VPN-клиента.
func TestClientWriteDuringReconnectDropsSilently(t *testing.T) {
	srv, err := NewWSServerTransport(WSServerConfig{
		Listen:       "127.0.0.1:0",
		WebhookPath:  "/ws",
		DirectWSPath: "/ws-direct",
	})
	if err != nil {
		t.Fatalf("NewWSServerTransport: %v", err)
	}
	addr := srv.Addr().String()
	wsURL := "ws://" + addr + "/ws-direct"

	cli, err := NewWSClientTransport(WSClientConfig{
		URL:          wsURL,
		PingInterval: -1,
		PongWait:     -1,
		ReconnectMin: 100 * time.Millisecond,
		ReconnectMax: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWSClientTransport: %v", err)
	}
	defer cli.Close()

	// Роняем сервер и сразу же делаем Write — он должен мгновенно вернуться
	// без ошибки, потому что conn пометится сломанным.
	_ = srv.Close()

	// Дадим клиенту время заметить разрыв (через ping/read недоступно, потому
	// что мы их выключили — но первое write упадёт само). Делаем write в
	// цикле: первый может ещё успеть; следующие должны идти в "drop" ветку.
	var (
		dropped int
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(1500 * time.Millisecond)
		for time.Now().Before(deadline) {
			n, err := cli.Write([]byte("payload"))
			if err != nil {
				t.Errorf("Write returned error %v while reconnect should be transparent", err)
				return
			}
			if n != len("payload") {
				t.Errorf("Write returned n=%d, want %d", n, len("payload"))
				return
			}
			dropped++
			time.Sleep(20 * time.Millisecond)
		}
	}()
	wg.Wait()

	if dropped == 0 {
		t.Fatalf("expected at least one Write during reconnect attempts, got 0")
	}
}
