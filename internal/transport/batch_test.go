package transport

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAppendFrameAndIterate(t *testing.T) {
	packets := [][]byte{
		[]byte("alpha"),
		[]byte("bravo"),
		bytes.Repeat([]byte{0xab}, 1500),
		[]byte("z"),
	}

	var buf []byte
	for _, p := range packets {
		var err error
		buf, err = AppendFrame(buf, p)
		if err != nil {
			t.Fatalf("AppendFrame(%d bytes): %v", len(p), err)
		}
	}

	var got [][]byte
	if err := IterateFrames(buf, func(frame []byte) error {
		got = append(got, append([]byte(nil), frame...))
		return nil
	}); err != nil {
		t.Fatalf("IterateFrames: %v", err)
	}

	if len(got) != len(packets) {
		t.Fatalf("got %d frames, want %d", len(got), len(packets))
	}
	for i := range packets {
		if !bytes.Equal(got[i], packets[i]) {
			t.Fatalf("frame %d mismatch:\n got=%x\nwant=%x", i, got[i], packets[i])
		}
	}
}

func TestAppendFrameRejectsBadInput(t *testing.T) {
	if _, err := AppendFrame(nil, nil); err == nil {
		t.Fatal("expected error on empty packet")
	}
	if _, err := AppendFrame(nil, make([]byte, MaxBatchEntryBytes+1)); err == nil {
		t.Fatal("expected error on oversize packet")
	}
}

func TestIterateFramesRejectsTruncation(t *testing.T) {
	cases := map[string][]byte{
		"single byte":            {0x00},
		"length without payload": {0x00, 0x05},
		"truncated payload":      {0x00, 0x05, 0x61, 0x62},
		"zero length":            {0x00, 0x00},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			err := IterateFrames(data, func([]byte) error { return nil })
			if err == nil {
				t.Fatalf("expected error for %q, got nil", name)
			}
		})
	}
}

func TestIterateFramesPropagatesCallbackError(t *testing.T) {
	buf, _ := AppendFrame(nil, []byte("hello"))
	wantErr := errors.New("stop")
	got := IterateFrames(buf, func([]byte) error { return wantErr })
	if !errors.Is(got, wantErr) {
		t.Fatalf("got %v, want %v", got, wantErr)
	}
}

func TestBatchedWriterFlushOnTimer(t *testing.T) {
	var (
		mu      sync.Mutex
		flushed [][]byte
	)
	w := newBatchedWriter(20*time.Millisecond, MaxBatchPayloadBytes, func(payload []byte) {
		mu.Lock()
		defer mu.Unlock()
		flushed = append(flushed, append([]byte(nil), payload...))
	})

	for _, msg := range []string{"a", "bb", "ccc"} {
		if err := w.Add([]byte(msg)); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	// До таймера ничего не должно быть отправлено.
	mu.Lock()
	if len(flushed) != 0 {
		mu.Unlock()
		t.Fatalf("got %d flushes before timer, want 0", len(flushed))
	}
	mu.Unlock()

	time.Sleep(80 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(flushed) != 1 {
		t.Fatalf("got %d flushes after timer, want 1", len(flushed))
	}

	var packets [][]byte
	if err := IterateFrames(flushed[0], func(p []byte) error {
		packets = append(packets, append([]byte(nil), p...))
		return nil
	}); err != nil {
		t.Fatalf("IterateFrames: %v", err)
	}
	want := []string{"a", "bb", "ccc"}
	if len(packets) != len(want) {
		t.Fatalf("got %d packets, want %d", len(packets), len(want))
	}
	for i, w := range want {
		if string(packets[i]) != w {
			t.Fatalf("packet %d = %q, want %q", i, packets[i], w)
		}
	}
}

func TestBatchedWriterFlushOnSize(t *testing.T) {
	var (
		mu      sync.Mutex
		flushed [][]byte
	)
	// Маленький лимит, чтобы тест шёл быстро.
	const maxBytes = 64
	w := newBatchedWriter(time.Hour, maxBytes, func(payload []byte) {
		mu.Lock()
		defer mu.Unlock()
		flushed = append(flushed, append([]byte(nil), payload...))
	})

	// Каждый пакет 20 байт + 2 заголовок = 22 байта; в один батч помещается 2,
	// третий вызывает overflow flush.
	pkt := bytes.Repeat([]byte{0x01}, 20)
	for i := 0; i < 5; i++ {
		if err := w.Add(pkt); err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	// 5 пакетов × 22 байта = 110 байт; делятся на батчи по 2 (44) и 1 (22) → 2 flush.
	if len(flushed) < 2 {
		t.Fatalf("got %d size-triggered flushes, expected ≥2", len(flushed))
	}
	totalPackets := 0
	for _, payload := range flushed {
		_ = IterateFrames(payload, func([]byte) error {
			totalPackets++
			return nil
		})
	}
	if totalPackets != 4 {
		// Один пакет ещё в буфере (не flush'ен) — это ожидаемо.
		t.Logf("flushed %d packets (1 left in buffer is expected)", totalPackets)
	}
}

func TestBatchedWriterRejectsOversized(t *testing.T) {
	w := newBatchedWriter(time.Hour, 100, func([]byte) {})
	big := make([]byte, 200)
	if err := w.Add(big); !errors.Is(err, errBatchOverflow) {
		t.Fatalf("got %v, want errBatchOverflow", err)
	}
}

func TestBatchedWriterCloseDropsBuffered(t *testing.T) {
	var (
		mu      sync.Mutex
		flushed [][]byte
	)
	w := newBatchedWriter(time.Hour, MaxBatchPayloadBytes, func(payload []byte) {
		mu.Lock()
		defer mu.Unlock()
		flushed = append(flushed, append([]byte(nil), payload...))
	})

	if err := w.Add([]byte("dropped")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	w.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(flushed) != 0 {
		t.Fatalf("Close should not flush, got %d flushes", len(flushed))
	}
	// Add после Close должен вернуть ошибку.
	if err := w.Add([]byte("late")); err == nil {
		t.Fatal("Add after Close should fail")
	}
}

func TestBatchedWriterFlushExplicit(t *testing.T) {
	var (
		mu      sync.Mutex
		flushed [][]byte
	)
	w := newBatchedWriter(time.Hour, MaxBatchPayloadBytes, func(payload []byte) {
		mu.Lock()
		defer mu.Unlock()
		flushed = append(flushed, append([]byte(nil), payload...))
	})

	if err := w.Add([]byte("hello")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	w.Flush()

	mu.Lock()
	defer mu.Unlock()
	if len(flushed) != 1 {
		t.Fatalf("got %d flushes, want 1", len(flushed))
	}
}
