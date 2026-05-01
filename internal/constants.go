package internal

const (
	// TUNMTU MTU TUN-интерфейса.
	//
	// Yandex API Gateway пропускает WS-сообщения до 128 КБ, но публичный путь до
	// gateway проходит через сети с обычным Ethernet MTU. ChaCha20-Poly1305 +
	// 1-байтный флаг сжатия даёт overhead 29 байт; при MTU 1420 наш WS-фрейм
	// помещается в один TCP-сегмент.
	TUNMTU = 1420

	// FlagCompressed бит флага сжатия LZ4 в первом байте WS-сообщения.
	FlagCompressed = 0x01
)
