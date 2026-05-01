package internal

const (
	// TUNMTU максимальный размер передаваемой единицы (MTU) TUN-интерфейса.
	//
	// Yandex API Gateway поддерживает WebSocket-сообщения до 128 КБ, поэтому жёсткой
	// привязки к UDP MTU (как было раньше) больше нет. Однако стандартный путь до
	// API Gateway проходит через сети с типичным Ethernet MTU, поэтому удобнее
	// держать VPN-MTU чуть ниже 1500: ChaCha20-Poly1305 + флаг сжатия даёт overhead
	// в 29 байт, итого пакет в WebSocket-фрейме укладывается в один TCP-сегмент.
	TUNMTU = 1420
	// HeaderSize размер заголовка протокола (4 байта для размера пакета + 1 байт флаги)
	HeaderSize = 5
	// FlagCompressed флаг сжатия в заголовке (бит 0)
	FlagCompressed = 0x01
)
