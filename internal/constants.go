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

	// TUNOffset резервируемые байты ПЕРЕД пакетом во всех буферах,
	// передаваемых в golang.zx2c4.com/wireguard/tun.
	//
	// На Linux библиотека по умолчанию открывает /dev/net/tun с флагом
	// IFF_VNET_HDR (для оффлоада/GRO/GSO), и тогда tun.Device.Read/Write
	// требуют, чтобы offset был не меньше длины virtio_net_hdr (10 байт);
	// иначе возвращается ошибка "invalid offset". На Windows (Wintun)
	// и на Linux без vnetHdr offset можно было бы оставить нулём, но
	// проще и безопаснее всегда использовать одну и ту же константу:
	// все backends корректно работают с произвольным положительным offset.
	TUNOffset = 10
)
