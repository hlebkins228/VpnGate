// Package envcfg содержит небольшие хелперы для чтения конфигурации из
// переменных окружения. Используется CLI клиента и сервера.
package envcfg

import (
	"log"
	"os"
	"strconv"
)

// String возвращает значение env-переменной, если она задана и непуста,
// иначе значение по умолчанию.
func String(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

// Bool читает env-переменную как bool. Принимает значения, понятные strconv.ParseBool
// ("1", "0", "true", "false", "TRUE", "False" и т.п.). При ошибке логирует warning
// и возвращает значение по умолчанию.
func Bool(name string, def bool) bool {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		log.Printf("envcfg: invalid bool value for %s=%q, using default %v", name, v, def)
		return def
	}
	return b
}
