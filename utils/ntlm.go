package utils

import (
	"encoding/hex"

	"golang.org/x/crypto/md4"
)

func NTLMHash(password string) string {
	var data []byte
	for _, b := range []byte(password) {
		data = append(data, b)
		data = append(data, 0x00)
	}

	encoder := md4.New()
	encoder.Write(data)
	return hex.EncodeToString(encoder.Sum(nil))
}
