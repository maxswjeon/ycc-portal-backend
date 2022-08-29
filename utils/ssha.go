package utils

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
)

type SSHAEncoder struct {
}

func (enc SSHAEncoder) Encode(password []byte) string {
	hash := makeSSHAHash(password, makeSalt())
	b64 := base64.StdEncoding.EncodeToString(hash)
	return fmt.Sprintf("{SSHA}%s", b64)
}

func makeSalt() []byte {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	return bytes
}

func makeSSHAHash(password []byte, salt []byte) []byte {
	sha := sha1.New()
	sha.Write(password)
	sha.Write(salt)

	hash := sha.Sum(nil)
	return append(hash, salt...)
}
