package utils

import (
	"crypto/rand"
	"encoding/base64"
	"os"

	"github.com/go-ldap/ldap/v3"
)

func LDAPConnectAndBind(dn string, pw string) (*ldap.Conn, error) {
	conn, err := ldap.DialURL(os.Getenv("LDAP_DOMAIN"))
	if err != nil {
		return nil, err
	}

	conn.Bind(dn, pw)

	return conn, nil
}

func LDAPGeneratePassword() (string, string) {
	rawPass := make([]byte, 24)
	rand.Read(rawPass)

	password := base64.StdEncoding.EncodeToString(rawPass)
	
	encoder := SSHAEncoder{}
	hash := encoder.Encode([]byte(password))
	
	return password, hash
}
