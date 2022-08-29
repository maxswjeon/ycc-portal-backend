package utils

import (
	"os"
	"strconv"
	"strings"
	"time"

	mail "github.com/xhit/go-simple-mail/v2"
)

func SendMail(to string, subject string, body string) error {	
	port, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))

	server := mail.NewSMTPClient()
	server.Host = os.Getenv("SMTP_DOMAIN")
	server.Port = port
	server.Username = os.Getenv("SMTP_USER")
	server.Password = os.Getenv("SMTP_PASS")
	server.Helo = os.Getenv("DOMAIN")
	if strings.ToLower(os.Getenv("SMTP_STARTTLS")) == "true" {
		server.Encryption = mail.EncryptionSTARTTLS
	} else {
		server.Encryption = mail.EncryptionSSLTLS
	}
	server.KeepAlive = false

	server.ConnectTimeout = 10 * time.Second
	server.SendTimeout = 10 * time.Second

	client, err := server.Connect()
	if err != nil {
		return err
	}
	defer client.Close()

	email := mail.NewMSG()
	email.SetFrom(os.Getenv("SMTP_SENDER_NAME") + " <" + os.Getenv("SMTP_SENDER_MAIL") + ">").
	  	  AddTo(to).
		  	SetSubject(subject).
				SetBody(mail.TextHTML, body)
		
	if email.Error != nil {
		return email.Error
	}

	return email.Send(client)
}

func SendInitialPasswordMail(to string, username string, password string) error {
	rawTemplate, err := os.ReadFile("templates/initial-password.html")
	if err != nil {
		return err
	}

	template := string(rawTemplate)

	template = strings.ReplaceAll(template, "{{ USERNAME }}", username)
	template = strings.ReplaceAll(template, "{{ PASSWORD }}", password)

	return SendMail(to, "YCC Portal - 초기 비밀번호가 생성되었습니다", template)
}
