package email

import (
	"net/smtp"
)

// EmailConfig rappresenta la configurazione necessaria per inviare un'email
type Client struct {
	email string

	auth smtp.Auth
	addr string
}

// Email rappresenta il contenuto dell'email
type Email struct {
	To      []string
	Subject string
	Body    string
}

func NewClient(senderEmail, password, host, port string) *Client {
	return &Client{
		addr: host + ":" + port,
		auth: smtp.PlainAuth("", senderEmail, password, host),
	}
}

// Send invia l'email utilizzando la configurazione fornita
func (config *Client) Send(email Email) error {
	// Costruzione del messaggio
	msg := "From: " + config.email + "\n" +
		"To: " + email.To[0] + "\n" +
		"Subject: " + email.Subject + "\n\n" +
		email.Body

	// Invio email tramite il server SMTP
	err := smtp.SendMail(config.addr, config.auth, config.email, email.To, []byte(msg))
	if err != nil {
		return err
	}

	return nil
}
