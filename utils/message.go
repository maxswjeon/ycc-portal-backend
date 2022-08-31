package utils

const (
	INFO = "INFO"
	WARN = "WARN"
	ERROR = "ERROR"
)

type Message struct {
	Message string `json:"message"`
	Type string `json:"type"`
}
