package apis

import "net/http"

// Request represents an HTTP Request to be parsed
type Request struct {
	Method      string
	Path        string
	Query       string
	Version     string
	ClientIP    string
	ServerIP    string
	IgnoreRules string
	ServerPort  int
	Headers     http.Header
	Body        []byte
}
