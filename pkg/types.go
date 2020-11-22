package isa

type Config struct {
	ModSecRulesFile string
	ModSecAgent     bool
	RateLimitAgent  bool
	NumberOfThreads int
}

// Request represents an HTTP Request to be parsed
type Request struct {
	Method     string
	Path       string
	Query      string
	Version    string
	ClientIP   string
	ServerIP   string
	ServerPort int
	Headers    []Header
	Body       []byte
}

// Header represent a struct with the Name and Value of a Header
type Header struct {
	Name  string
	Value string
}
