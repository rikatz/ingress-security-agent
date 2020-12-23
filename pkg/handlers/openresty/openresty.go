package openresty

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"encoding/base64"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"

	isa "github.com/rikatz/ingress-security-agent/pkg"

	"github.com/prometheus/client_golang/prometheus"
	apis "github.com/rikatz/ingress-security-agent/apis"
	agents "github.com/rikatz/ingress-security-agent/pkg/agents"
)

var (
	config isa.Config

	openrestyTime = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "openresty",
		Name:      "handler_message_processing_time",
		Buckets:   []float64{.1, 1, 5, 10, 50, 100, 500},
	}, []string{"name", "module"})
)

type requestDecode struct {
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Query       string            `json:"query"`
	Version     string            `json:"version"`
	ClientIP    string            `json:"clientip"`
	ServerIP    string            `json:"serverip"`
	IgnoreRules string            `json:"ignorerules"`
	ServerPort  string            `json:"serverport"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	Namespace   string            `json:"namespace"`
	IngressName string            `json:"ingressname"`
}

// Shameless copied from iprepd :)
func mwHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("X-Frame-Options", "DENY")
		w.Header().Add("X-Content-Type-Options", "nosniff")
		w.Header().Add("Content-Security-Policy",
			"default-src 'none'; frame-ancestors 'none'; report-uri /__cspreport__")
		w.Header().Add("Strict-Transport-Security", "max-age=31536000")
		h.ServeHTTP(w, r)
	})
}

func newRouter() *mux.Router {
	r := mux.NewRouter().StrictSlash(true)

	// For now, those are unauthenticated, but future they should be authenticated
	if config.ModSecAgent {
		r.HandleFunc("/modsecurity", httpModSecurity).Methods("POST")
	}
	if config.RateLimitAgent {
		r.HandleFunc("/ratelimit", httpRateLimit).Methods("GET")
	}

	return r
}

func httpModSecurity(w http.ResponseWriter, r *http.Request) {

	StartedAt := time.Now()
	// TODO: Blah, something is wrong with the metrics from here...
	defer func() {
		Duration := time.Since(StartedAt)
		openrestyTime.WithLabelValues("openresty", "modsecurity").Observe(float64(Duration.Milliseconds()))
	}()
	request, err := PopulateRequest(r)

	if err != nil {
		log.Errorf("Failed to parse Openresty request: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var agent agents.Judger
	agent = agents.NewModSecurityAgent(config.ModSecStruct)

	intervene, err := agent.GetIntervention(request)
	if err != nil {
		log.Errorf("Could not get intervention: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if intervene {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func httpRateLimit(w http.ResponseWriter, r *http.Request) {
	buf := []byte("Rate Limit Not implemented")
	w.Header().Set("Content-Type", "application/json")
	w.Write(buf)
}

// PopulateRequest gets an HTTP Request from Openresty/Json and turns into an internal
// API request
// TODO: Turn this into an interface, as the request is the same for any
// agent and each handler can deal with this differently :)
func PopulateRequest(r *http.Request) (request *apis.Request, err error) {
	var rDecode requestDecode

	request = &apis.Request{}
	err = json.NewDecoder(r.Body).Decode(&rDecode)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode the payload: %v", err)
	}

	if rDecode.Method == "" || rDecode.Path == "" ||
		rDecode.Version == "" || rDecode.ClientIP == "" ||
		rDecode.ServerIP == "" || rDecode.ServerPort == "" {
		return nil, fmt.Errorf("Payload does not contain the required fields")
	}

	srvport, err := strconv.Atoi(rDecode.ServerPort)
	if err != nil {
		return nil, fmt.Errorf("Failed to convert server port from the payload to integer")
	}

	bodyReq, err := base64.StdEncoding.DecodeString(rDecode.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode request body")
	}

	headers := make(http.Header)
	for key, value := range rDecode.Headers {
		headers.Add(key, value)
	}

	request.Method = rDecode.Method
	request.Path = rDecode.Path
	request.Version = rDecode.Version
	request.Query = rDecode.Query
	request.ClientIP = rDecode.ClientIP
	request.ServerIP = rDecode.ServerIP
	request.ServerPort = srvport
	request.IgnoreRules = rDecode.IgnoreRules
	request.Headers = headers
	request.Body = bodyReq
	request.Namespace = rDecode.Namespace
	request.IngressName = rDecode.IngressName

	return request, nil
}

// NewListener starts a new SPOAListener to serve HAProxy requests
func NewListener(IsaConfig isa.Config) error {
	config = IsaConfig
	prometheus.MustRegister(openrestyTime)
	// TODO: This should be configurable
	err := http.ListenAndServe(":8000", mwHandler(newRouter()))
	if err != nil {
		return err
	}
	return nil
}
