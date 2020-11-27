package modsecurity

import (
	"fmt"
	"time"

	"github.com/rikatz/ingress-security-agent/apis"
)

//ModsecTransaction parses a request and return if it needs intervention
func ModsecTransaction(request *apis.Request, agent *ModsecAgent) (intervention bool, err error) {
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		fmt.Printf("Elapsed time: %s\n", elapsed)
	}()

	var path string

	clientIP := fmt.Sprintf("%s:12345", request.ClientIP)
	srvIP := fmt.Sprintf("%s:%d", request.ServerIP, request.ServerPort)

	transaction, err := agent.rules.NewTransaction(clientIP, srvIP)

	if err != nil {
		return false, fmt.Errorf("Modsecurity: Failed to process the connection: %v", err)
	}

	if request.IgnoreRules != "" {
		transaction.IgnoreRules = request.IgnoreRules
	}
	defer func() {
		transaction.ProcessLogging()
		transaction.Cleanup()
	}()

	path = request.Path
	if request.Query != "" {
		path = fmt.Sprintf("%s?%s", request.Path, request.Query)
	}

	if transaction.ProcessUri(path, request.Method, request.Version) != nil {
		return false, fmt.Errorf("Modsecurity: Failed to process the URI: %s", err.Error())
	}
	if transaction.ShouldIntervene() {
		return true, nil
	}

	for key, values := range request.Headers {
		for _, value := range values {
			if transaction.AddRequestHeader([]byte(key), []byte(value)) != nil {
				return false, fmt.Errorf("Modsecurity: Failed to Add Headers: %s", err.Error())
			}
		}
	}

	// Kubernetes specific. Add the directives into headers to be logged :)
	if request.IngressName != "" && request.Namespace != "" {
		if transaction.AddRequestHeader([]byte("x-kubernetes-namespace"), []byte(request.Namespace)) != nil {
			return false, fmt.Errorf("Modsecurity: Failed to Kubernetes Namespace Headers: %s", err.Error())
		}

		if transaction.AddRequestHeader([]byte("x-kubernetes-ingressname"), []byte(request.IngressName)) != nil {
			return false, fmt.Errorf("Modsecurity: Failed to Kubernetes Ingress Name Headers: %s", err.Error())
		}
	}

	if transaction.ProcessRequestHeaders() != nil {
		return false, fmt.Errorf("Modsecurity: Failed to process the Headers: %s", err.Error())
	}

	if transaction.ShouldIntervene() {
		return true, nil
	}

	if transaction.AppendRequestBody(request.Body) != nil {
		return false, fmt.Errorf("Modsecurity: Failed to append the Body: %s", err.Error())
	}

	if transaction.ProcessRequestBody() != nil {
		return false, fmt.Errorf("Modsecurity: Failed to process the Body: %s", err.Error())
	}

	if transaction.ShouldIntervene() {
		return true, nil
	}

	return false, nil
}
