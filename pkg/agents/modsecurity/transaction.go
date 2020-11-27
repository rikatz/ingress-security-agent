package modsecurity

import (
	"fmt"
	"time"

	modsec "github.com/rikatz/go-modsecurity"
	"github.com/rikatz/ingress-security-agent/apis"
)

//ModsecTransaction parses a request and return if it needs intervention
func ModsecTransaction(request *apis.Request, agent *ModsecAgent) (intervention bool, err error) {
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		fmt.Printf("Elapsed time: %s\n", elapsed)
	}()

	var path, ignoreRules string

	// I know this might be slower, but it was the safer way
	// I found to do without getting hit by segfaults from CGO
	var curRules *modsec.RuleSet
	curRules = agent.modsecurity.NewRuleSet()
	err = agent.rules.Merge(curRules)
	if err != nil {
		return false, fmt.Errorf("Modsecurity: Failed to clone additional rules: %v", err)
	}

	if request.IgnoreRules != "" {
		ignoreRules = fmt.Sprint("SecRuleRemoveById " + request.IgnoreRules)
		err := curRules.AddRules(ignoreRules)
		if err != nil {
			return false, fmt.Errorf("Modsecurity: Failed to parse the additional rules: %v", err)
		}
	}

	clientIP := fmt.Sprintf("%s:12345", request.ClientIP)
	srvIP := fmt.Sprintf("%s:%d", request.ServerIP, request.ServerPort)

	transaction, err := curRules.NewTransaction(clientIP, srvIP)

	if err != nil {
		return false, fmt.Errorf("Modsecurity: Failed to process the connection: %v", err)
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
