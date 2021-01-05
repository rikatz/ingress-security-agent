package spoa

import (
	"fmt"
	"log"
	"net"
	"time"

	spoe "github.com/criteo/haproxy-spoe-go"
	apis "github.com/rikatz/ingress-security-agent/apis"
	isa "github.com/rikatz/ingress-security-agent/pkg"
	agents "github.com/rikatz/ingress-security-agent/pkg/agents"

	"github.com/prometheus/client_golang/prometheus"
)

type SPOAConfig struct {
	Address      string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

/*
// GetDecision handles if a request needs intervention based on an agent
func GetDecision(request isa.Request) (intervention bool, err error) {

	return false, nil
}*/
const expectedSPOEArguments = 8

var (
	config   isa.Config
	spoaTime = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "spoa",
		Name:      "handler_message_processing_time",
		Buckets:   []float64{.1, 1, 5, 10, 50, 100, 500},
	}, []string{"name", "module"})
)

func MessageHandler(msgs *spoe.MessageIterator) (actions []spoe.Action, err error) {

	var agent agents.Judger
	var spoeresponse spoe.ActionSetVar
	spoeresponse.Scope = spoe.VarScopeSession
	spoeresponse.Name = ""
	spoeresponse.Value = false

	StartedAt := time.Now()
	defer func() {
		Duration := time.Since(StartedAt)
		spoaTime.WithLabelValues("spoa", spoeresponse.Name).Observe(float64(Duration.Milliseconds()))
	}()

	for msgs.Next() {
		msg := msgs.Message
		request, err := PopulateRequest(msg)
		if err != nil {
			return nil, fmt.Errorf("Failed to populate the request: %v", err)
		}
		if msg.Name == "modsecurity" && config.ModSecAgent {
			agent = agents.NewModSecurityAgent(config.ModSecStruct)
			spoeresponse.Name = "modsecurity"
		}
		if msg.Name == "rate-limit" && config.RateLimitAgent {
			//agent = agent.NewRateLimitAgent()
			spoeresponse.Name = "rate-limit"
		}
		if msg.Name == "" || agent == nil {
			return nil, fmt.Errorf("spoe handler: Message could not be parsed, no such agent: %s", msg.Name)
		}

		intervene, err := agent.GetIntervention(request)
		if err != nil {
			return nil, fmt.Errorf("Could not parse the message: %s", err.Error())
		}

		if intervene {
			spoeresponse.Value = true
		}
	}

	return []spoe.Action{
		spoeresponse,
	}, nil
}

// TODO: Turn this into an interface, as the request is the same for any
// agent and each handler can deal with this differently :)
func PopulateRequest(msg spoe.Message) (request *apis.Request, err error) {
	var countRequired int
	request = &apis.Request{}

	for msg.Args.Next() {
		arg := msg.Args.Arg
		if value, ok := arg.Value.(string); ok {
			switch arg.Name {
			case "method":
				request.Method = value
				countRequired++
				continue
			case "path":
				request.Path = value
				countRequired++
				continue
			case "query":
				request.Query = value
				continue
			case "reqver":
				request.Version = value
				countRequired++
				continue
			case "ignorerules":
				request.IgnoreRules = value
				continue
			case "namespace":
				request.Namespace = value
				continue
			case "ingressname":
				request.IngressName = value
				continue
			}
		}

		if value, ok := arg.Value.(net.IP); ok {
			switch arg.Name {
			case "srvip":
				request.ServerIP = value.String()
				countRequired++
				continue
			case "clientip":
				request.ClientIP = value.String()
				countRequired++
				continue
			}
		}

		if value, ok := arg.Value.(int); ok && arg.Name == "srvport" {
			countRequired++
			request.ServerPort = value
		}

		if value, ok := arg.Value.([]byte); ok {
			switch arg.Name {
			case "reqhdrs":
				if request.Headers, err = spoe.DecodeHeaders(value); err != nil {
					return &apis.Request{}, fmt.Errorf("Failure decoding the headers")
				}
				countRequired++
				continue
			case "reqbody":
				request.Body = value
				countRequired++
				continue
			}
		}
	}
	if countRequired != expectedSPOEArguments {
		return nil, fmt.Errorf("spoe error: number of expected arguments (%d) is different from the passed arguments: %d", expectedSPOEArguments, countRequired)
	}
	return request, nil
}

// NewListener starts a new SPOAListener to serve HAProxy requests
func NewListener(IsaConfig isa.Config, spoaConfig SPOAConfig) error {
	config = IsaConfig
	agentConfig := spoe.Config{
		ReadTimeout:  spoaConfig.ReadTimeout,
		WriteTimeout: spoaConfig.WriteTimeout,
		IdleTimeout:  spoaConfig.IdleTimeout,
	}

	prometheus.MustRegister(spoaTime)
	listener := spoe.NewWithConfig(MessageHandler, agentConfig)
	go func() {
		err := listener.ListenAndServe(spoaConfig.Address)
		if err != nil {
			log.Fatalf("[SPOA] Error starting the agent: %s", err)
		}
	}()
	return nil
}
