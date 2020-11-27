package spoa

import (
	"fmt"
	"net"

	spoe "github.com/criteo/haproxy-spoe-go"
	apis "github.com/rikatz/ingress-security-agent/apis"
	isa "github.com/rikatz/ingress-security-agent/pkg"
	agents "github.com/rikatz/ingress-security-agent/pkg/agents"
)

/*
type SPOAListener struct {
	address      string
	port         uint16
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}


// GetDecision handles if a request needs intervention based on an agent
func GetDecision(request isa.Request) (intervention bool, err error) {

	return false, nil
}*/

var config isa.Config

func MessageHandler(msgs *spoe.MessageIterator) (actions []spoe.Action, err error) {

	var agent agents.Judger
	var spoeresponse spoe.ActionSetVar
	spoeresponse.Scope = spoe.VarScopeSession
	spoeresponse.Name = ""
	spoeresponse.Value = false

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
// TODO2: validate if all fields are here (ValidateRequest)
// agent and each handler can deal with this differently :)
func PopulateRequest(msg spoe.Message) (request *apis.Request, err error) {
	request = &apis.Request{}

	for msg.Args.Next() {
		arg := msg.Args.Arg
		if value, ok := arg.Value.(string); ok {
			switch arg.Name {
			case "method":
				request.Method = value
				continue
			case "path":
				request.Path = value
				continue
			case "query":
				request.Query = value
				continue
			case "reqver":
				request.Version = value
				continue
			case "ignorerules":
				request.IgnoreRules = value
				continue
			}
		}

		if value, ok := arg.Value.(net.IP); ok {
			switch arg.Name {
			case "srvip":
				request.ServerIP = value.String()
				continue
			case "clientip":
				request.ClientIP = value.String()
				continue
			}
		}

		if value, ok := arg.Value.(int); ok && arg.Name == "srvport" {
			request.ServerPort = value
		}

		if value, ok := arg.Value.([]byte); ok {
			switch arg.Name {
			case "reqhdrs":
				if request.Headers, err = spoe.DecodeHeaders(value); err != nil {
					return &apis.Request{}, fmt.Errorf("Failure decoding the headers")
				}
			case "reqbody":
				request.Body = value
			}
		}
	}
	return request, nil
}

// NewListener starts a new SPOAListener to serve HAProxy requests
func NewListener(IsaConfig isa.Config) error {
	config = IsaConfig
	listener := spoe.New(MessageHandler)
	err := listener.ListenAndServe(":9000")
	if err != nil {
		return err
	}
	return nil
}
