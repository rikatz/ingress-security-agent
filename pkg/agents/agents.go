package agents

import (
	"github.com/rikatz/ingress-security-agent/apis"
	"github.com/rikatz/ingress-security-agent/pkg/agents/modsecurity"
)

// Judger specifies an agent that Judges a Request
// TODO: A better name here please
type Judger interface {
	GetIntervention(*apis.Request) (bool, error)
}

// ModSecurityAgent defines a struct containing the
// current Modsecurity engine
type ModSecurityAgent struct {
	Agent *modsecurity.ModsecAgent
}

// NewModSecurityAgent creates a New ModSecurity agent to be used in the
func NewModSecurityAgent(Agent *modsecurity.ModsecAgent) *ModSecurityAgent {
	return &ModSecurityAgent{
		Agent: Agent,
	}
}

// GetIntervention checks with ModSecurity if this transaction should be intervene
func (agent *ModSecurityAgent) GetIntervention(request *apis.Request) (intervene bool, err error) {
	return modsecurity.ModsecTransaction(request, agent.Agent)
}

// Judge judges a request based in the Agent response
// Returns: a field name (to SPOE), if should intervene and an error
func Judge(j Judger, request *apis.Request) (bool, error) {
	return j.GetIntervention(request)
}
