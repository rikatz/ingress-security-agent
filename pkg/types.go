package isa

import (
	modsec "github.com/rikatz/ingress-security-agent/pkg/agents/modsecurity"
)

// Config defines the Configuration of the agent necessary for all
// the handlers
type Config struct {
	OpenRestyAddress string
	ModSecAgent      bool
	ModSecStruct     *modsec.ModsecAgent
	RateLimitAgent   bool
}
