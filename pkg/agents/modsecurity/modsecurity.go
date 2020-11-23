package modsecurity

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	modsec "github.com/rikatz/go-modsecurity"
)

// ModsecAgent is the handler of ModSecurity created before use
type ModsecAgent struct {
	modsecurity *modsec.Modsecurity
	rules       *modsec.RuleSet
}

// InitModSecurity initializes the ModSecurity to be used by the worker
func InitModSecurity(rules string) (*ModsecAgent, error) {
	modsecurity, err := modsec.NewModsecurity()
	if err != nil {
		return &ModsecAgent{}, fmt.Errorf("unable to load Modsecurity: %s", err.Error())
	}

	modsecurity.SetServerLogCallback(func(msg string) {
		log.Infof(msg)
	})

	agent := &ModsecAgent{
		modsecurity: modsecurity,
	}

	log.Infof("Modsecurity thread initialized: %s", modsecurity.WhoAmI())

	agent.rules = agent.modsecurity.NewRuleSet()
	err = agent.rules.AddFile(rules)

	if err != nil {
		return &ModsecAgent{}, fmt.Errorf("failed to load rules files: %s", err.Error())
	}

	return agent, nil

}
