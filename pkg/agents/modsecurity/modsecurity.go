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
		return &ModsecAgent{}, fmt.Errorf("unable to load Modsecurity: %v", err)
	}

	modsecurity.SetServerLogCallback(func(msg string) {
		log.Infof(msg)
	})

	agent := &ModsecAgent{
		modsecurity: modsecurity,
	}

	log.Infof("Modsecurity thread initialized: %s", modsecurity.WhoAmI())
	err = agent.loadRules(rules)
	if err != nil {
		return &ModsecAgent{}, fmt.Errorf("unable to load Modsecurity: %v", err)
	}

	return agent, nil

}

func (m *ModsecAgent) loadRules(rules string) error {

	ruleset := m.modsecurity.NewRuleSet()
	err := ruleset.AddFile(rules)
	if err != nil {
		return fmt.Errorf("Could not load file '%s': %s", rules, err.Error())
	}

	m.rules = ruleset
	return nil
}
