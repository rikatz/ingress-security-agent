package modsecurity

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	modsec "github.com/rikatz/go-modsecurity"
)

// ModsecAgent is the handler of ModSecurity created before use
type ModsecAgent struct {
	modsecurity *modsec.Modsecurity
	rules       *modsec.RuleSet
}

var (
	blockCountRule = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agent_modsecurity_blocked_rules",
	}, []string{"ruleid"})

	blockCountURL = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agent_modsecurity_blocked_urls",
	}, []string{"namespace", "ingressname"})
)

// InitModSecurity initializes the ModSecurity to be used by the worker
func InitModSecurity(rules string) (*ModsecAgent, error) {
	modsecurity, err := modsec.NewModsecurity()
	if err != nil {
		return &ModsecAgent{}, fmt.Errorf("unable to load Modsecurity: %s", err.Error())
	}

	modsecurity.SetServerLogCallback(func(msg string) {
		log.Println(msg)
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
	prometheus.MustRegister(blockCountRule, blockCountURL)

	return agent, nil

}
