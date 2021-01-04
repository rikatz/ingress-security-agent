package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	isa "github.com/rikatz/ingress-security-agent/pkg"
	"github.com/rikatz/ingress-security-agent/pkg/agents/modsecurity"
	openresty "github.com/rikatz/ingress-security-agent/pkg/handlers/openresty"
	spoa "github.com/rikatz/ingress-security-agent/pkg/handlers/spoa"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

// The version var will be used to generate the --version command and is passed by goreleaser
var version string

var (
	// ModSec Configs
	rulesfile   string
	modsecagent bool

	// Ratelimit configs
	ratelimitagent bool

	// SPOE Handlers
	spoehandler  bool
	spoeaddress  string
	spoertimeout int
	spoewtimeout int
	spoeitimeout int

	// OpenResty Handlers
	openrestyhandler bool
	openrestyaddress string

	// Logconfigs
	logformat string
	loglevel  string
	logfile   string

	// Prometheus
	metricsPath    string
	metricsAddress string

	rootCmd = &cobra.Command{
		Use:          filepath.Base(os.Args[0]),
		SilenceUsage: true,
		Short:        "Security Agent for Ingress Controllers",
		Example:      filepath.Base(os.Args[0]),
		Args:         cobra.MinimumNArgs(0),
		RunE:         runSA,
		Version:      getVersion(),
	}
)

func getVersion() string {
	if version == "" {
		return "master branch"
	}
	return version
}

func runSA(cmd *cobra.Command, args []string) error {
	var config isa.Config

	go func() {
		http.Handle(metricsPath, promhttp.Handler())
		http.ListenAndServe(metricsAddress, nil)
	}()

	lvl, err := log.ParseLevel(loglevel)
	if err != nil {
		return err
	}
	log.SetLevel(lvl)

	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
	if lvl == log.DebugLevel {
		log.SetReportCaller(true)
	}

	if modsecagent {
		config.ModSecAgent = true
		if rulesfile == "" {
			return fmt.Errorf("ModSecurity Rules is required when using ModSecurity Agent")
		}
		info, err := os.Stat(rulesfile)
		if os.IsNotExist(err) || info.IsDir() {
			return fmt.Errorf("rules file not found or created as a directory: %s", rulesfile)
		}

		config.ModSecStruct, err = modsecurity.InitModSecurity(rulesfile)
		if err != nil {
			return fmt.Errorf("Failed to initialize Modsecurity: %s", err.Error())
		}
	}

	if ratelimitagent {
		config.RateLimitAgent = true
		log.Warnf("Ratelimit agent is not implemented yet")
	}

	if spoehandler {
		configAgent := spoa.SPOAConfig{
			Address:      spoeaddress,
			ReadTimeout:  time.Duration(spoertimeout) * time.Second,
			WriteTimeout: time.Duration(spoewtimeout) * time.Second,
			IdleTimeout:  time.Duration(spoeitimeout) * time.Second,
		}
		log.Infof("[OpenResty] Starting agent")
		spoa.NewListener(config, configAgent)
	}

	if openrestyhandler {
		config.OpenRestyAddress = openrestyaddress
		log.Infof("[OpenResty] Starting agent")
		openresty.NewListener(config)

	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	return nil
}

func init() {

	rootCmd.PersistentFlags().BoolVar(&spoehandler, "spoe", true, "[SPOE] Start the SPOE Handler (HAProxy)")
	rootCmd.PersistentFlags().StringVar(&spoeaddress, "spoe-address", ":9000", "[SPOE] The address agent should listen")
	rootCmd.PersistentFlags().IntVar(&spoeitimeout, "spoe-idle-timeout", 30, "[SPOE] Socket idle timeout in seconds")
	rootCmd.PersistentFlags().IntVar(&spoertimeout, "spoe-read-timeout", 1, "[SPOE] Socket read timeout in seconds")
	rootCmd.PersistentFlags().IntVar(&spoewtimeout, "spoe-write-timeout", 1, "[SPOE] Socket write timeout in seconds")

	rootCmd.PersistentFlags().BoolVar(&openrestyhandler, "openresty", true, "[OpenResty] Start the OpenResty Handler (NGINX)")
	rootCmd.PersistentFlags().StringVar(&openrestyaddress, "openresty-address", ":8000", "[OpenResty] The address agent should listen")

	rootCmd.PersistentFlags().BoolVar(&modsecagent, "modsec", true, "[ModSecurity] Start the ModSecurity Agent")
	rootCmd.PersistentFlags().StringVar(&rulesfile, "modsec-rules", "/etc/rules/modsecurity.conf", "[ModSecurity] Location of the rules file for ModSecurity Agent")

	rootCmd.PersistentFlags().BoolVar(&ratelimitagent, "ratelimit", false, "[RateLimit] Start the Rate Limit Agent")

	rootCmd.PersistentFlags().StringVar(&logformat, "log-format", "json", "[Log] Format of the log. Can be: [stdout, plain, json]")
	rootCmd.PersistentFlags().StringVar(&logfile, "log-file", "", "[Log] Name of the file to save the log files, if empty it will display to stdout")
	rootCmd.PersistentFlags().StringVarP(&loglevel, "log-level", "v", log.WarnLevel.String(), "[Log] Log level: debug, info, warn, error, fatal, panic")

	rootCmd.PersistentFlags().StringVar(&metricsPath, "metrics-path", "/metrics", "[Metrics] Path for the metrics endpoint")
	rootCmd.PersistentFlags().StringVar(&metricsAddress, "metrics-address", ":2112", "[Metrics] Bind address for the metrics endpoint")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Errorf("An error has ocurred: %v", err)
		os.Exit(1)
	}
}
