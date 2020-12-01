package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	isa "github.com/rikatz/ingress-security-agent/pkg"
	"github.com/rikatz/ingress-security-agent/pkg/agents/modsecurity"
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

	// HAProxy / SPOE Handler
	spoehandler bool

	// Logconfigs
	logformat string
	loglevel  string
	logfile   string
	// TODO: Are we going to use threads inside here
	nbthreads int

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
		return fmt.Errorf("Ratelimit agent not yet implemented")
	}

	if spoehandler {
		if err := spoa.NewListener(config); err != nil {
			log.Fatal(err)
		}
	}

	return nil
}

func init() {
	// TODO: Ordenate, break in sections

	rootCmd.PersistentFlags().BoolVar(&spoehandler, "spoe", true, "Start the SPOE Handler (HAProxy)")
	rootCmd.PersistentFlags().BoolVar(&modsecagent, "modsec", true, "Start the ModSecurity Agent")
	rootCmd.PersistentFlags().StringVar(&rulesfile, "modsec-rules", "", "Location of the rules file for ModSecurity Agent")
	rootCmd.PersistentFlags().BoolVar(&ratelimitagent, "ratelimit", false, "Start the Rate Limit Agent")
	rootCmd.PersistentFlags().StringVar(&logformat, "log-format", "json", "Format of the log. Can be: [stdout, plain, json]")
	rootCmd.PersistentFlags().StringVar(&logfile, "log-file", "", "Name of the file to save the log files, if empty it will display to stdout")
	rootCmd.PersistentFlags().StringVarP(&loglevel, "log-level", "v", log.WarnLevel.String(), "Log level: debug, info, warn, error, fatal, panic")
	rootCmd.PersistentFlags().IntVarP(&nbthreads, "nbthreads", "n", 5, "Number of threads to start")

	// Prometheus
	rootCmd.PersistentFlags().StringVar(&metricsPath, "metrics-path", "/metrics", "Path for the metrics endpoint")
	rootCmd.PersistentFlags().StringVar(&metricsAddress, "metrics-address", ":2112", "Bind address for the metrics endpoint")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Errorf("An error has ocurred: %v", err)
		os.Exit(1)
	}
}
