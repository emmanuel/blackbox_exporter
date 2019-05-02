package main

import (
	// "flag"
	// "net"
	"os"
	// "strings"

	"github.com/emmanuel/blackbox-exporter/internal/adminsvc"
	"github.com/emmanuel/blackbox-exporter/internal/config"
	"github.com/emmanuel/blackbox-exporter/internal/config/cli"
	"github.com/emmanuel/blackbox-exporter/internal/httpsvc"
	"github.com/emmanuel/blackbox-exporter/internal/logging"
	"github.com/emmanuel/blackbox-exporter/internal/metrics"
	"github.com/emmanuel/blackbox-exporter/internal/probesvc"

	"github.com/heptio/workgroup"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	logger := logging.DefaultLogger()
	app := kingpin.New("blackbox_exporter", "Prometheus blackbox exporter.")

	serve := app.Command("serve", "")
	var cmd cli.ServeCmd
	serve.Flag("config.file", "Blackbox exporter configuration file.").Default("blackbox.yml").ExistingFileVar(&cmd.ConfigFile)
	// app.Flag("config.check", "If true validate the config file and then exit.").Default().BoolVar(&cmd.CheckConfig)
	serve.Flag("web.listen-address", "The address to listen on for HTTP requests.").Default("0.0.0.0").StringVar(&cmd.ListenAddress.Address)
	serve.Flag("web.listen-port", "The port to listen on for HTTP requests.").Default("9115").IntVar(&cmd.ListenAddress.Port)
	serve.Flag("admin.listen-address", "The address to listen on for HTTP requests for the admin endpoint.").Default("127.0.0.1").StringVar(&cmd.AdminAddress.Address)
	serve.Flag("admin.listen-port", "The port to listen on for HTTP requests for the admin endpoint.").Default("9116").IntVar(&cmd.AdminAddress.Port)
	// app.Flag("timeout-offset", "Offset to subtract from timeout in seconds.").Default("0.5").Float64Var(&cmd.TimeoutOffset)
	// app.Flag("history.limit", "The maximum amount of items to keep in the history.").Default("100").UintVar(&cmd.HistoryLimit)
	completions := app.Command("completions", "")
	// var completionsCfg cli.CompletionsCmd

	registry := prometheus.NewRegistry()
	cfgReader := config.NewFilePathConfigReader(cmd.ConfigFile)

	// register detault process / go collectors
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	registry.MustRegister(prometheus.NewGoCollector())

	// register our custom metrics
	serviceMetrics := metrics.NewServiceMetrics(registry)

	adminsvcLogger := logger.With(zap.String("context", "adminsvc"))
	adminsvc := adminsvc.Service{
		Service:        httpsvc.New(cmd.AdminAddress.Address, cmd.AdminAddress.Port, adminsvcLogger),
		ConfigReader:   cfgReader,
		ServiceMetrics: serviceMetrics,
	}

	probesvcLogger := logger.With(zap.String("context", "probesvc"))
	probesvc := probesvc.Service{
		Service:        httpsvc.New(cmd.ListenAddress.Address, cmd.ListenAddress.Port, probesvcLogger),
		ConfigReader:   cfgReader,
		ServiceMetrics: serviceMetrics,
	}

	args := os.Args[1:]
	switch kingpin.MustParse(app.Parse(args)) {
	case serve.FullCommand():
		logger.Info("starting", zap.Strings("args", args))
		var g workgroup.Group

		g.Add(adminsvc.Start)
		g.Add(probesvc.Start)

		g.Run()
	case completions.FullCommand():
		app.Usage(args)
		os.Exit(3)
	default:
		app.Usage(args)
		os.Exit(2)
	}
}
