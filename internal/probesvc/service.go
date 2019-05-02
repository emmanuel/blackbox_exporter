package probesvc

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/emmanuel/blackbox-exporter/internal/config"
	"github.com/emmanuel/blackbox-exporter/internal/httpsvc"
	"github.com/emmanuel/blackbox-exporter/internal/metrics"
	"github.com/emmanuel/blackbox-exporter/internal/prober"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

var (
	defaultModuleName    string = "http_2xx"
	errUnknownModuleName error  = errors.New("Unknown module")
)

// Service serves various metric and health checking endpoints
type Service struct {
	httpsvc.Service
	*metrics.ServiceMetrics
	config.ConfigReader
}

// Start fulfills the g.Start contract.
// When stop is closed the http server will shutdown.
func (this *Service) Start(stop <-chan struct{}) error {
	this.Service.ServeMux.HandleFunc("/probe", handlerFunc(this.Service.Logger, this.ConfigReader))

	return this.Service.Start(stop)
}

func handlerFunc(logger *zap.Logger, cfgReader config.ConfigReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// timeout, _ := ctx.Deadline()
		cfg := cfgReader.Config()
		moduleName := r.URL.Query().Get("module")
		module := moduleByName(cfg, moduleName)
		if module == nil {
			http.Error(w, fmt.Sprintf("Unknown module %q", moduleName), http.StatusBadRequest)
			return
		}
		logger := logger.With(zap.String("module", moduleName))
		prober := prober.ProberForModule(moduleName, module)
		registry := prometheus.NewRegistry()
		target := "foo"
		if err := prober.Probe(ctx, target, registry, logger); err != nil {
			http.Error(w, "Something went wrong", http.StatusInternalServerError)
			return
		}
		promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
		return
	}
}

func moduleByName(cfg *config.Config, moduleName string) *config.Module {
	if moduleName == "" {
		moduleName = defaultModuleName
	}
	module, ok := cfg.Modules[moduleName]
	if !ok {
		return nil
	}
	return module
}
