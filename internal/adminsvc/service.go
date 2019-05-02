package adminsvc

import (
	"fmt"
	"net/http"

	"github.com/emmanuel/blackbox-exporter/internal/config"
	"github.com/emmanuel/blackbox-exporter/internal/httpsvc"
	"github.com/emmanuel/blackbox-exporter/internal/metrics"

	// "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	this.Service.ServeMux.HandleFunc("/-/reload", reloadHandlerFunc(this.ConfigReader))
	// this.Service.ServeMux.HandleFunc("/-/reload", reloadHandlerFunc(this.ConfigReader))
	this.Service.ServeMux.Handle("/metrics", serviceMetricsHandler(this.ServiceMetrics))
	this.Service.ServeMux.HandleFunc("/healthz", healthCheckHandlerFunc())

	return this.Service.Start(stop)
}

func healthCheckHandlerFunc() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})
}

func serviceMetricsHandler(metrix *metrics.ServiceMetrics) http.Handler {
	return promhttp.HandlerFor(metrix.Registry, promhttp.HandlerOpts{})
}

// func registerReload(mux *http.ServeMux, cfg config.ConfigReader) {
func reloadHandlerFunc(cfg config.ConfigReader) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintf(w, "This endpoint requires a POST request.\n")
			return
		}
		// TODO (emmanuel): reload config
		if err := cfg.ReloadConfig(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "There was an error reloading the configuration: %s.\n", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})
}
