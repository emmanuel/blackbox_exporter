package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ServiceMetrics provides Prometheus metrics for the app
type ServiceMetrics struct {
	Registry                            *prometheus.Registry
	ConfigReadsTotalCounter             prometheus.Counter
	ConfigReadsDurationSecondsCounter   prometheus.Counter
	ProbeAttemptsTotalCounter           prometheus.Counter
	ProbeAttemptsDurationSecondsCounter prometheus.Counter
}

const (
	ConfigReadsTotalCounter             = "config_reads_total"
	ConfigReadsDurationSecondsCounter   = "config_reads_duration_seconds"
	ProbeAttemptsTotalCounter           = "probe_attempts_total"
	ProbeAttemptsDurationSecondsCounter = "probe_attempts_duration_seconds"
)

// NewServiceMetrics creates a new set of metrics and registers them with
// the supplied registry.
func NewServiceMetrics(registry *prometheus.Registry) *ServiceMetrics {
	m := ServiceMetrics{
		Registry: registry,
		ConfigReadsTotalCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: ConfigReadsTotalCounter,
			Help: "Total number of reads/reloads of the config file",
		}),

		ConfigReadsDurationSecondsCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: ConfigReadsDurationSecondsCounter,
			Help: "Total number of seconds elapsed during reads/reloads of the config file",
		}),

		ProbeAttemptsTotalCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: ProbeAttemptsTotalCounter,
			Help: "Total number of reads/reloads of the config file",
		}),

		ProbeAttemptsDurationSecondsCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: ProbeAttemptsDurationSecondsCounter,
			Help: "Total number of seconds elapsed during reads/reloads of the config file",
		}),
	}
	m.Register(registry)
	return &m
}

// register registers the ServiceMetrics with the supplied registry.
func (this *ServiceMetrics) Register(registry *prometheus.Registry) {
	registry.MustRegister(
		this.ConfigReadsTotalCounter,
		this.ConfigReadsDurationSecondsCounter,
		this.ProbeAttemptsTotalCounter,
		this.ProbeAttemptsDurationSecondsCounter,
	)
}

// IncConfigReadsTotal increments the total number of config reads that have
// occurred since startup
func (this *ServiceMetrics) IncConfigReadsTotal() {
	this.ConfigReadsTotalCounter.Inc()
}

// AddConfigReadDuration adds the supplied duration to the total amount of time
// spent on config reads
func (this *ServiceMetrics) AddConfigReadDuration(duration time.Duration) {
	this.ConfigReadsDurationSecondsCounter.Add(duration.Seconds())
}

// IncProbeAttemptsTotal increments the total number of probe attempts that have
// occurred since startup
func (this *ServiceMetrics) IncProbeAttemptsTotal() {
	this.ProbeAttemptsTotalCounter.Inc()
}

// AddProbeAttemptsDurationSeconds adds the supplied duration to the total amount of time
// spent on probe attempts
func (this *ServiceMetrics) AddProbeAttemptsDuration(duration time.Duration) {
	this.ProbeAttemptsDurationSecondsCounter.Add(duration.Seconds())
}
