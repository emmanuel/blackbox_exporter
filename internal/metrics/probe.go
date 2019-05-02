package metrics

import (
	"net"
	"time"

	// "github.com/emmanuel/blackbox-exporter/internal/config"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	ProbeSuccessGauge          = "probe_success"
	ProbeDurationSecondsGauge  = "probe_duration_seconds"
	ProbeFailedDueToRegexGauge = "probe_failed_due_to_regex"
)

type Registerer interface {
	Register(registry *prometheus.Registry) error
}

// ProbeMetrics provides Prometheus metrics common for all probes
type ProbeMetrics struct {
	successGauge          prometheus.Gauge
	durationSecondsGauge  prometheus.Gauge
	failedDueToRegexGauge prometheus.Gauge
	ipProtocolGauge       prometheus.Gauge
	dnsLookupTimeSeconds  prometheus.Gauge
}

// NewHTTPProbeMetrics creates a new set of metrics for an HTTP probe and
// registers them with the supplied registry.
func NewProbeMetrics(registry *prometheus.Registry) *ProbeMetrics {
	m := ProbeMetrics{
		successGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: ProbeSuccessGauge,
			Help: "Displays whether or not the probe was a success",
		}),

		durationSecondsGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: ProbeDurationSecondsGauge,
			Help: "Returns how long the probe took to complete in seconds",
		}),

		failedDueToRegexGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: ProbeFailedDueToRegexGauge,
			Help: "Indicates if probe failed due to regex",
		}),

		dnsLookupTimeSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_dns_lookup_time_seconds",
			Help: "Returns the time taken for probe dns lookup in seconds",
		}),

		ipProtocolGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_ip_protocol",
			Help: "Specifies whether probe ip protocol is IP4 or IP6",
		}),
	}
	m.Register(registry)
	return &m
}

// register registers the Metrics with the supplied registry.
func (m *ProbeMetrics) Register(registry *prometheus.Registry) {
	registry.MustRegister(
		m.successGauge,
		m.durationSecondsGauge,
		m.failedDueToRegexGauge,
		m.dnsLookupTimeSeconds,
		m.ipProtocolGauge,
	)
}

// SetSuccessMetric records whether the probe attempt succeeded
func (m *ProbeMetrics) SetSuccessMetric(succeeded bool) {
	if succeeded {
		m.successGauge.Set(1)
	} else {
		m.successGauge.Set(0)
	}
}

// SetDurationMetric records the duration of the response; the sum of the
// durations of all redirections during the probe attempt
func (m *ProbeMetrics) SetDurationMetric(duration time.Duration) {
	m.durationSecondsGauge.Set(duration.Seconds())
}

// SetDurationMetric records the duration of the response; the sum of the
// durations of all redirections during the probe attempt
func (m *ProbeMetrics) SetDNSLookupTimeMetric(duration time.Duration) {
	m.dnsLookupTimeSeconds.Set(duration.Seconds())
}

// SetDurationMetric records the duration of the response; the sum of the
// durations of all redirections during the probe attempt
func (m *ProbeMetrics) SetIPProtocol(ip net.IP) {
	if ip.To4() == nil {
		m.ipProtocolGauge.Set(6)
	} else {
		m.ipProtocolGauge.Set(4)
	}
}

// SetFailedDueToRegexMetric records whether the probe attempt failed because
// the final response matched one of the fail regex, or didn't match the pass
// regex
func (m *ProbeMetrics) SetFailedDueToRegexMetric(failedDueToRegex bool) {
	if failedDueToRegex {
		m.failedDueToRegexGauge.Set(1)
	} else {
		m.failedDueToRegexGauge.Set(0)
	}
}
