package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type ProbeTCPDurationPhase int

const (
	ProbeTCPDurationPhaseResolve ProbeTCPDurationPhase = iota + 1
	ProbeTCPDurationPhaseConnect
	ProbeTCPDurationPhaseTLS

	ProbeTCPDurationSecondsGauge    = "probe_tcp_duration_seconds"
	ProbeTCPIsSSLGauge              = "probe_tcp_ssl"
	ProbeTCPEarliestCertExpiryGauge = "probe_ssl_earliest_cert_expiry"
)

func (p ProbeTCPDurationPhase) String() string {
	switch p {
	case ProbeTCPDurationPhaseResolve:
		return "resolve"
	case ProbeTCPDurationPhaseConnect:
		return "connect"
	case ProbeTCPDurationPhaseTLS:
		return "tls"
	default:
		return "unknown"
	}
}

type TCPProbeMetrics struct {
	ProbeMetrics

	durationSecondsGaugeVec *prometheus.GaugeVec
	contentLengthBytesGauge prometheus.Gauge
	redirectsTotalGauge     prometheus.Gauge
	isSSLGauge              prometheus.Gauge
	httpVersionGauge        prometheus.Gauge
	statusCodeGauge         prometheus.Gauge
	earliestCertExpiryGauge prometheus.Gauge
}

// NewTCPProbeMetrics creates a new set of metrics for an HTTP probe and
// registers them with the supplied registry.
func NewTCPProbeMetrics(registry *prometheus.Registry) *TCPProbeMetrics {
	m := TCPProbeMetrics{
		ProbeMetrics: *NewProbeMetrics(registry),

		durationSecondsGaugeVec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: ProbeTCPDurationSecondsGauge,
			Help: "Duration of http request by phase, summed over all redirects",
		}, []string{"phase"}),

		isSSLGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: ProbeTCPIsSSLGauge,
			Help: "Indicates if SSL was used for the final redirect",
		}),

		earliestCertExpiryGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: ProbeTCPEarliestCertExpiryGauge,
			Help: "Returns earliest SSL cert expiry in unixtime",
		}),
	}
	m.Register(registry)
	return &m
}

// register registers the Metrics with the supplied registry.
func (this *TCPProbeMetrics) Register(registry *prometheus.Registry) {
	registry.MustRegister(
		this.durationSecondsGaugeVec,
		this.isSSLGauge,
		this.earliestCertExpiryGauge,
	)
}

// SetDurationMetric records the duration of the response; the sum of the
// durations of all redirections during the probe attempt
func (this *TCPProbeMetrics) SetPhaseDurationMetric(phase ProbeTCPDurationPhase, duration time.Duration) {
	this.durationSecondsGaugeVec.WithLabelValues(phase.String()).Set(duration.Seconds())
}

// SetIsSSLMetric records whether the final response was served via SSL/TLS
func (this *TCPProbeMetrics) SetIsSSLMetric(isSSL bool) {
	if isSSL {
		this.isSSLGauge.Set(1)
	} else {
		this.isSSLGauge.Set(0)
	}
}

// SetEarliestCertExpiryMetric records the earliest cert expiry observed (across all redirects)
func (this *TCPProbeMetrics) SetEarliestCertExpiryMetric(expiry float64) {
	this.earliestCertExpiryGauge.Set(expiry)
}
