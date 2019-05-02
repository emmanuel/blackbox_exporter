package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type ProbeDNSDurationPhase int

const (
	ProbeDNSDurationPhaseResolve ProbeDNSDurationPhase = iota + 1
	ProbeDNSDurationPhaseConnect
	ProbeDNSDurationPhaseTLS
	ProbeDNSDurationPhaseProcessing
	ProbeDNSDurationPhaseTransfer

	ProbeDNSDurationSecondsGauge    = "probe_icmp_duration_seconds"
	ProbeDNSContentLengthBytesGauge = "probe_icmp_content_length"
)

func (p ProbeDNSDurationPhase) String() string {
	switch p {
	case ProbeDNSDurationPhaseResolve:
		return "resolve"
	case ProbeDNSDurationPhaseConnect:
		return "connect"
	case ProbeDNSDurationPhaseTLS:
		return "tls"
	case ProbeDNSDurationPhaseProcessing:
		return "processing"
	case ProbeDNSDurationPhaseTransfer:
		return "transfer"
	default:
		return "unknown"
	}
}

type DNSProbeMetrics struct {
	ProbeMetrics

	durationSecondsGaugeVec    *prometheus.GaugeVec
	probeDNSAnswerRRSGauge     prometheus.Gauge
	probeDNSAuthorityRRSGauge  prometheus.Gauge
	probeDNSAdditionalRRSGauge prometheus.Gauge
}

// NewDNSProbeMetrics creates a new set of metrics for an HTTP probe and
// registers them with the supplied registry.
func NewDNSProbeMetrics(registry *prometheus.Registry) *DNSProbeMetrics {
	m := DNSProbeMetrics{
		ProbeMetrics: *NewProbeMetrics(registry),

		durationSecondsGaugeVec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: ProbeDNSDurationSecondsGauge,
			Help: "Duration of DNS request by phase",
		}, []string{"phase"}),

		probeDNSAnswerRRSGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_dns_answer_rrs",
			Help: "Returns number of entries in the answer resource record list",
		}),

		probeDNSAuthorityRRSGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_dns_authority_rrs",
			Help: "Returns number of entries in the authority resource record list",
		}),

		probeDNSAdditionalRRSGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_dns_additional_rrs",
			Help: "Returns number of entries in the additional resource record list",
		}),
	}
	m.Register(registry)
	return &m
}

// register registers the Metrics with the supplied registry.
func (this *DNSProbeMetrics) Register(registry *prometheus.Registry) {
	registry.MustRegister(
		this.durationSecondsGaugeVec,
		this.probeDNSAnswerRRSGauge,
		this.probeDNSAuthorityRRSGauge,
		this.probeDNSAdditionalRRSGauge,
	)
}

// SetPhaseDurationMetric records the duration of the phase
func (this *DNSProbeMetrics) SetPhaseDurationMetric(phase ProbeDNSDurationPhase, duration time.Duration) {
	this.durationSecondsGaugeVec.WithLabelValues(phase.String()).Set(duration.Seconds())
}
