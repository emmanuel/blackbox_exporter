package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type ProbeICMPDurationPhase int

const (
	ProbeICMPDurationPhaseResolve ProbeICMPDurationPhase = iota + 1
	ProbeICMPDurationPhaseSetup
	ProbeICMPDurationPhaseRTT

	ProbeICMPDurationSecondsGauge    = "probe_icmp_duration_seconds"
	ProbeICMPContentLengthBytesGauge = "probe_icmp_content_length"
)

func (p ProbeICMPDurationPhase) String() string {
	switch p {
	case ProbeICMPDurationPhaseResolve:
		return "resolve"
	case ProbeICMPDurationPhaseSetup:
		return "setup"
	case ProbeICMPDurationPhaseRTT:
		return "rtt"
	default:
		return "unknown"
	}
}

type ICMPProbeMetrics struct {
	ProbeMetrics

	durationSecondsGaugeVec *prometheus.GaugeVec
}

// NewICMPProbeMetrics creates a new set of metrics for an HTTP probe and
// registers them with the supplied registry.
func NewICMPProbeMetrics(registry *prometheus.Registry) *ICMPProbeMetrics {
	m := ICMPProbeMetrics{
		ProbeMetrics: *NewProbeMetrics(registry),

		durationSecondsGaugeVec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: ProbeICMPDurationSecondsGauge,
			Help: "Duration of ICMP request by phase",
		}, []string{"phase"}),
	}
	m.Register(registry)
	return &m
}

// register registers the Metrics with the supplied registry.
func (this *ICMPProbeMetrics) Register(registry *prometheus.Registry) {
	registry.MustRegister(
		this.durationSecondsGaugeVec,
	)
}

// SetPhaseDurationMetric records the duration of the response
func (this *ICMPProbeMetrics) SetPhaseDurationMetric(phase ProbeICMPDurationPhase, duration time.Duration) {
	this.durationSecondsGaugeVec.WithLabelValues(phase.String()).Set(duration.Seconds())
}
