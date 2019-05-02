package metrics

import (
	"crypto/tls"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tcnksm/go-httpstat"
)

type ProbeHTTPDurationPhase int

const (
	ProbeHTTPDurationPhaseResolve ProbeHTTPDurationPhase = iota + 1
	ProbeHTTPDurationPhaseConnect
	ProbeHTTPDurationPhaseTLS
	ProbeHTTPDurationPhaseProcessing
	ProbeHTTPDurationPhaseTransfer

	ProbeHTTPDurationSecondsGauge    = "probe_http_duration_seconds"
	ProbeHTTPContentLengthBytesGauge = "probe_http_content_length"
	ProbeHTTPRedirectsGauge          = "probe_http_redirects"
	ProbeHTTPIsSSLGauge              = "probe_http_ssl"
	ProbeHTTPVersionGauge            = "probe_http_version"
	ProbeHTTPStatusCodeGauge         = "probe_http_status_code"
	ProbeSSLEarliestCertExpiryGauge  = "probe_ssl_earliest_cert_expiry"
)

func AllProbeHTTPDurationPhases() []ProbeHTTPDurationPhase {
	return []ProbeHTTPDurationPhase{
		ProbeHTTPDurationPhaseResolve,
		ProbeHTTPDurationPhaseConnect,
		ProbeHTTPDurationPhaseTLS,
		ProbeHTTPDurationPhaseProcessing,
		ProbeHTTPDurationPhaseTransfer,
	}
}

func (p ProbeHTTPDurationPhase) String() string {
	switch p {
	case ProbeHTTPDurationPhaseResolve:
		return "resolve"
	case ProbeHTTPDurationPhaseConnect:
		return "connect"
	case ProbeHTTPDurationPhaseTLS:
		return "tls"
	case ProbeHTTPDurationPhaseProcessing:
		return "processing"
	case ProbeHTTPDurationPhaseTransfer:
		return "transfer"
	default:
		return "unknown"
	}
}

type HTTPProbeMetrics struct {
	ProbeMetrics

	durationSecondsGaugeVec *prometheus.GaugeVec
	contentLengthBytesGauge prometheus.Gauge
	redirectsTotalGauge     prometheus.Gauge
	isSSLGauge              prometheus.Gauge
	httpVersionGauge        prometheus.Gauge
	statusCodeGauge         prometheus.Gauge
	earliestCertExpiryGauge prometheus.Gauge
}

// NewHTTPProbeMetrics creates a new set of metrics for an HTTP probe and
// registers them with the supplied registry.
func NewHTTPProbeMetrics(registry *prometheus.Registry) *HTTPProbeMetrics {
	m := HTTPProbeMetrics{
		ProbeMetrics: *NewProbeMetrics(registry),

		durationSecondsGaugeVec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: ProbeHTTPDurationSecondsGauge,
			Help: "Duration of http request by phase, summed over all redirects",
		}, []string{"phase"}),

		contentLengthBytesGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: ProbeHTTPContentLengthBytesGauge,
			Help: "Length of http content response",
		}),

		redirectsTotalGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: ProbeHTTPRedirectsGauge,
			Help: "The number of redirects",
		}),

		isSSLGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: ProbeHTTPIsSSLGauge,
			Help: "Indicates if SSL was used for the final redirect",
		}),

		statusCodeGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: ProbeHTTPStatusCodeGauge,
			Help: "Response HTTP status code",
		}),

		earliestCertExpiryGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: ProbeSSLEarliestCertExpiryGauge,
			Help: "Returns earliest SSL cert expiry in unixtime",
		}),

		httpVersionGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: ProbeHTTPVersionGauge,
			Help: "Returns the version of HTTP of the probe response",
		}),
	}
	m.Register(registry)
	return &m
}

// register registers the Metrics with the supplied registry.
func (h *HTTPProbeMetrics) HTTPClientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		// DNSStart:             func (_ httptrace.DNSInfo) {
		// 	h.
		// },
		// DNSDone:              tt.DNSDone,
		// ConnectStart:         tt.ConnectStart,
		// ConnectDone:          tt.ConnectDone,
		// GotConn:              tt.GotConn,
		// GotFirstResponseByte: tt.GotFirstResponseByte,
	}
}

// register registers the Metrics with the supplied registry.
func (h *HTTPProbeMetrics) resetPhaseDurations() {
	allPhases := AllProbeHTTPDurationPhases()
	for _, phase := range allPhases {
		h.SetPhaseDurationMetric(phase, 0)
	}
}

// register registers the Metrics with the supplied registry.
func (h *HTTPProbeMetrics) Register(registry *prometheus.Registry) {
	// doing this for the side effect of eagerly creating the underlying gauge for each phase
	h.resetPhaseDurations()
	registry.MustRegister(
		h.durationSecondsGaugeVec,
		h.contentLengthBytesGauge,
		h.redirectsTotalGauge,
		h.isSSLGauge,
		h.statusCodeGauge,
		h.earliestCertExpiryGauge,
		h.httpVersionGauge,
	)
}

// ProbeHTTPDurationPhaseResolve ProbeHTTPDurationPhase = iota + 1
// ProbeHTTPDurationPhaseConnect
// ProbeHTTPDurationPhaseTLS
// ProbeHTTPDurationPhaseProcessing
// ProbeHTTPDurationPhaseTransfer

// RecordHTTPStatResult records the relevant timings captured via httpstat.Result
func (h *HTTPProbeMetrics) RecordFinalResult(redirectCount int, result *httpstat.Result, resp *http.Response, done time.Time) {
	h.RecordIntermediateResult(result, done)

	h.SetContentLengthBytesMetric(resp.ContentLength)
	httpVersionNumber, _ := strconv.ParseFloat(strings.TrimPrefix(resp.Proto, "HTTP/"), 64)
	h.SetHTTPVersionMetric(httpVersionNumber)
	h.SetStatusCodeMetric(resp.StatusCode)
	h.SetRedirectsTotalMetric(redirectCount)

	if resp.TLS != nil {
		h.SetIsSSLMetric(true)
		h.SetEarliestCertExpiryMetric(getEarliestCertExpiry(resp.TLS))
	}
}

// getEarliestCertExpiry from github.com/prometheus/blackbox_exporter/prober/tls.go
func getEarliestCertExpiry(state *tls.ConnectionState) time.Time {
	earliest := time.Time{}
	for _, cert := range state.PeerCertificates {
		if (earliest.IsZero() || cert.NotAfter.Before(earliest)) && !cert.NotAfter.IsZero() {
			earliest = cert.NotAfter
		}
	}
	return earliest
}

// RecordHTTPStatResult records the relevant timings captured via httpstat.Result
func (h *HTTPProbeMetrics) RecordIntermediateResult(result *httpstat.Result, done time.Time) {
	h.AddPhaseDurationMetric(ProbeHTTPDurationPhaseResolve, result.DNSLookup)
	h.AddPhaseDurationMetric(ProbeHTTPDurationPhaseConnect, result.TCPConnection)
	h.AddPhaseDurationMetric(ProbeHTTPDurationPhaseTLS, result.TLSHandshake)
	h.AddPhaseDurationMetric(ProbeHTTPDurationPhaseProcessing, result.ServerProcessing)
	h.AddPhaseDurationMetric(ProbeHTTPDurationPhaseTransfer, result.ContentTransfer(done))
}

// AddPhaseDurationMetric records the duration of the response; the sum of the
// durations of all redirections during the probe attempt
func (h *HTTPProbeMetrics) AddPhaseDurationMetric(phase ProbeHTTPDurationPhase, duration time.Duration) {
	h.durationSecondsGaugeVec.WithLabelValues(phase.String()).Add(duration.Seconds())
}

// SetDurationMetric records the duration of the response; the sum of the
// durations of all redirections during the probe attempt
func (h *HTTPProbeMetrics) SetPhaseDurationMetric(phase ProbeHTTPDurationPhase, duration time.Duration) {
	h.durationSecondsGaugeVec.WithLabelValues(phase.String()).Set(duration.Seconds())
}

// AddContentLengthBytesMetric records the content length of the final response from the last probe attempt
func (h *HTTPProbeMetrics) AddContentLengthBytesMetric(length int64) {
	h.contentLengthBytesGauge.Set(float64(length))
}

// SetContentLengthBytesMetric records the content length of the final response from the last probe attempt
func (h *HTTPProbeMetrics) SetContentLengthBytesMetric(length int64) {
	h.contentLengthBytesGauge.Set(float64(length))
}

// SetRedirectsTotalMetric records the number of redirects processed during the request
func (h *HTTPProbeMetrics) SetRedirectsTotalMetric(total int) {
	h.redirectsTotalGauge.Set(float64(total))
}

// SetRedirectsMetric adds one to the number of redirects processed during the request
func (h *HTTPProbeMetrics) IncRedirectsTotalMetric() {
	h.redirectsTotalGauge.Add(1)
}

// SetIsSSLMetric records whether the final response was served via SSL/TLS
func (h *HTTPProbeMetrics) SetIsSSLMetric(isSSL bool) {
	if isSSL {
		h.isSSLGauge.Set(1)
	} else {
		h.isSSLGauge.Set(0)
	}
}

// SetHTTPVersionMetric records the HTTP status code of the final response
func (h *HTTPProbeMetrics) SetHTTPVersionMetric(version float64) {
	h.httpVersionGauge.Set(version)
}

// SetStatusCodeMetric records the HTTP status code of the final response
func (h *HTTPProbeMetrics) SetStatusCodeMetric(code int) {
	h.statusCodeGauge.Set(float64(code))
}

// SetEarliestCertExpiryMetric records the earliest cert expiry observed (across all redirects)
func (h *HTTPProbeMetrics) SetEarliestCertExpiryMetric(expiry time.Time) {
	h.earliestCertExpiryGauge.Set(float64(expiry.Unix()))
}
