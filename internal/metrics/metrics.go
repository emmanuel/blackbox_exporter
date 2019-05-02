package metrics

import (
	"context"
)

type metricsKeyType int

const (
	metricsKey metricsKeyType = iota
	metricsKeyHTTP
	metricsKeyTCP
	metricsKeyDNS
	metricsKeyICMP
)

// FromContext extracts a Registerer from the provided Context, if present
func FromContext(ctx context.Context) (Registerer, bool) {
	ctxMetrics, ok := ctx.Value(metricsKey).(Registerer)
	return ctxMetrics, ok
}

// ContextWith returns a new Context with the provided Registerer
func ContextWith(ctx context.Context, metrix Registerer) context.Context {
	return context.WithValue(ctx, metricsKey, metrix)
}

// FromContextHTTP extracts a HTTPProbeMetrics from the provided Context, if present
func FromContextHTTP(ctx context.Context) (*HTTPProbeMetrics, bool) {
	ctxMetrics, ok := ctx.Value(metricsKeyHTTP).(*HTTPProbeMetrics)
	return ctxMetrics, ok
}

// ContextWithHTTP returns a new Context with the provided HTTPProbeMetrics
func ContextWithHTTP(ctx context.Context, metrix *HTTPProbeMetrics) context.Context {
	return context.WithValue(ctx, metricsKeyHTTP, metrix)
}

// FromContextTCP extracts a TCPProbeMetrics from the provided Context, if present
func FromContextTCP(ctx context.Context) (*TCPProbeMetrics, bool) {
	ctxMetrics, ok := ctx.Value(metricsKeyTCP).(*TCPProbeMetrics)
	return ctxMetrics, ok
}

// ContextWithTCP returns a new Context with the provided TCPProbeMetrics
func ContextWithTCP(ctx context.Context, metrix *TCPProbeMetrics) context.Context {
	return context.WithValue(ctx, metricsKeyTCP, metrix)
}

// FromContextDNS extracts a DNSProbeMetrics from the provided Context, if present
func FromContextDNS(ctx context.Context) (*DNSProbeMetrics, bool) {
	ctxMetrics, ok := ctx.Value(metricsKeyDNS).(*DNSProbeMetrics)
	return ctxMetrics, ok
}

// ContextWithTCP returns a new Context with the provided DNSProbeMetrics
func ContextWithDNS(ctx context.Context, metrix *DNSProbeMetrics) context.Context {
	return context.WithValue(ctx, metricsKeyDNS, metrix)
}

// FromContextICMP extracts a ICMPProbeMetrics from the provided Context, if present
func FromContextICMP(ctx context.Context) (*ICMPProbeMetrics, bool) {
	ctxMetrics, ok := ctx.Value(metricsKeyICMP).(*ICMPProbeMetrics)
	return ctxMetrics, ok
}

// ContextWithTCP returns a new Context with the provided ICMPProbeMetrics
func ContextWithICMP(ctx context.Context, metrix *ICMPProbeMetrics) context.Context {
	return context.WithValue(ctx, metricsKeyICMP, metrix)
}
