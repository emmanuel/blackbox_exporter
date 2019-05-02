package prober

import (
	"context"
	// "net"
	// "time"

	"github.com/emmanuel/blackbox-exporter/internal/config"
	// "github.com/emmanuel/blackbox-exporter/internal/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type Prober interface {
	Probe(ctx context.Context, target string, registry *prometheus.Registry, logger *zap.Logger) error
}

// type Module struct {
// 	Prober  string        `yaml:"prober,omitempty"`
// 	Timeout time.Duration `yaml:"timeout,omitempty"`
// 	HTTP    HTTPProbe     `yaml:"http,omitempty"`
// 	TCP     TCPProbe      `yaml:"tcp,omitempty"`
// 	ICMP    ICMPProbe     `yaml:"icmp,omitempty"`
// 	DNS     DNSProbe      `yaml:"dns,omitempty"`
// }

type prober struct {
}

func ProberForModule(moduleName string, module *config.Module) Prober {
	switch module.Prober {
	case config.ModuleProberHTTP:
		return NewHTTP(moduleName, module)
	case config.ModuleProberTCP:
		return NewTCP(moduleName, module)
	case config.ModuleProberICMP:
		return NewICMP(moduleName, module)
	case config.ModuleProberDNS:
		return NewDNS(moduleName, module)
	default:
		return nil
	}
}

// func pickAProtocol(preferredIPProtocol config.IPProtocol) (config.IPProtocol, config.IPProtocol) {
// 	var fallbackIPProtocol config.IPProtocol
// 	// if preferredIPProtocol == "ip6" || preferredIPProtocol == "" {
// 	// 	preferredIPProtocol = "ip6"
// 	// 	fallbackIPProtocol = "ip4"
// 	// } else {
// 	// 	preferredIPProtocol = "ip4"
// 	// 	fallbackIPProtocol = "ip6"
// 	// }
// 	// // if preferredIPProtocol == "ip6" {
// 	// // 	fallbackIPProtocol = "ip4"
// 	// // } else {
// 	// // 	fallbackIPProtocol = "ip6"
// 	// // }
//
// 	if preferredIPProtocol == config.IPv6 || preferredIPProtocol == 0 {
// 		preferredIPProtocol = config.IPv6
// 		fallbackIPProtocol = config.IPv4
// 	} else {
// 		preferredIPProtocol = config.IPv4
// 		fallbackIPProtocol = config.IPv6
// 	}
// 	// if preferredIPProtocol == config.IPv6 {
// 	// 	fallbackIPProtocol = config.IPv4
// 	// } else {
// 	// 	fallbackIPProtocol = config.IPv6
// 	// }
//
// 	return preferredIPProtocol, fallbackIPProtocol
// }

// func chooseProtocol(IPProtocol string, fallbackIPProtocol bool, target string, registry *prometheus.Registry, logger log.Logger) (ip *net.IPAddr, lookupTime float64, err error) {
// func chooseProtocol(preferredIPProtocol config.IPProtocol, attemptIPProtocolFallback bool, target string, metrix *metrics.ProbeMetrics, logger *zap.Logger) (ip *net.IPAddr, lookupTime time.Duration, err error) {
// 	var fallbackIPProtocol config.IPProtocol
//
// 	preferredIPProtocol, fallbackIPProtocol = pickAProtocol(preferredIPProtocol)
// 	logger.Info("Resolving target address", zap.Stringer("ip_protocol", preferredIPProtocol))
// 	resolveStart := time.Now()
//
// 	// TODO (emmanuel): can this be a one-liner?
// 	// defer metrics.AddProbeDNSLookupTimeSeconds(time.Since(resolveStart))
// 	defer func() {
// 		metrix.SetDNSLookupTimeMetric(time.Since(resolveStart))
// 	}()
//
// 	ip, err = net.ResolveIPAddr(preferredIPProtocol.String(), target)
// 	if err != nil {
// 		if attemptIPProtocolFallback == false {
// 			logger.Error("Resolution with IP protocol failed (fallback_ip_protocol is false)", zap.Error(err))
// 			return nil, 0.0, err
// 		} else {
// 			logger.Warn("Resolution with IP protocol failed, attempting fallback protocol", zap.Stringer("fallback_protocol", fallbackIPProtocol), zap.Error(err))
// 			ip, err = net.ResolveIPAddr(fallbackIPProtocol.String(), target)
// 			if err != nil {
// 				return nil, 0.0, err
// 			}
// 		}
// 	}
//
// 	metrix.SetIPProtocol(ip.IP)
//
// 	logger.Info("Resolved target address", zap.Stringer("ip", ip))
// 	return ip, time.Since(resolveStart), nil
// }
