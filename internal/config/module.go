package config

import (
	"time"
)

const (
	ModuleProberHTTP string = "http"
	ModuleProberTCP  string = "tcp"
	ModuleProberICMP string = "icmp"
	ModuleProberDNS  string = "dns"
)

type Module struct {
	Prober  string        `yaml:"prober,omitempty"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
	HTTP    *HTTPProbe    `yaml:"http,omitempty"`
	TCP     *TCPProbe     `yaml:"tcp,omitempty"`
	ICMP    *ICMPProbe    `yaml:"icmp,omitempty"`
	DNS     *DNSProbe     `yaml:"dns,omitempty"`
}

// TODO (emmanuel): extract a common struct for embedding in HTTP, TCP, DNS & ICMP probes
// type Probe struct {
// 	PreferredIPProtocol string `yaml:"preferred_ip_protocol,omitempty"`
// 	IPProtocolFallback  bool   `yaml:"ip_protocol_fallback,omitempty"`
// }

// UnmarshalYAML implements the yaml.Unmarshaler interface.
// func (s *Module) UnmarshalYAML(unmarshal func(interface{}) error) error {
// 	type plain Module
// 	if err := unmarshal((*plain)(s)); err != nil {
// 		return err
// 	}
// 	return nil
// }
