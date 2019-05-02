package config

import (
	"errors"
	"runtime"
)

var (
	errDontFragmentNotSupportedOnWindows error = errors.New("\"dont_fragment\" is not supported on windows platforms")
)

type ICMPProbe struct {
	IPProtocol         string `yaml:"preferred_ip_protocol,omitempty"` // Defaults to "ip6".
	IPProtocolFallback bool   `yaml:"ip_protocol_fallback,omitempty"`
	SourceIPAddress    string `yaml:"source_ip_address,omitempty"`
	PayloadSize        int    `yaml:"payload_size,omitempty"`
	DontFragment       bool   `yaml:"dont_fragment,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *ICMPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain ICMPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	if runtime.GOOS == "windows" && s.DontFragment {
		return errDontFragmentNotSupportedOnWindows
	}
	return nil
}
