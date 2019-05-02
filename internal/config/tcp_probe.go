package config

import ()

type QueryResponse struct {
	Expect   string `yaml:"expect,omitempty"`
	Send     string `yaml:"send,omitempty"`
	StartTLS bool   `yaml:"starttls,omitempty"`
}

type TCPProbe struct {
	IPProtocol         string          `yaml:"preferred_ip_protocol,omitempty"`
	IPProtocolFallback bool            `yaml:"ip_protocol_fallback,omitempty"`
	SourceIPAddress    string          `yaml:"source_ip_address,omitempty"`
	QueryResponse      []QueryResponse `yaml:"query_response,omitempty"`
	TLS                bool            `yaml:"tls,omitempty"`
	TLSConfig          TLSConfig       `yaml:"tls_config,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
// func (s *TCPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
// 	type plain TCPProbe
// 	if err := unmarshal((*plain)(s)); err != nil {
// 		return err
// 	}
// 	return nil
// }

// UnmarshalYAML implements the yaml.Unmarshaler interface.
// func (s *QueryResponse) UnmarshalYAML(unmarshal func(interface{}) error) error {
// 	type plain QueryResponse
// 	if err := unmarshal((*plain)(s)); err != nil {
// 		return err
// 	}
// 	return nil
// }
