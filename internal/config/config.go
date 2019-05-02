package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/url"
)

type IPProtocol int

const (
	IPv4 IPProtocol = 4
	IPv6 IPProtocol = 6
)

func IPProtocolFromString(ip string) IPProtocol {
	switch ip {
	case "ip", "ip4", "ipv4":
		return IPv4
	case "ip6", "ipv6":
		return IPv6
	default:
		return IPv6
	}
}

func (ip IPProtocol) Int() int {
	return int(ip)
}

func (ip IPProtocol) Float64() float64 {
	return float64(ip)
}

func (ip IPProtocol) String() string {
	switch ip {
	case IPv4:
		return "ip4"
	case IPv6:
		return "ip6"
	default:
		return "unknown"
	}
}

type Config struct {
	Modules map[string]*Module `yaml:"modules"`
}

// Secret special type for storing secrets.
type Secret string

// TLSConfig configures the options for TLS connections.
type TLSConfig struct {
	CAFile             string `yaml:"ca_file,omitempty"`     // The CA cert to use for the targets.
	CertFile           string `yaml:"cert_file,omitempty"`   // The client cert file for the targets.
	KeyFile            string `yaml:"key_file,omitempty"`    // The client key file for the targets.
	ServerName         string `yaml:"server_name,omitempty"` // Used to verify the hostname for the targets.
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`  // Disable target certificate validation.
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
// func (s *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
// 	type plain Config
// 	if err := unmarshal((*plain)(s)); err != nil {
// 		return err
// 	}
// 	return nil
// }

// UnmarshalYAML implements the yaml.Unmarshaler interface.
// func (c *TLSConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
// 	type plain TLSConfig
// 	return unmarshal((*plain)(c))
// }

// NewTLSConfig creates a new tls.Config from the given TLSConfig.
func (this *TLSConfig) TLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: this.InsecureSkipVerify}

	// If a CA cert is provided then let's read it in so we can validate the
	// scrape target's certificate properly.
	if len(this.CAFile) > 0 {
		caCertPool := x509.NewCertPool()
		// Load CA cert.
		caCert, err := ioutil.ReadFile(this.CAFile)
		if err != nil {
			return nil, fmt.Errorf("unable to use specified CA cert %s: %s", this.CAFile, err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	if len(this.ServerName) > 0 {
		tlsConfig.ServerName = this.ServerName
	}
	// If a client cert & key is provided then configure TLS config accordingly.
	if len(this.CertFile) > 0 && len(this.KeyFile) == 0 {
		return nil, fmt.Errorf("client cert file %q specified without client key file", this.CertFile)
	} else if len(this.KeyFile) > 0 && len(this.CertFile) == 0 {
		return nil, fmt.Errorf("client key file %q specified without client cert file", this.KeyFile)
	} else if len(this.CertFile) > 0 && len(this.KeyFile) > 0 {
		cert, err := tls.LoadX509KeyPair(this.CertFile, this.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("unable to use specified client cert (%s) & key (%s): %s", this.CertFile, this.KeyFile, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	tlsConfig.BuildNameToCertificate()

	return tlsConfig, nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for URLs.
func (u *URL) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	urlp, err := url.Parse(s)
	if err != nil {
		return err
	}
	u.URL = urlp
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface for URLs.
func (u URL) MarshalYAML() (interface{}, error) {
	if u.URL != nil {
		return u.String(), nil
	}
	return nil, nil
}

// MarshalYAML implements the yaml.Marshaler interface for Secrets.
func (s Secret) MarshalYAML() (interface{}, error) {
	if s != "" {
		return "<secret>", nil
	}
	return nil, nil
}

//UnmarshalYAML implements the yaml.Unmarshaler interface for Secrets.
func (s *Secret) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Secret
	return unmarshal((*plain)(s))
}
