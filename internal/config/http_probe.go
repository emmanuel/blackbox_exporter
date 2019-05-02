package config

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type HTTPProbe struct {
	// Defaults to 2xx.
	ValidStatusCodes   []int       `yaml:"valid_status_codes,omitempty"`
	ValidHTTPVersions  []string    `yaml:"valid_http_versions,omitempty"`
	IPProtocol         string      `yaml:"preferred_ip_protocol,omitempty"`
	IPProtocolFallback bool        `yaml:"ip_protocol_fallback,omitempty"`
	NoFollowRedirects  bool        `yaml:"no_follow_redirects,omitempty"`
	FailIfSSL          bool        `yaml:"fail_if_ssl,omitempty"`
	FailIfNotSSL       bool        `yaml:"fail_if_not_ssl,omitempty"`
	Method             string      `yaml:"method,omitempty"`
	Headers            HTTPHeaders `yaml:"headers,omitempty"`
	// Headers            map[string]string `yaml:"headers,omitempty"`
	// FailIfMatchesRegexp    []string          `yaml:"fail_if_matches_regexp,omitempty"`
	// FailIfNotMatchesRegexp []string          `yaml:"fail_if_not_matches_regexp,omitempty"`
	BodyRegexValidator RegexpValidator  `yaml:"body_regexp_validator,inline"`
	Body               string           `yaml:"body,omitempty"`
	BodyFile           string           `yaml:"body_file,omitempty"`
	HTTPClientConfig   HTTPClientConfig `yaml:"http_client_config,inline"`
}

// HTTPClientConfig configures an HTTP client.
type HTTPClientConfig struct {
	// The HTTP basic authentication credentials for the targets.
	BasicAuth *BasicAuth `yaml:"basic_auth,omitempty"`
	// The bearer token for the targets.
	BearerToken Secret `yaml:"bearer_token,omitempty"`
	// The bearer token file for the targets.
	BearerTokenFile string `yaml:"bearer_token_file,omitempty"`
	// HTTP proxy server to use to connect to the targets.
	ProxyURL URL `yaml:"proxy_url,omitempty"`
	// TLSConfig to use to connect to the targets.
	TLSConfig TLSConfig `yaml:"tls_config,omitempty"`
}

// BasicAuth contains basic HTTP authentication credentials.
type BasicAuth struct {
	Username     string `yaml:"username"`
	Password     Secret `yaml:"password,omitempty"`
	PasswordFile string `yaml:"password_file,omitempty"`
}

// URL is a custom URL type that allows validation at configuration load time.
type URL struct {
	*url.URL
}

func (this *HTTPProbe) BodyReader() (io.Reader, error) {
	if len(this.Body) > 0 {
		return strings.NewReader(this.Body), nil
	} else if len(this.BodyFile) > 0 {
		return os.Open(this.BodyFile)
	}
	return nil, nil
}

func (this *HTTPProbe) IsValidStatusCode(statusCode int) bool {
	return checkStatusCodes(this.ValidStatusCodes, statusCode)
}

func (this *HTTPProbe) IsValidHTTPVersion(httpVersion string) bool {
	return checkHTTPVersion(this.ValidHTTPVersions, httpVersion)
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (this *HTTPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain HTTPProbe
	if err := unmarshal((*plain)(this)); err != nil {
		return err
	}
	if this.Method == "" {
		this.Method = http.MethodGet
	}
	if err := this.HTTPClientConfig.Validate(); err != nil {
		return err
	}
	return nil
}

// Validate validates the HTTPClientConfig to check only one of BearerToken,
// BasicAuth and BearerTokenFile is configured.
func (this *HTTPClientConfig) Validate() error {
	if len(this.BearerToken) > 0 && len(this.BearerTokenFile) > 0 {
		return fmt.Errorf("at most one of bearer_token & bearer_token_file must be configured")
	}
	if this.BasicAuth != nil && (len(this.BearerToken) > 0 || len(this.BearerTokenFile) > 0) {
		return fmt.Errorf("at most one of basic_auth, bearer_token & bearer_token_file must be configured")
	}
	if this.BasicAuth != nil && (string(this.BasicAuth.Password) != "" && this.BasicAuth.PasswordFile != "") {
		return fmt.Errorf("at most one of basic_auth password & password_file must be configured")
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface
func (this *HTTPClientConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain HTTPClientConfig
	if err := unmarshal((*plain)(this)); err != nil {
		return err
	}
	return this.Validate()
}

func checkStatusCodes(validCodes []int, statusCode int) bool {
	return (containsNoInts(validCodes) || containsInt(validCodes, statusCode))
}

func containsNoInts(items []int) bool {
	return (len(items) == 0)
}

func containsInt(items []int, target int) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func checkHTTPVersion(validVersions []string, version string) bool {
	return (containsNoStrings(validVersions) || containsString(validVersions, version))
}

func containsNoStrings(items []string) bool {
	return (len(items) == 0)
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
