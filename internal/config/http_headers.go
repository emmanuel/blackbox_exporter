// From: github.com/wrouesnel/tail_exporter/config/regexp.go
// Defines the regexp file-type

package config

import (
	"errors"
	// "io"
	"net/http"
	// "regexp"

	// "go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

// flaggedRegex fields which fail to parse are parsed again against this to
// allow using the full PCRE library.
// type flaggedRegex struct {
// 	regex string `yaml:"expr"`
// 	flags string `yaml:"flags,omitempty"`
// }

// regexValidator contains
type serializedHTTPHeaders struct {
	Headers map[string]string `yaml:"headers,omitempty"`
}

// HTTPHeader is a set of headers for an HTTP request
type HTTPHeaders struct {
	original serializedHTTPHeaders

	Headers http.Header
}

// NewRegexp creates a new anchored Regexp and returns an error if the
// passed-in regular expression does not compile.
func NewHTTPHeaders(h serializedHTTPHeaders) *HTTPHeaders {
	headers := convertToHTTPHeaders(h.Headers)

	return &HTTPHeaders{
		original: h,
		Headers:  headers,
	}
}

func convertToHTTPHeaders(h map[string]string) http.Header {
	h2 := make(http.Header, len(h))
	for k, v := range h {
		h2[http.CanonicalHeaderKey(k)] = []string{v}
	}
	return h2
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (this *HTTPHeaders) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var h serializedHTTPHeaders
	// Try parsing the full struct
	if err := unmarshal(&h); err != nil {
		return err
	}

	hdr := NewHTTPHeaders(h)
	if hdr == nil {
		return errors.New("error initializing HTTPHeaders")
	}
	*this = *hdr
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (this *HTTPHeaders) MarshalYAML() (interface{}, error) {
	if len(this.original.Headers) > 0 {
		return yaml.Marshal(&this.original)
	} else if this != nil {
		return this.original, nil
	}
	return nil, nil
}

func (this *HTTPHeaders) CloneToRequest(r *http.Request) error {
	for key, vv := range this.Headers {
		value := ""
		if len(vv) > 0 {
			value = vv[0]

			if http.CanonicalHeaderKey(key) == "Host" {
				r.Host = value
				continue
			}
			r.Header.Set(key, value)

			if len(vv) > 1 {
				for _, val := range vv[1:] {
					r.Header.Add(key, val)
				}
			}
		}
	}
	return nil
}
