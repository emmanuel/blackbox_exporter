// From: github.com/wrouesnel/tail_exporter/config/regexp.go
// Defines the regexp file-type

package config

import (
	"errors"
	"io"
	"io/ioutil"
	"regexp"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

// flaggedRegex fields which fail to parse are parsed again against this to
// allow using the full PCRE library.
// type flaggedRegex struct {
// 	regex string `yaml:"expr"`
// 	flags string `yaml:"flags,omitempty"`
// }

// regexValidator contains
type regexValidator struct {
	FailIfMatchesRegexp    []string `yaml:"fail_if_matches_regexp,omitempty"`
	FailIfNotMatchesRegexp []string `yaml:"fail_if_not_matches_regexp,omitempty"`
}

// Regexp encapsulates a regexp.Regexp and makes it YAML marshallable.
type RegexpValidator struct {
	original regexValidator

	FailIfMatchesRegexp    []*regexp.Regexp
	FailIfNotMatchesRegexp []*regexp.Regexp
}

// NewRegexp creates a new anchored Regexp and returns an error if the
// passed-in regular expression does not compile.
func NewRegexpValidator(s regexValidator) (*RegexpValidator, error) {
	failIfMatches, err := compileRegexpList(s.FailIfMatchesRegexp)
	if err != nil {
		return nil, err
	}
	failIfNotMatches, err := compileRegexpList(s.FailIfNotMatchesRegexp)
	if err != nil {
		return nil, err
	}

	return &RegexpValidator{
		original:               s,
		FailIfMatchesRegexp:    failIfMatches,
		FailIfNotMatchesRegexp: failIfNotMatches,
	}, nil
}

// compileRegexpList compiles a slice of strings into a slice of regexes
func compileRegexpList(exprs []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, len(exprs))
	for _, expr := range exprs {
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (this *RegexpValidator) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var rv regexValidator
	var s []string
	// Try parsing the full struct
	if err := unmarshal(&rv); err != nil {
		// Try parsing the short-form
		if err = unmarshal(&s); err != nil {
			// Fail
			return err
		}
		rv.FailIfNotMatchesRegexp = s
	}

	r, err := NewRegexpValidator(rv)
	if err != nil {
		return err
	}
	*this = *r
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (this *RegexpValidator) MarshalYAML() (interface{}, error) {
	if hasRegexpsDefined(this.original) {
		return yaml.Marshal(&this.original)
	} else if this != nil {
		return this.original, nil
	}
	return nil, nil
}

func (this *RegexpValidator) ValidateReader(reader io.Reader, logger *zap.Logger) (ok bool, err error) {
	if !this.HasRegexpsDefined() {
		return true, nil
	}
	// TODO (emmanuel): are there any better ways to test the body with regexes
	//   than to slurp the body into a buffer?
	body, err := ioutil.ReadAll(reader)
	if err != nil {
		logger.Error("Error reading HTTP body", zap.Error(err))
		return false, err
	}

	return this.Validate(body, logger)
}

func (this *RegexpValidator) Validate(body []byte, logger *zap.Logger) (ok bool, err error) {
	if !this.HasRegexpsDefined() {
		return true, nil
	}
	var (
		expression string
	)
	expression, err = this.errorIfMatchesRegularExpressions(body)
	if err != nil {
		logger.Error("failed validation", zap.String("regexp", expression), zap.Error(err))
		return false, err
	}
	expression, err = this.errorIfNotMatchesRegularExpressions(body)
	if err != nil {
		logger.Error("failed validation", zap.String("regexp", expression), zap.Error(err))
		return false, err
	}

	return true, nil
}

func (this *RegexpValidator) errorIfMatchesRegularExpressions(body []byte) (string, error) {
	return matchesRegularExpressions(body, this.FailIfMatchesRegexp, this.original.FailIfMatchesRegexp)
}

func (this *RegexpValidator) errorIfNotMatchesRegularExpressions(body []byte) (string, error) {
	return doesNotMatchRegularExpressions(body, this.FailIfNotMatchesRegexp, this.original.FailIfNotMatchesRegexp)
}

func (this *RegexpValidator) HasRegexpsDefined() bool {
	return (len(this.FailIfMatchesRegexp) > 0 || len(this.FailIfNotMatchesRegexp) > 0)
}

func hasRegexpsDefined(rv regexValidator) bool {
	return (len(rv.FailIfMatchesRegexp) > 0 || len(rv.FailIfNotMatchesRegexp) > 0)
}

func matchesRegularExpressions(body []byte, res []*regexp.Regexp, exprs []string) (string, error) {
	for i, re := range res {
		if re.Match(body) {
			return exprs[i], errors.New("body matched regular expression")
		}
	}
	return "", nil
}

func doesNotMatchRegularExpressions(body []byte, res []*regexp.Regexp, exprs []string) (string, error) {
	for i, re := range res {
		if !re.Match(body) {
			return exprs[i], errors.New("body did not match regular expression")
		}
	}
	return "", nil
}
