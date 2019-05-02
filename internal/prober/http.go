package prober

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	// "errors"
	"fmt"
	// "io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	// "regexp"
	// "strconv"
	"strings"
	"time"

	"github.com/emmanuel/blackbox-exporter/internal/config"
	"github.com/emmanuel/blackbox-exporter/internal/logging"
	"github.com/emmanuel/blackbox-exporter/internal/metrics"

	"golang.org/x/net/publicsuffix"

	"github.com/mwitkow/go-conntrack"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tcnksm/go-httpstat"
	"go.uber.org/zap"
)

const (
	defaultMaxRedirects int = 10
)

type httpProber struct {
	name   string
	module *config.Module
	// Client *http.Client
}

func NewHTTP(name string, module *config.Module) Prober {
	prober := &httpProber{
		name:   name,
		module: module,
	}
	return prober
}

// func ProbeHTTP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
func (this *httpProber) Probe(ctx context.Context, target string, registry *prometheus.Registry, logger *zap.Logger) error {
	metrix := metrics.NewHTTPProbeMetrics(registry)
	logger = logger.With(zap.String("module", this.name))
	// client := http.DefaultClient
	// metrix.SetContentLengthBytesMetric(0)

	logger.Debug("probing HTTP target", zap.String("target", target))
	// targetURL, targetHost, targetPort, err := parseTarget(target)
	targetURL, err := parseTargetURL(target)
	if err != nil {
		logger.Error("Could not parse target URL", zap.Error(err), zap.String("target", target))
		return err
	}

	_, resp, respBody, responseDoneTimes, results, err := this.doRequest(ctx, targetURL, logger)
	httpConfig := this.module.HTTP

	// Err won't be nil if redirects were turned off. See https://github.com/golang/go/issues/3795
	if err != nil && resp == nil {
		logger.Error("Error for HTTP request", zap.Error(err))
	} else {
		// requestErrored := (err != nil)

		logger.Info("Received HTTP response", zap.Int("status_code", resp.StatusCode))
		if !httpConfig.IsValidStatusCode(resp.StatusCode) {
			logger.Info("Invalid HTTP response status code",
				zap.Int("status_code", resp.StatusCode),
				zap.Ints("valid_status_codes", httpConfig.ValidStatusCodes))
			return errors.New("Invalid HTTP response status code")
		}

		if httpConfig.BodyRegexValidator.HasRegexpsDefined() {
			ok, err := httpConfig.BodyRegexValidator.Validate(respBody, logger)
			if err != nil {
				return err
			}
			metrix.SetFailedDueToRegexMetric(!ok)
		}
		if !httpConfig.IsValidHTTPVersion(resp.Proto) {
			logger.Error("Invalid HTTP version number", zap.String("version", resp.Proto))
			// metrix.SetFailedDueToRegexMetric(!ok)
			return errors.New("Invalid HTTP version")
		}

	}

	if resp == nil {
		resp = &http.Response{}
	}
	for i, result := range results {
		responseDoneAtTime := responseDoneTimes[i]
		logger.Info("Response timings for roundtrip",
			zap.Int("roundtrip", i),
			zap.Duration("dns_lookup", result.DNSLookup),
			zap.Duration("tcp_connection", result.TCPConnection),
			zap.Duration("tls_handshake", result.TLSHandshake),
			zap.Duration("server_processing", result.ServerProcessing),
			zap.Duration("total", result.Total(responseDoneAtTime)),
		)
		if i == len(results) {
			metrix.RecordFinalResult(i, result, resp, responseDoneAtTime)
			if resp.TLS != nil {
				if httpConfig.FailIfSSL {
					logger.Error("Final request was over SSL")
					return errors.New("final request was over SSL")
				}
			} else if httpConfig.FailIfNotSSL {
				logger.Error("Final request was not over SSL")
				return errors.New("final request was not over SSL")
			}
		} else {
			metrix.RecordIntermediateResult(result, responseDoneAtTime)
		}
	}

	return nil
}

// func (this *httpProber) doRequest(ctx context.Context, targetURL *url.URL, logger *zap.Logger)  {
func (this *httpProber) maxRedirects() int {
	if this.module.HTTP.NoFollowRedirects {
		return 0
		// maxRedirects = min(defaultMaxRedirects, this.module.HTTP.NoFollowRedirects)
	}
	return defaultMaxRedirects
}

// func (this *httpProber) doRequest(ctx context.Context, targetURL *url.URL, logger *zap.Logger)  {
func (this *httpProber) doRequest(ctx context.Context, targetURL *url.URL, logger *zap.Logger) (int, *http.Response, []byte, []time.Time, []*httpstat.Result, error) {
	maxRedirects := this.maxRedirects()
	results := make([]*httpstat.Result, 0, maxRedirects)
	client := httpClientFromHTTPModule(this.module.HTTP, this.name, targetURL.Host, logger)
	nextURL := targetURL
	var (
		redirectCount int
		response      *http.Response
		responseBody  []byte
		responseDones []time.Time
		err           error
	)

	// follow redirects manually in order to trace each request;
	// inspired by: https://jonathanmh.com/tracing-preventing-http-redirects-golang/
	for redirectCount = 0; redirectCount <= maxRedirects; redirectCount++ {
		result := httpstat.Result{}
		redirectContext := httpstat.WithHTTPStat(ctx, &result)
		request, err := probeHTTPRequest(redirectContext, nextURL, this.module.HTTP)
		if err != nil {
			logger.Error("Error creating request", zap.Error(err))
			break
		}
		logger.Info("Making HTTP request", zap.Stringer("url", request.URL), zap.String("host", request.Host))

		// TODO (emmanuel): fix error handling
		response, err = client.Do(request)
		if err != nil {
			logger.Error("Error doing request", zap.Error(err))
			break
		}
		responseBody, err = ioutil.ReadAll(response.Body)
		if err != nil {
			logger.Error("Error reading response body", zap.Error(err))
			break
		}
		response.Body.Close()
		responseDoneAtTime := time.Now()
		result.End(responseDoneAtTime)
		results = append(results, &result)
		responseDones = append(responseDones, responseDoneAtTime)

		if err != nil {
			logger.Error("Error doing request", zap.Error(err))
			break
		}

		logger.Debug("Got response", zap.Stringer("url", response.Request.URL), zap.Int("status_code", response.StatusCode))

		if is2xx(response) {
			logger.Info("Got terminal response")
			break
		} else if isRedirect(response) {
			nextURL, err = responseRedirectURL(response)
			if err != nil {
				logger.Error("Error parsing location header on redirect", zap.Error(err))
				break
			}
			logger.Debug("Following redirect", zap.Stringer("url", nextURL))
			continue
		} else {
			logger.Error("Not a successful response, nor redirect", zap.Error(err))
			break
		}
	}

	return redirectCount, response, responseBody, responseDones, results, err
}

func responseRedirectURL(resp *http.Response) (*url.URL, error) {
	return url.Parse(resp.Header.Get("Location"))
}

func isRedirect(resp *http.Response) bool {
	return (resp.StatusCode >= 300 && resp.StatusCode <= 399)
}

func is2xx(resp *http.Response) bool {
	return (resp.StatusCode >= 200 && resp.StatusCode <= 299)
}

func probeHTTPRequest(ctx context.Context, targetURL *url.URL, httpConfig *config.HTTPProbe) (*http.Request, error) {
	// If a body is configured, add it to the request.
	body, err := httpConfig.BodyReader()
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(httpConfig.Method, targetURL.String(), body)
	if err != nil {
		return nil, err
	}
	request = request.WithContext(ctx)

	err = httpConfig.Headers.CloneToRequest(request)
	if err != nil {
		return nil, err
	}

	return request, nil
}

// func probeHTTPRequest2(ctx context.Context, targetURL *url.URL, ip *net.IPAddr, targetPort int, httpConfig *config.HTTPProbe) (*http.Request, error) {
// 	// Replace the host field in the URL with the IP we resolved.
// 	origHost := targetURL.Host
// 	if targetPort == 0 {
// 		targetURL.Host = "[" + ip.String() + "]"
// 	} else {
// 		targetURL.Host = net.JoinHostPort(ip.String(), strconv.Itoa(targetPort))
// 	}
//
// 	// If a body is configured, add it to the request.
// 	body := httpConfig.BodyReader()
//
// 	request, err := http.NewRequest(httpConfig.Method, targetURL.String(), body)
// 	if err != nil {
// 		return nil, err
// 	}
// 	request.Host = origHost
// 	request = request.WithContext(ctx)
//
// 	for key, value := range httpConfig.Headers {
// 		if http.CanonicalHeaderKey(key) == "Host" {
// 			request.Host = value
// 			continue
// 		}
// 		request.Header.Set(key, value)
// 	}
//
// 	return request, nil
// }

func parseTargetURL(target string) (*url.URL, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	return url.Parse(target)
}

func parseTarget(target string) (*url.URL, string, string, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, "", "", err
	}
	targetHost, targetPort, err := net.SplitHostPort(targetURL.Host)
	// If split fails, assuming it's a hostname without port part.
	if err != nil {
		targetHost = targetURL.Host
	}
	return targetURL, targetHost, targetPort, nil
}

func httpClientFromHTTPModule(mod *config.HTTPProbe, moduleName, targetHost string, logger *zap.Logger) *http.Client {
	httpClientConfig := mod.HTTPClientConfig
	if len(httpClientConfig.TLSConfig.ServerName) == 0 {
		// If there is no `server_name` in tls_config, use
		// the hostname of the target.
		httpClientConfig.TLSConfig.ServerName = targetHost
	}
	client, err := newHTTPClientFromConfig(&httpClientConfig, targetHost)
	if err != nil {
		logger.Error("Error generating HTTP client", zap.Error(err))
		return nil
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		logger.Error("Error generating cookiejar", zap.Error(err))
		return nil
	}
	client.Jar = jar

	if mod.NoFollowRedirects {
		client.CheckRedirect = httpClientCheckRedirectAlwaysFail
	} else {
		client.CheckRedirect = httpClientCheckRedirectFailAfterMax
	}

	// Inject transport that tracks trace for each redirect.
	// tt := newTransport(client.Transport, logger)
	// client.Transport = tt

	return client
}

var (
	errCheckRedirectFailAfterMax = errors.New("max redirects already followed")
	errCheckRedirectAlwaysFail   = errors.New("following redirects disabled via config")
	errNoRegexpsDefined          = errors.New("no regexps defined in config")
)

// func fromContext(ctx context.Context)  {
// }

func httpClientCheckRedirectFailAfterMax(r *http.Request, via []*http.Request) error {
	logger := logging.FromContext(r.Context())
	logger.Info("Received redirect", zap.Stringer("url", r.URL))
	if len(via) > defaultMaxRedirects {
		logger.Info("Max redirects already followed")
		return errCheckRedirectFailAfterMax
	}
	// behavior is to return redirects, and not automatically follow them.
	//   this allows us to capture stats for each redirect segment
	return http.ErrUseLastResponse
}

func httpClientCheckRedirectAlwaysFail(r *http.Request, via []*http.Request) error {
	logger := logging.FromContext(r.Context())
	logger.Info("Following redirects disabled via config")
	return errCheckRedirectAlwaysFail
}

// NewClient returns a http.Client using the specified http.RoundTripper.
func newClient(rt http.RoundTripper) *http.Client {
	return &http.Client{Transport: rt}
}

// NewClientFromConfig returns a new HTTP client configured for the
// given config.HTTPClientConfig. The name is used as go-conntrack metric label.
func newHTTPClientFromConfig(cfg *config.HTTPClientConfig, name string) (*http.Client, error) {
	rt, err := NewRoundTripperFromConfig(cfg, name)
	if err != nil {
		return nil, err
	}
	return newClient(rt), nil
}

// NewRoundTripperFromConfig returns a new HTTP RoundTripper configured for the
// given config.HTTPClientConfig. The name is used as go-conntrack metric label.
func NewRoundTripperFromConfig(cfg *config.HTTPClientConfig, name string) (http.RoundTripper, error) {
	tlsConfig, err := NewTLSConfig(&cfg.TLSConfig)
	if err != nil {
		return nil, err
	}
	// The only timeout we care about is the configured scrape timeout.
	// It is applied on request. So we leave out any timings here.
	var rt http.RoundTripper = &http.Transport{
		Proxy:               http.ProxyURL(cfg.ProxyURL.URL),
		MaxIdleConns:        20000,
		MaxIdleConnsPerHost: 1000, // see https://github.com/golang/go/issues/13801
		DisableKeepAlives:   false,
		TLSClientConfig:     tlsConfig,
		DisableCompression:  true,
		// 5 minutes is typically above the maximum sane scrape interval. So we can
		// use keepalive for all configurations.
		IdleConnTimeout: 5 * time.Minute,
		DialContext: conntrack.NewDialContextFunc(
			conntrack.DialWithTracing(),
			conntrack.DialWithName(name),
		),
	}

	// // If a bearer token is provided, create a round tripper that will set the
	// // Authorization header correctly on each request.
	// if len(cfg.BearerToken) > 0 {
	// 	rt = NewBearerAuthRoundTripper(cfg.BearerToken, rt)
	// } else if len(cfg.BearerTokenFile) > 0 {
	// 	rt = NewBearerAuthFileRoundTripper(cfg.BearerTokenFile, rt)
	// }
	//
	// if cfg.BasicAuth != nil {
	// 	rt = NewBasicAuthRoundTripper(cfg.BasicAuth.Username, cfg.BasicAuth.Password, cfg.BasicAuth.PasswordFile, rt)
	// }

	// Return a new configured RoundTripper.
	return rt, nil
}

// NewTLSConfig creates a new tls.Config from the given TLSConfig.
func NewTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}

	// If a CA cert is provided then let's read it in so we can validate the
	// scrape target's certificate properly.
	if len(cfg.CAFile) > 0 {
		caCertPool := x509.NewCertPool()
		// Load CA cert.
		caCert, err := ioutil.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("unable to use specified CA cert %s: %s", cfg.CAFile, err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	if len(cfg.ServerName) > 0 {
		tlsConfig.ServerName = cfg.ServerName
	}
	// If a client cert & key is provided then configure TLS config accordingly.
	if len(cfg.CertFile) > 0 && len(cfg.KeyFile) == 0 {
		return nil, fmt.Errorf("client cert file %q specified without client key file", cfg.CertFile)
	} else if len(cfg.KeyFile) > 0 && len(cfg.CertFile) == 0 {
		return nil, fmt.Errorf("client key file %q specified without client cert file", cfg.KeyFile)
	} else if len(cfg.CertFile) > 0 && len(cfg.KeyFile) > 0 {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("unable to use specified client cert (%s) & key (%s): %s", cfg.CertFile, cfg.KeyFile, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	tlsConfig.BuildNameToCertificate()

	return tlsConfig, nil
}
