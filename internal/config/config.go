package config

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

const (
	DefaultClassifierTimeout = time.Second
	DefaultBodyMaxBytes      = 16384
	DefaultExtProcAddr       = ":9001"
	DefaultForwardAuthAddr   = ":9002"
	DefaultMetricsAddr       = ":9090"
	ConventionalExtAuthzAddr = ":9003"
	ProxyTimeoutMargin       = 500 * time.Millisecond
)

const MaxDeepMaxBytes = 64 << 20
const MaxDeepMaxMessages = 10000
const (
	BackendJev    = "jev"
	BackendOpenAI = "openai"
)

var defaultBaseURL = map[string]string{
	BackendJev:    "https://api.typesafe.ai",
	BackendOpenAI: "https://api.openai.com/v1",
}

type Config struct {
	InspectionMode  inspect.Mode
	FailureMode     policy.FailureMode
	BadOutput       policy.BadOutput
	BlockThreshold  float64
	BodyMaxBytes    int
	Backend         string
	BaseURL         string
	Model           string
	APIKey          Secret
	Timeout         time.Duration
	DeepMaxBytes    int
	DeepOversize    inspect.Oversize
	DeepMaxMessages int
	ExtProcAddr     string
	ExtAuthzAddr    string
	ForwardAuthAddr string
	MetricsAddr     string
	PolicyFile      string
	LogLevel        slog.Level
	ExposeVerdict   bool
	JA4Header       string
}

func parsed[T any](get func(name, def string) string, fail func(string, error), name, def string, parse func(string) (T, error)) T {
	v, err := parse(get(name, def))
	if err != nil {
		fail(name, err)
	}
	return v
}

func Load(lookup func(string) (string, bool), readFile func(string) ([]byte, error)) (Config, error) {
	var errs []error
	fail := func(name string, err error) { errs = append(errs, fmt.Errorf("%s: %w", name, err)) }
	get := func(name, def string) string {
		if v, ok := lookup(name); ok {
			return v
		}
		return def
	}
	positive := func(name, def string, max int) int {
		n, err := strconv.Atoi(get(name, def))
		switch {
		case err == nil && n >= 1 && (max == 0 || n <= max):
			return n
		case max > 0:
			fail(name, fmt.Errorf("must be an integer from 1 to %d", max))
		default:
			fail(name, errors.New("must be a positive integer"))
		}
		return 0
	}

	var c Config
	var err error
	c.InspectionMode = parsed(get, fail, "AILUROS_INSPECTION_MODE", "standard", inspect.ParseMode)
	c.FailureMode = parsed(get, fail, "AILUROS_FAILURE_MODE", "open", policy.ParseFailureMode)
	c.BadOutput = parsed(get, fail, "AILUROS_BAD_OUTPUT", string(policy.BadOutputBlock), policy.ParseBadOutput)
	c.BlockThreshold, err = strconv.ParseFloat(get("AILUROS_BLOCK_THRESHOLD", "0.8"), 64)
	if err != nil || !(c.BlockThreshold > 0 && c.BlockThreshold <= 1) {
		fail("AILUROS_BLOCK_THRESHOLD", errors.New("must be a number in (0, 1]"))
	}
	c.BodyMaxBytes = positive("AILUROS_BODY_MAX_BYTES", strconv.Itoa(DefaultBodyMaxBytes), 0)

	c.Backend = get("AILUROS_CLASSIFIER_BACKEND", "")
	switch defaultURL, known := defaultBaseURL[c.Backend]; {
	case c.Backend == "":
		fail("AILUROS_CLASSIFIER_BACKEND", errors.New("required (jev or openai)"))
	case !known:
		fail("AILUROS_CLASSIFIER_BACKEND", fmt.Errorf("unknown backend %q (want jev or openai)", c.Backend))
	default:
		c.BaseURL = get("AILUROS_CLASSIFIER_BASE_URL", defaultURL)
		if err := checkBaseURL(c.BaseURL); err != nil {
			fail("AILUROS_CLASSIFIER_BASE_URL", err)
		}
	}
	if c.Model = get("AILUROS_CLASSIFIER_MODEL", ""); c.Model == "" {
		fail("AILUROS_CLASSIFIER_MODEL", errors.New("required"))
	}

	key, _ := lookup("AILUROS_CLASSIFIER_API_KEY")
	key = strings.TrimSpace(key)
	keyFile, _ := lookup("AILUROS_CLASSIFIER_API_KEY_FILE")
	hasKey, hasFile := key != "", keyFile != ""
	switch {
	case hasKey && hasFile:
		fail("AILUROS_CLASSIFIER_API_KEY_FILE", errors.New("set AILUROS_CLASSIFIER_API_KEY or AILUROS_CLASSIFIER_API_KEY_FILE, not both"))
	case hasFile:
		data, err := readFile(keyFile)
		c.APIKey = Secret(strings.TrimSpace(string(data)))
		switch {
		case err != nil:
			fail("AILUROS_CLASSIFIER_API_KEY_FILE", fmt.Errorf("cannot read the file (%s); the value must be a file path, and it is not shown in case it is the key itself", readError(err)))
		case c.APIKey == "":
			fail("AILUROS_CLASSIFIER_API_KEY_FILE", fmt.Errorf("%s is empty", keyFile))
		}
	default:
		c.APIKey = Secret(key)
	}

	c.Timeout, err = time.ParseDuration(get("AILUROS_CLASSIFIER_TIMEOUT", DefaultClassifierTimeout.String()))
	if err != nil || c.Timeout <= 0 {
		fail("AILUROS_CLASSIFIER_TIMEOUT", errors.New("must be a positive duration such as 1s or 750ms"))
	}
	if c.DeepMaxBytes = positive("AILUROS_DEEP_MAX_BYTES", strconv.Itoa(DefaultBodyMaxBytes), 0); c.DeepMaxBytes > MaxDeepMaxBytes {
		fail("AILUROS_DEEP_MAX_BYTES", fmt.Errorf("must be at most %d (64 MiB): deep mode holds up to this many bytes per stream", MaxDeepMaxBytes))
	}
	c.DeepOversize = parsed(get, fail, "AILUROS_DEEP_OVERSIZE", "classify_prefix", inspect.ParseOversize)
	c.DeepMaxMessages = positive("AILUROS_DEEP_MAX_MESSAGES", "100", MaxDeepMaxMessages)
	c.ExtProcAddr = get("AILUROS_EXTPROC_ADDR", DefaultExtProcAddr)
	c.ExtAuthzAddr = get("AILUROS_EXTAUTHZ_ADDR", "")
	c.ForwardAuthAddr = get("AILUROS_FORWARDAUTH_ADDR", DefaultForwardAuthAddr)
	if c.MetricsAddr = get("AILUROS_METRICS_ADDR", DefaultMetricsAddr); c.MetricsAddr == "" {
		fail("AILUROS_METRICS_ADDR", errors.New("must not be empty; it serves /metrics, /healthz, and /readyz"))
	}
	c.PolicyFile = get("AILUROS_POLICY_FILE", "")
	if err := c.LogLevel.UnmarshalText([]byte(get("AILUROS_LOG_LEVEL", "info"))); err != nil {
		fail("AILUROS_LOG_LEVEL", errors.New("must be debug, info, warn, or error"))
	}
	if c.ExposeVerdict, err = strconv.ParseBool(get("AILUROS_EXPOSE_VERDICT", "false")); err != nil {
		fail("AILUROS_EXPOSE_VERDICT", errors.New("must be true or false"))
	}
	switch c.JA4Header = strings.ToLower(strings.TrimSpace(get("AILUROS_JA4_HEADER", ""))); {
	case c.JA4Header == "":
	case strings.HasPrefix(c.JA4Header, ":"):
		fail("AILUROS_JA4_HEADER", fmt.Errorf("%q is a pseudo-header", c.JA4Header))
	case !inspect.IsToken(c.JA4Header):
		fail("AILUROS_JA4_HEADER", fmt.Errorf("%q is not a header name", c.JA4Header))
	case inspect.IsInspectedHeader(c.JA4Header):
		fail("AILUROS_JA4_HEADER", fmt.Errorf("%q is a header Ailuros inspects; reading the fingerprint removes the header, so name a dedicated one such as x-ailuros-ja4", c.JA4Header))
	}

	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return c, nil
}

func readError(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return "read error"
}

type Secret string

const redacted = "[REDACTED]"

func (s Secret) String() string { return redacted }

func (s Secret) GoString() string { return redacted }

func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

func checkBaseURL(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case raw == "":
		return errors.New("must not be empty")
	case err != nil:
		return errors.New("is not a valid URL")
	case u.Scheme != "http" && u.Scheme != "https":
		return fmt.Errorf("must start with http:// or https://, not %q", u.Scheme+":")
	case u.Host == "":
		return errors.New("has no host")
	case u.RawQuery != "" || u.Fragment != "":
		return errors.New("must not have a query or fragment")
	}
	return nil
}
