package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

type fileMatch struct {
	Host        string `yaml:"host"`
	PathPrefix  string `yaml:"path_prefix"`
	GRPCService string `yaml:"grpc_service"`
}

type fileRoute struct {
	Match       fileMatch   `yaml:"match"`
	FailureMode string      `yaml:"failure_mode"`
	Threshold   *float64    `yaml:"threshold"`
	Limits      *fileLimits `yaml:"limits"`
}

type fileCategory struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

type fileRedact struct {
	Headers    []string `yaml:"headers"`
	JSONFields []string `yaml:"json_fields"`
}

type file struct {
	Categories *[]fileCategory `yaml:"categories"`
	Routes     []fileRoute     `yaml:"routes"`
	Redact     *fileRedact     `yaml:"redact"`
	Limits     *fileLimits     `yaml:"limits"`
}

const MaxLimit = 1 << 20

type limitInt struct {
	n   int
	bad string
}

func (l *limitInt) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!int" {
		l.bad = n.Value
		return nil
	}
	return n.Decode(&l.n)
}

type fileGraphQLLimits struct {
	MaxDepth      *limitInt `yaml:"max_depth"`
	MaxAliases    *limitInt `yaml:"max_aliases"`
	MaxFields     *limitInt `yaml:"max_fields"`
	MaxOperations *limitInt `yaml:"max_operations"`
	MaxBatch      *limitInt `yaml:"max_batch"`
	Introspection string    `yaml:"introspection"`
}

type fileWebSocketLimits struct {
	CrossOrigin string `yaml:"cross_origin"`
	BadVersion  string `yaml:"bad_version"`
}

type fileJA4Limits struct {
	Block *[]string `yaml:"block"`
}

type fileLimits struct {
	GraphQL   *fileGraphQLLimits   `yaml:"graphql"`
	Smuggling string               `yaml:"smuggling"`
	WebSocket *fileWebSocketLimits `yaml:"websocket"`
	JA4       *fileJA4Limits       `yaml:"ja4"`
}

func parseLimits(where string, f *fileLimits) (Limits, []error) {
	var l Limits
	var errs []error
	if f == nil {
		return l, nil
	}
	action := func(name, s string) Action {
		switch a := Action(s); a {
		case "", ActionAllow, ActionBlock:
			return a
		}
		errs = append(errs, fmt.Errorf("%s.%s: %q is not allow or block", where, name, s))
		return ""
	}
	limit := func(name string, v *limitInt) int {
		if v == nil {
			return 0
		}
		if v.bad != "" {
			errs = append(errs, fmt.Errorf("%s.%s: must be an integer, got %q", where, name, v.bad))
			return 0
		}
		if v.n < 1 {
			errs = append(errs, fmt.Errorf("%s.%s: must be at least 1, got %d", where, name, v.n))
			return 0
		}
		if v.n >= MaxLimit {
			errs = append(errs, fmt.Errorf("%s.%s: must be below %d, got %d", where, name, MaxLimit, v.n))
			return 0
		}
		return v.n
	}
	if g := f.GraphQL; g != nil {
		l.GraphQL = GraphQLLimits{
			MaxDepth: limit("graphql.max_depth", g.MaxDepth), MaxAliases: limit("graphql.max_aliases", g.MaxAliases),
			MaxFields: limit("graphql.max_fields", g.MaxFields), MaxOperations: limit("graphql.max_operations", g.MaxOperations),
			MaxBatch: limit("graphql.max_batch", g.MaxBatch), Introspection: action("graphql.introspection", g.Introspection),
		}
	}
	l.Smuggling = action("smuggling", f.Smuggling)
	if w := f.WebSocket; w != nil {
		l.WebSocket = WebSocketLimits{CrossOrigin: action("websocket.cross_origin", w.CrossOrigin), BadVersion: action("websocket.bad_version", w.BadVersion)}
	}
	if j := f.JA4; j != nil && j.Block != nil {
		l.JA4Block = []string{}
		for i, p := range *j.Block {
			if !ja4Pattern.MatchString(p) {
				errs = append(errs, fmt.Errorf("%s.ja4.block[%d]: %q is not a JA4 fingerprint or prefix", where, i, p))
				continue
			}
			l.JA4Block = append(l.JA4Block, p)
		}
	}
	return l, errs
}

var categoryName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func Load(path string) (*Policy, error) {
	if path == "" {
		return Default(), nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path is the operator's AILUROS_POLICY_FILE
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Policy, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("policy: %w", err)
	}
	for {
		var extra any
		err := dec.Decode(&extra)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || extra != nil {
			return nil, errors.New("policy: the file holds more than one YAML document; put the whole policy in one")
		}
	}

	p := Default()
	var errs []error
	if f.Categories != nil {
		if len(*f.Categories) == 0 {
			errs = append(errs, errors.New("categories: must list at least one category when present"))
		}
		p.Categories = nil
		seen := map[string]bool{}
		for i, c := range *f.Categories {
			switch {
			case c.Name == Benign:
				errs = append(errs, fmt.Errorf("categories[%d]: %q is built in and cannot be redefined", i, Benign))
			case !categoryName.MatchString(c.Name):
				errs = append(errs, fmt.Errorf("categories[%d]: name %q must match %s", i, c.Name, categoryName))
			case seen[c.Name]:
				errs = append(errs, fmt.Errorf("categories[%d]: duplicate category %q", i, c.Name))
			}
			seen[c.Name] = true
			p.Categories = append(p.Categories, Category(c))
		}
	}
	for i, r := range f.Routes {
		if r.Match == (fileMatch{}) {
			errs = append(errs, fmt.Errorf("routes[%d]: match must set at least one of host, path_prefix, grpc_service", i))
		}
		var fm FailureMode
		if r.FailureMode != "" {
			m, err := ParseFailureMode(r.FailureMode)
			if err != nil {
				errs = append(errs, fmt.Errorf("routes[%d]: %w", i, err))
			}
			fm = m
		}
		if err := checkThreshold(r.Threshold); err != nil {
			errs = append(errs, fmt.Errorf("routes[%d]: %w", i, err))
		}
		errs = append(errs, checkMatch(i, r.Match)...)
		m := normalizeMatch(Match(r.Match))
		for _, f := range []struct{ name, set, got string }{
			{"host", r.Match.Host, m.Host},
			{"path_prefix", r.Match.PathPrefix, m.PathPrefix},
			{"grpc_service", r.Match.GRPCService, m.GRPCService},
		} {
			if f.set != "" && f.got == "" {
				errs = append(errs, fmt.Errorf("routes[%d]: match %s %q is empty after normalization", i, f.name, f.set))
			}
		}
		lim, lerrs := parseLimits(fmt.Sprintf("routes[%d].limits", i), r.Limits)
		errs = append(errs, lerrs...)
		p.Routes = append(p.Routes, Route{Match: m, FailureMode: fm, Threshold: r.Threshold, Limits: lim})
	}
	var lerrs []error
	p.Limits, lerrs = parseLimits("limits", f.Limits)
	errs = append(errs, lerrs...)
	if f.Redact != nil {
		for i, h := range f.Redact.Headers {
			if !inspect.IsToken(h) {
				errs = append(errs, fmt.Errorf("redact.headers[%d]: %q is not a header name", i, h))
			}
		}
		for i, name := range f.Redact.JSONFields {
			if strings.TrimSpace(name) == "" {
				errs = append(errs, fmt.Errorf("redact.json_fields[%d]: must not be empty", i))
			}
		}
		p.Redact = Redact{Headers: f.Redact.Headers, JSONFields: f.Redact.JSONFields}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("policy: %w", errors.Join(errs...))
	}
	return p, nil
}

func normalizeMatch(m Match) Match {
	if m.Host != "" {
		m.Host = normalizeHost(m.Host)
	}
	if m.PathPrefix != "" {
		m.PathPrefix = normalizePath(m.PathPrefix, true)
		if m.PathPrefix != "/" {
			m.PathPrefix = strings.TrimSuffix(m.PathPrefix, "/")
		}
	}
	return m
}

var grpcService = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$`)

func checkMatch(i int, m fileMatch) []error {
	var errs []error
	if m.Host != "" && strings.ContainsAny(m.Host, "/@*?# \t") {
		errs = append(errs, fmt.Errorf("routes[%d]: match host %q must be a host name or address, without scheme, path, or wildcard", i, m.Host))
	}
	if m.GRPCService != "" && !grpcService.MatchString(m.GRPCService) {
		errs = append(errs, fmt.Errorf("routes[%d]: match grpc_service %q must be a service name such as payments.v1.Payments, without a method", i, m.GRPCService))
	}
	return errs
}

func checkThreshold(t *float64) error {
	if t != nil && !(*t > 0 && *t <= 1) {
		return fmt.Errorf("threshold %v must be in (0, 1]", *t)
	}
	return nil
}
