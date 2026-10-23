package policy

import "fmt"

const Benign = "benign"

type FailureMode string

const (
	FailOpen   FailureMode = "open"
	FailClosed FailureMode = "closed"
)

func ParseFailureMode(s string) (FailureMode, error) {
	switch m := FailureMode(s); m {
	case FailOpen, FailClosed:
		return m, nil
	}
	return "", fmt.Errorf("invalid failure mode %q (want open or closed)", s)
}

type BadOutput string

const (
	BadOutputBlock       BadOutput = "block"
	BadOutputFailClosed  BadOutput = "fail_closed"
	BadOutputFailureMode BadOutput = "failure_mode"
)

func ParseBadOutput(s string) (BadOutput, error) {
	switch b := BadOutput(s); b {
	case BadOutputBlock, BadOutputFailClosed, BadOutputFailureMode:
		return b, nil
	}
	return "", fmt.Errorf("invalid bad-output action %q (want block, fail_closed, or failure_mode)", s)
}

type Category struct {
	Name        string
	Description string
}

type Match struct {
	Host        string
	PathPrefix  string
	GRPCService string
}

type Route struct {
	Match       Match
	FailureMode FailureMode
	Threshold   *float64
	Limits      Limits
}

type Redact struct {
	Headers    []string
	JSONFields []string
}

type Policy struct {
	Categories []Category
	Routes     []Route
	Limits     Limits
	Redact     Redact
}

func DefaultCategories() []Category {
	return []Category{
		{Name: "injection", Description: "Code, query or command injection into an interpreter: SQL syntax, quotes, comments or UNION/boolean tricks; NoSQL operators such as $ne, $gt or $where; shell metacharacters or command substitution; template or expression syntax such as {{...}} or ${...}; JNDI or deserialization payloads; CRLF sequences (%0d%0a) that inject headers."},
		{Name: "xss", Description: "Cross-site scripting: HTML or JavaScript payloads such as script tags, event handlers, or javascript: URLs."},
		{Name: "file_access", Description: "Path traversal or local file inclusion: ../ sequences, encoded variants, or requests for sensitive files such as /etc/passwd."},
		{Name: "ssrf_redirect", Description: "Server-side request forgery or open redirect: a URL, IP address or internal hostname in a parameter or header that the server might fetch or redirect to, pointing at a cloud metadata address (169.254.169.254), localhost, private networks, file:// or gopher://, or at an unrelated external site, including //host and backslash tricks. A URL pointing at the site's own hosts, a relative path, or a well-known public service is normal."},
		{Name: "recon", Description: "Automated reconnaissance: vulnerability scanners, probing for admin panels, backups, .git or .env files, or known exploit paths."},
		{Name: "auth_abuse", Description: "Automated login abuse: scripted authentication attempts using lists of usernames and passwords."},
		{Name: "other_attack", Description: "Clearly malicious traffic that fits none of the other categories. Do not use it for unusual but legitimate requests."},
	}
}

func DefaultRedact() Redact {
	return Redact{Headers: []string{"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}}
}

func Default() *Policy {
	return &Policy{Categories: DefaultCategories(), Redact: DefaultRedact()}
}
