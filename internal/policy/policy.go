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
		{Name: "sqli", Description: "SQL injection: SQL syntax, quotes, comments, or UNION/boolean tricks in parameters, headers, or body."},
		{Name: "xss", Description: "Cross-site scripting: HTML or JavaScript payloads such as script tags, event handlers, or javascript: URLs."},
		{Name: "path_traversal", Description: "Path traversal or local file inclusion: ../ sequences, encoded variants, or requests for sensitive files such as /etc/passwd."},
		{Name: "rce", Description: "Remote code or command execution: shell metacharacters, command substitution, template or expression injection, deserialization payloads, or JNDI lookups."},
		{Name: "scanner", Description: "Automated reconnaissance: vulnerability scanners, probing for admin panels, backups, .git or .env files, or known exploit paths."},
		{Name: "credential_stuffing", Description: "Automated login abuse: scripted authentication attempts using lists of usernames and passwords."},
	}
}

func DefaultRedact() Redact {
	return Redact{Headers: []string{"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}}
}

func Default() *Policy {
	return &Policy{Categories: DefaultCategories(), Redact: DefaultRedact()}
}
