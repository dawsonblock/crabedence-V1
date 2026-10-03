// Package secretpattern is the shared credential-shape corpus used by
// the provider-transport DLP chain and durable-state admission checks.
// It is shape detection: it never learns what the runtime's secrets
// are, only what secrets look like.
package secretpattern

import "regexp"

// secretPattern pairs a detector with its non-secret audit name.
type secretPattern struct {
	name    string
	pattern *regexp.Regexp
}

// patterns is the baseline credential corpus. New shapes are
// additive — the provider transport's policy digest names this exact
// rule set so a change in detection is a change in audit identity.
var patterns = []secretPattern{
	{name: "github-pat", pattern: regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr|ghc)_[A-Za-z0-9]{30,}\b`)},
	{name: "github-fine-grained-pat", pattern: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
	{name: "github-oauth", pattern: regexp.MustCompile(`\bgho_[A-Za-z0-9]{30,}\b`)},
	{name: "aws-access-key", pattern: regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{name: "private-key", pattern: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`)},
	{name: "jwt", pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
	{name: "bearer-token", pattern: regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b`)},
	{name: "slack-token", pattern: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{name: "openai-key", pattern: regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`)},
	{name: "database-url-with-password", pattern: regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^/\s:@]+:[^@\s/]+@`)},
}

// Scan returns the non-secret audit name of the first credential
// shape found in data, or "" when nothing matches.
func Scan(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	s := string(data)
	for _, p := range patterns {
		if p.pattern.MatchString(s) {
			return p.name
		}
	}
	return ""
}
