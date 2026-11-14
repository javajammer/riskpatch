// Package collect gathers read-only host facts using a static allowlist of files and commands.
package collect

import "regexp"

const Redacted = "[REDACTED]"

var (
	secretKey   = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|authorization|dsn)`)
	secretValue = regexp.MustCompile(`(-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sw_[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})`)
	urlCreds    = regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@`)
	assign      = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|private[_-]?key)[A-Za-z0-9_.-]*)\s*([=:])\s*\S+`)
)

// RedactText scrubs credentials embedded in free text.
func RedactText(s string) string {
	s = urlCreds.ReplaceAllString(s, "${1}"+Redacted+"@")
	s = assign.ReplaceAllString(s, "${1}${2}"+Redacted)
	return secretValue.ReplaceAllString(s, Redacted)
}

// RedactKV redacts the value when the key looks secret, otherwise scrubs the text.
func RedactKV(key, value string) string {
	if secretKey.MatchString(key) {
		if value == "" {
			return value
		}
		return Redacted
	}
	return RedactText(value)
}
