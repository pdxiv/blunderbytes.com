package handlers

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Length limits are expressed in runes, not bytes, so that non-ASCII text is
// not truncated mid-character or unfairly penalised.
const (
	MaxUsernameRunes = 64
	MaxTitleRunes    = 200
	MaxContentRunes  = 20000
)

// usernameDisallowed matches anything not permitted in a username. Usernames
// are identifiers rather than prose, so a conservative allowlist is
// appropriate here. It is deliberately NOT applied to passwords or post text.
var usernameDisallowed = regexp.MustCompile(`[^\p{L}\p{N}._-]+`)

// sanitizeUsername reduces a submitted username to an identifier.
func sanitizeUsername(input string) string {
	cleaned := usernameDisallowed.ReplaceAllString(strings.TrimSpace(input), "")
	return truncateRunes(cleaned, MaxUsernameRunes)
}

// sanitizeTitle normalises a post title to a single line of plain text.
func sanitizeTitle(input string) string {
	cleaned := stripControlRunes(normalizeNewlines(input), false)
	return truncateRunes(strings.TrimSpace(cleaned), MaxTitleRunes)
}

// sanitizeContent normalises post body text. Markup characters are preserved:
// the body is rendered through the markdown parser, which escapes HTML, and
// html/template escapes anything that reaches a template directly. Stripping
// punctuation here would only mangle legitimate prose.
func sanitizeContent(input string) string {
	cleaned := stripControlRunes(normalizeNewlines(input), true)
	return truncateRunes(strings.TrimSpace(cleaned), MaxContentRunes)
}

// normalizeNewlines converts CRLF and lone CR line endings to LF.
func normalizeNewlines(input string) string {
	input = strings.ReplaceAll(input, "\r\n", "\n")
	return strings.ReplaceAll(input, "\r", "\n")
}

// stripControlRunes removes control characters and invalid UTF-8. Newlines and
// tabs survive only when allowMultiline is set.
func stripControlRunes(input string, allowMultiline bool) string {
	var builder strings.Builder
	builder.Grow(len(input))

	for _, r := range input {
		switch {
		case r == utf8.RuneError:
			// Drop invalid UTF-8 rather than emitting replacement characters.
			continue
		case r == '\n' || r == '\t':
			if allowMultiline {
				builder.WriteRune(r)
			} else {
				builder.WriteRune(' ')
			}
		case unicode.IsControl(r):
			continue
		default:
			builder.WriteRune(r)
		}
	}

	return builder.String()
}

// truncateRunes trims input to at most limit runes, never splitting a rune.
func truncateRunes(input string, limit int) string {
	if utf8.RuneCountInString(input) <= limit {
		return input
	}

	count := 0
	for index := range input {
		if count == limit {
			return input[:index]
		}
		count++
	}
	return input
}
