package handlers

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeContentPreservesNonASCII(t *testing.T) {
	// The previous implementation stripped every non-ASCII rune, because Go's
	// \w character class is ASCII-only.
	cases := []string{
		"Ærlig talt: det gikk dårlig",
		"naïve café résumé",
		"日本語のテキスト",
		"emoji survive: 🔥💻",
		"punctuation: don't; <b> & \"quotes\" | pipes",
	}

	for _, input := range cases {
		if got := sanitizeContent(input); got != input {
			t.Errorf("sanitizeContent(%q) = %q, want unchanged", input, got)
		}
	}
}

func TestSanitizeContentTruncatesByRunesNotBytes(t *testing.T) {
	input := strings.Repeat("é", MaxContentRunes+50)

	got := sanitizeContent(input)

	if count := utf8.RuneCountInString(got); count != MaxContentRunes {
		t.Errorf("got %d runes, want %d", count, MaxContentRunes)
	}
	if !utf8.ValidString(got) {
		t.Error("truncation split a rune and produced invalid UTF-8")
	}
}

func TestSanitizeContentStripsControlCharactersButKeepsNewlines(t *testing.T) {
	got := sanitizeContent("line one\r\nline two\x00\x07\tend")

	want := "line one\nline two\tend"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSanitizeTitleIsSingleLine(t *testing.T) {
	got := sanitizeTitle("a title\nsplit over lines")

	if strings.Contains(got, "\n") {
		t.Errorf("got %q, want no newlines", got)
	}
	if got != "a title split over lines" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeUsernameKeepsIdentifierCharacters(t *testing.T) {
	cases := map[string]string{
		"frank":            "frank",
		"frank.stengard":   "frank.stengard",
		"frank stengard":   "frankstengard",
		"robert'); DROP--": "robertDROP--",
		"Ærlig":            "Ærlig",
	}

	for input, want := range cases {
		if got := sanitizeUsername(input); got != want {
			t.Errorf("sanitizeUsername(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestTruncateRunesLeavesShortInputAlone(t *testing.T) {
	if got := truncateRunes("short", 100); got != "short" {
		t.Errorf("got %q", got)
	}
}
