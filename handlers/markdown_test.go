package handlers

import (
	"strings"
	"testing"
)

func TestParseMarkdownEscapesHTML(t *testing.T) {
	// Post text must never be able to introduce tags of its own.
	cases := []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`plain <b>bold</b> attempt`,
	}

	for _, input := range cases {
		got := parseMarkdown(input)
		// Escaped text containing the word "onerror" is harmless; what matters
		// is that no tag survives unescaped.
		if strings.Contains(got, "<script") || strings.Contains(got, "<b>") ||
			strings.Contains(got, "<img ") {
			t.Errorf("parseMarkdown(%q) leaked raw HTML: %q", input, got)
		}
		if !strings.Contains(got, "&lt;") {
			t.Errorf("parseMarkdown(%q) = %q, want escaped angle brackets", input, got)
		}
	}
}

func TestParseMarkdownRejectsDangerousURLs(t *testing.T) {
	cases := map[string]string{
		"[x](javascript:alert(1))":       `href="#"`,
		"[x](JaVaScRiPt:alert(1))":       `href="#"`,
		"[x](data:text/html;base64,abc)": `href="#"`,
		"[x](https://example.com/)":      `href="https://example.com/"`,
		"[x](/uploads/a.png)":            `href="/uploads/a.png"`,
		"[x](#anchor)":                   `href="#anchor"`,
	}

	for input, want := range cases {
		if got := parseMarkdown(input); !strings.Contains(got, want) {
			t.Errorf("parseMarkdown(%q) = %q, want it to contain %q", input, got, want)
		}
	}
}

func TestParseHeaderCountsOnlyLeadingHashes(t *testing.T) {
	// "# C# rocks" used to become an <h2> because every '#' on the line counted.
	got := parseMarkdown("# C# rocks")

	if !strings.Contains(got, "<h1>") || !strings.Contains(got, "</h1>") {
		t.Errorf("got %q, want an <h1>", got)
	}
	if strings.Contains(got, "<h2>") {
		t.Errorf("got %q, want no <h2>", got)
	}
}

func TestParseHeaderLevels(t *testing.T) {
	if got := parseMarkdown("### three"); !strings.Contains(got, "<h3>three</h3>") {
		t.Errorf("got %q", got)
	}
	// Seven hashes is not a valid header and falls through to a paragraph.
	if got := parseMarkdown("####### seven"); !strings.Contains(got, "<p>") {
		t.Errorf("got %q, want a paragraph", got)
	}
}

func TestSecondTableGetsItsOwnHeader(t *testing.T) {
	// tableHeaderProcessed was never reset, so a second table lost its <thead>.
	input := "| a | b |\n| --- | --- |\n| 1 | 2 |\n\ntext\n\n| c | d |\n| --- | --- |\n| 3 | 4 |\n"

	got := parseMarkdown(input)

	if count := strings.Count(got, "<thead>"); count != 2 {
		t.Errorf("got %d <thead> elements, want 2\n%s", count, got)
	}
	if count := strings.Count(got, "<table>"); count != 2 {
		t.Errorf("got %d <table> elements, want 2\n%s", count, got)
	}
	if !strings.Contains(got, "<th>c</th>") {
		t.Errorf("second table header missing:\n%s", got)
	}
}

func TestCodeBlockContentIsNotFormatted(t *testing.T) {
	input := "```\nvalue = a * b * c\nlink := \"[x](y)\"\n```\n"

	got := parseMarkdown(input)

	if strings.Contains(got, "<em>") {
		t.Errorf("inline formatting leaked into a code block:\n%s", got)
	}
	if strings.Contains(got, "<a href") {
		t.Errorf("link formatting leaked into a code block:\n%s", got)
	}
	if !strings.Contains(got, "<pre><code>") || !strings.Contains(got, "</code></pre>") {
		t.Errorf("code block not delimited:\n%s", got)
	}
}

func TestUnclosedBlocksAreClosed(t *testing.T) {
	cases := map[string]string{
		"* one\n* two":          "</ul>",
		"1. one\n2. two":        "</ol>",
		"```\ncode":             "</code></pre>",
		"| a |\n| --- |\n| 1 |": "</table>",
	}

	for input, want := range cases {
		if got := parseMarkdown(input); !strings.Contains(got, want) {
			t.Errorf("parseMarkdown(%q) = %q, want it to contain %q", input, got, want)
		}
	}
}

func TestInlineFormatting(t *testing.T) {
	cases := map[string]string{
		"**bold**":   "<strong>bold</strong>",
		"*italic*":   "<em>italic</em>",
		"~~gone~~":   "<del>gone</del>",
		"`code`":     "<code>code</code>",
		"***both***": "<strong><em>both</em></strong>",
	}

	for input, want := range cases {
		if got := parseMarkdown(input); !strings.Contains(got, want) {
			t.Errorf("parseMarkdown(%q) = %q, want it to contain %q", input, got, want)
		}
	}
}

func TestBothListMarkersWork(t *testing.T) {
	for _, marker := range []string{"*", "-"} {
		got := parseMarkdown(marker + " item\n")
		if !strings.Contains(got, "<li>item</li>") {
			t.Errorf("marker %q produced %q", marker, got)
		}
	}
}
