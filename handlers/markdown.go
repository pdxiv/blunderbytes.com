package handlers

import (
	"bufio"
	"html"
	"html/template"
	"regexp"
	"strconv"
	"strings"
)

type markdownParserState struct {
	inOrderedList        bool
	inUnorderedList      bool
	inCodeBlock          bool
	inTable              bool
	tableHeaderProcessed bool
}

var (
	headerSeparatorRegex = regexp.MustCompile(`^\|\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|$`)
	olRegex              = regexp.MustCompile(`^\d+\.\s`)
	codeBlockStartRegex  = regexp.MustCompile("^```")
	atxHeaderRegex       = regexp.MustCompile(`^(#{1,6})\s+(.*)$`)
	imageRegex           = regexp.MustCompile(`!\[(.*?)\]\((.*?)\)`)
	linkRegex            = regexp.MustCompile(`\[(.*?)\]\((.*?)\)`)
	// safeURLPrefixes are the only absolute schemes permitted in links and
	// images. Anything else (javascript:, data:, vbscript:) is neutralised.
	safeURLPrefixes = []string{"http://", "https://", "mailto:"}
)

// renderMarkdown converts post text to HTML that is safe to embed directly.
// Every input line is HTML-escaped before any markup is generated, so author
// text can never introduce tags of its own.
func renderMarkdown(markdown string) template.HTML {
	return template.HTML(parseMarkdown(markdown))
}

// parseMarkdown translates markdown to HTML.
func parseMarkdown(markdown string) string {
	state := &markdownParserState{}
	scanner := bufio.NewScanner(strings.NewReader(markdown))
	// Post bodies can legitimately contain long lines; the default 64KiB
	// scanner buffer is raised to the content limit to avoid silent truncation.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*MaxContentRunes)

	var htmlBuffer strings.Builder
	for scanner.Scan() {
		// Escape first: everything emitted below is generated markup plus
		// already-escaped author text.
		parseLine(html.EscapeString(scanner.Text()), state, &htmlBuffer)
	}

	finalizeHTML(state, &htmlBuffer)
	return htmlBuffer.String()
}

// finalizeHTML closes any tags left open at the end of a block or document.
func finalizeHTML(state *markdownParserState, htmlBuffer *strings.Builder) {
	if state.inOrderedList {
		htmlBuffer.WriteString("</ol>\n")
		state.inOrderedList = false
	}
	if state.inUnorderedList {
		htmlBuffer.WriteString("</ul>\n")
		state.inUnorderedList = false
	}
	if state.inCodeBlock {
		htmlBuffer.WriteString("</code></pre>\n")
		state.inCodeBlock = false
	}
	closeTable(state, htmlBuffer)
}

// closeTable ends an open table and resets the per-table header state, so that
// a second table in the same document gets its own <thead>.
func closeTable(state *markdownParserState, htmlBuffer *strings.Builder) {
	if !state.inTable {
		return
	}
	htmlBuffer.WriteString("</tbody>\n</table>\n")
	state.inTable = false
	state.tableHeaderProcessed = false
}

// inlineReplacements are applied in order to already-escaped text. They are
// compiled once rather than per call.
var inlineReplacements = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`\*\*\*(.+?)\*\*\*`), "<strong><em>$1</em></strong>"},
	{regexp.MustCompile(`___(.+?)___`), "<strong><em>$1</em></strong>"},
	{regexp.MustCompile(`\*\*(.+?)\*\*`), "<strong>$1</strong>"},
	{regexp.MustCompile(`__(.+?)__`), "<strong>$1</strong>"},
	{regexp.MustCompile(`\*(.+?)\*`), "<em>$1</em>"},
	{regexp.MustCompile(`_(.+?)_`), "<em>$1</em>"},
	{regexp.MustCompile(`~~(.+?)~~`), "<del>$1</del>"},
	{regexp.MustCompile("`([^`]+)`"), "<code>$1</code>"},
}

// inline applies inline markdown formatting to a single already-escaped
// fragment. It is applied per fragment rather than to the whole document so
// that the contents of code blocks are left alone.
func inline(text string) string {
	// Images before links: the link pattern also matches the image syntax.
	text = imageRegex.ReplaceAllStringFunc(text, func(match string) string {
		groups := imageRegex.FindStringSubmatch(match)
		return `<img alt="` + groups[1] + `" src="` + safeURL(groups[2]) + `" loading="lazy">`
	})
	text = linkRegex.ReplaceAllStringFunc(text, func(match string) string {
		groups := linkRegex.FindStringSubmatch(match)
		return `<a href="` + safeURL(groups[2]) + `" rel="noopener noreferrer">` + groups[1] + `</a>`
	})

	for _, replacement := range inlineReplacements {
		text = replacement.re.ReplaceAllString(text, replacement.repl)
	}
	return text
}

// safeURL passes through relative URLs, fragments, and a small allowlist of
// schemes. Anything else becomes "#" so that a post cannot smuggle in
// javascript: or data: URLs.
func safeURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "#"
	}

	// Relative paths and fragments carry no scheme and are always safe.
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "./") || strings.HasPrefix(trimmed, "../") {
		return trimmed
	}

	lowered := strings.ToLower(trimmed)
	for _, prefix := range safeURLPrefixes {
		if strings.HasPrefix(lowered, prefix) {
			return trimmed
		}
	}

	// A colon before the first slash means an unrecognised scheme.
	if colon := strings.IndexByte(lowered, ':'); colon >= 0 {
		if slash := strings.IndexByte(lowered, '/'); slash < 0 || colon < slash {
			return "#"
		}
	}
	return trimmed
}

// parseLine dispatches a single line to the right block handler.
func parseLine(line string, state *markdownParserState, htmlBuffer *strings.Builder) {
	if state.inCodeBlock {
		parseCodeBlock(line, state, htmlBuffer)
		return
	}

	if state.inTable && !strings.HasPrefix(strings.TrimSpace(line), "|") {
		closeTable(state, htmlBuffer)
	}

	if state.inTable || strings.HasPrefix(strings.TrimSpace(line), "|") {
		parseTable(line, state, htmlBuffer)
		return
	}

	// A blank line ends any open list.
	if strings.TrimSpace(line) == "" {
		if state.inOrderedList {
			htmlBuffer.WriteString("</ol>\n")
			state.inOrderedList = false
		}
		if state.inUnorderedList {
			htmlBuffer.WriteString("</ul>\n")
			state.inUnorderedList = false
		}
		return
	}

	// Close the current list before starting a different kind of block.
	if state.inOrderedList && !olRegex.MatchString(line) {
		htmlBuffer.WriteString("</ol>\n")
		state.inOrderedList = false
	}
	if state.inUnorderedList && !isUnorderedListItem(line) {
		htmlBuffer.WriteString("</ul>\n")
		state.inUnorderedList = false
	}

	switch {
	case codeBlockStartRegex.MatchString(line):
		parseCodeBlock(line, state, htmlBuffer)
	case olRegex.MatchString(line):
		parseOrderedList(line, state, htmlBuffer)
	case isUnorderedListItem(line):
		parseUnorderedList(line, state, htmlBuffer)
	case atxHeaderRegex.MatchString(line):
		parseHeader(line, htmlBuffer)
	default:
		parseParagraph(line, htmlBuffer)
	}
}

func isUnorderedListItem(line string) bool {
	return strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "- ")
}

// parseHeader emits an <h1>..<h6>. The level comes from the run of leading '#'
// characters only, so a line such as "# C# rocks" is still an <h1>.
func parseHeader(line string, htmlBuffer *strings.Builder) {
	groups := atxHeaderRegex.FindStringSubmatch(line)
	level := strconv.Itoa(len(groups[1]))
	htmlBuffer.WriteString("<h" + level + ">" + inline(strings.TrimSpace(groups[2])) + "</h" + level + ">\n")
}

func parseOrderedList(line string, state *markdownParserState, htmlBuffer *strings.Builder) {
	if !state.inOrderedList {
		htmlBuffer.WriteString("<ol>\n")
		state.inOrderedList = true
	}
	htmlBuffer.WriteString("<li>" + inline(olRegex.ReplaceAllString(line, "")) + "</li>\n")
}

func parseUnorderedList(line string, state *markdownParserState, htmlBuffer *strings.Builder) {
	if !state.inUnorderedList {
		htmlBuffer.WriteString("<ul>\n")
		state.inUnorderedList = true
	}
	item := strings.TrimPrefix(strings.TrimPrefix(line, "* "), "- ")
	htmlBuffer.WriteString("<li>" + inline(item) + "</li>\n")
}

// parseCodeBlock handles fenced code. Content is emitted verbatim (already
// escaped by the caller) with no inline formatting applied.
func parseCodeBlock(line string, state *markdownParserState, htmlBuffer *strings.Builder) {
	if !state.inCodeBlock {
		if codeBlockStartRegex.MatchString(line) {
			htmlBuffer.WriteString("<pre><code>")
			state.inCodeBlock = true
		}
		return
	}

	if codeBlockStartRegex.MatchString(line) {
		htmlBuffer.WriteString("</code></pre>\n")
		state.inCodeBlock = false
		return
	}
	htmlBuffer.WriteString(line + "\n")
}

func parseTable(line string, state *markdownParserState, htmlBuffer *strings.Builder) {
	trimmedLine := strings.TrimSpace(line)

	// A line that is not a table row ends the table.
	if !strings.HasPrefix(trimmedLine, "|") {
		closeTable(state, htmlBuffer)
		return
	}

	if !state.inTable {
		htmlBuffer.WriteString("<table>\n")
		state.inTable = true
	}

	// A lone pipe on its own line closes the table explicitly.
	if len(trimmedLine) == 1 {
		closeTable(state, htmlBuffer)
		return
	}

	// The alignment row contributes no output.
	if headerSeparatorRegex.MatchString(trimmedLine) {
		return
	}

	cells := strings.Split(trimmedLine, "|")
	if len(cells) > 1 && cells[0] == "" {
		cells = cells[1:]
	}
	if len(cells) > 1 && cells[len(cells)-1] == "" {
		cells = cells[:len(cells)-1]
	}

	if !state.tableHeaderProcessed {
		htmlBuffer.WriteString("<thead>\n<tr>\n")
		for _, cell := range cells {
			htmlBuffer.WriteString("<th>" + inline(strings.TrimSpace(cell)) + "</th>\n")
		}
		htmlBuffer.WriteString("</tr>\n</thead>\n<tbody>\n")
		state.tableHeaderProcessed = true
		return
	}

	htmlBuffer.WriteString("<tr>\n")
	for _, cell := range cells {
		htmlBuffer.WriteString("<td>" + inline(strings.TrimSpace(cell)) + "</td>\n")
	}
	htmlBuffer.WriteString("</tr>\n")
}

func parseParagraph(line string, htmlBuffer *strings.Builder) {
	if strings.TrimSpace(line) == "" {
		return
	}
	htmlBuffer.WriteString("<p>" + inline(line) + "</p>\n")
}
