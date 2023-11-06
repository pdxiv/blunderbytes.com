package handlers

import (
	"bufio"
	"html"
	"regexp"
	"strconv"
	"strings"
)

type markdownParserState struct {
	inOrderedList        bool
	inUnorderedList      bool
	inCodeBlock          bool
	inTable              bool
	inParagraph          bool
	tableHeader          string
	tableBody            string
	tableColumnCount     int
	tableHeaderProcessed bool
}

// Global precompiled regular expressions remain unchanged
var (
	headerSeparatorRegex = regexp.MustCompile(`^\|\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|$`)
	olRegex              = regexp.MustCompile(`^\d+\.\s`)
	codeBlockStartRegex  = regexp.MustCompile("^```")
)

// parseMarkdown translates markdown to HTML.
func parseMarkdown(markdown string) string {
	state := &markdownParserState{} // Initialize empty parser state
	reader := strings.NewReader(markdown)
	scanner := bufio.NewScanner(reader)
	var htmlBuffer strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		parseLine(line, state, &htmlBuffer)
	}

	// Close any open HTML tags if needed
	finalizeHTML(state, &htmlBuffer)

	htmlStr := htmlBuffer.String()
	return replaceInlineFormatting(htmlStr)
}

// finalizeHTML handles any closing tags that are necessary at the end of the document.
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
	if state.inTable {
		htmlBuffer.WriteString("</tbody>\n")
		htmlBuffer.WriteString("</table>\n")
		state.inTable = false
	}
}

// replaceInlineFormatting handles the inline markdown formatting.
func replaceInlineFormatting(htmlStr string) string {
	replacements := []*struct {
		re   *regexp.Regexp
		repl string
	}{
		{regexp.MustCompile(`\*\*\*(.*?)\*\*\*`), "<strong><em>$1</em></strong>"},
		{regexp.MustCompile(`\_\_\_(.*?)\_\_\_`), "<strong><em>$1</em></strong>"},
		{regexp.MustCompile(`\*\*(.*?)\*\*`), "<strong>$1</strong>"},
		{regexp.MustCompile(`\_\_(.*?)\_\_`), "<strong>$1</strong>"},
		{regexp.MustCompile(`\*(.*?)\*`), "<em>$1</em>"},
		{regexp.MustCompile(`\_(.*?)\_`), "<em>$1</em>"},
		{regexp.MustCompile(`\~\~(.*?)\~\~`), "<del>$1</del>"},
		{regexp.MustCompile("`([^`]+)`"), "<code>$1</code>"},
		{regexp.MustCompile(`!\[(.*?)\]\((.*?)\)`), "<img alt=\"$1\" src=\"$2\">"},
		{regexp.MustCompile(`\[(.*?)\]\((.*?)\)`), "<a href=\"$2\">$1</a>"},
	}

	for _, replacement := range replacements {
		htmlStr = replacement.re.ReplaceAllString(htmlStr, replacement.repl)
	}

	return htmlStr
}

// The parseLine function determines which parsing function to call based on the current line
func parseLine(line string, state *markdownParserState, htmlBuffer *strings.Builder) {
	if state.inCodeBlock {
		parseCodeBlock(line, state, htmlBuffer)
		return
	}

	if state.inTable && !strings.HasPrefix(line, "|") {
		finalizeHTML(state, htmlBuffer)
	}

	if state.inTable {
		parseTable(line, state, htmlBuffer)
		return
	}

	// New table check before checking for paragraphs
	if strings.HasPrefix(line, "|") && !headerSeparatorRegex.MatchString(line) {
		parseTable(line, state, htmlBuffer)
		return
	}

	// Check for empty line which should end any current lists
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

	// Detect if we should close the current list before starting a different type
	if state.inOrderedList && !olRegex.MatchString(line) {
		htmlBuffer.WriteString("</ol>\n")
		state.inOrderedList = false
	}
	if state.inUnorderedList && !strings.HasPrefix(line, "* ") {
		htmlBuffer.WriteString("</ul>\n")
		state.inUnorderedList = false
	}

	switch {
	case codeBlockStartRegex.MatchString(line):
		parseCodeBlock(line, state, htmlBuffer)
	case olRegex.MatchString(line):
		parseOrderedList(line, state, htmlBuffer)
	case strings.HasPrefix(line, "* "):
		parseUnorderedList(line, state, htmlBuffer)
	case strings.HasPrefix(line, "#"):
		parseHeader(line, state, htmlBuffer)
	default:
		parseParagraph(line, state, htmlBuffer)
	}
}

func parseHeader(line string, state *markdownParserState, htmlBuffer *strings.Builder) {
	level := strings.Count(line, "#")
	htmlBuffer.WriteString("<h" + strconv.Itoa(level) + ">" + strings.TrimSpace(line[level:]) + "</h" + strconv.Itoa(level) + ">\n")
}

func parseOrderedList(line string, state *markdownParserState, htmlBuffer *strings.Builder) {
	if !state.inOrderedList {
		htmlBuffer.WriteString("<ol>\n")
		state.inOrderedList = true
	}
	line = olRegex.ReplaceAllString(line, "")
	htmlBuffer.WriteString("<li>" + line + "</li>\n")
}

func parseUnorderedList(line string, state *markdownParserState, htmlBuffer *strings.Builder) {
	if !state.inUnorderedList {
		htmlBuffer.WriteString("<ul>\n")
		state.inUnorderedList = true
	}
	line = strings.TrimPrefix(line, "* ")
	htmlBuffer.WriteString("<li>" + line + "</li>\n")
}

func parseCodeBlock(line string, state *markdownParserState, htmlBuffer *strings.Builder) {
	if codeBlockStartRegex.MatchString(line) || state.inCodeBlock {
		if state.inCodeBlock && (line == "```" || codeBlockStartRegex.MatchString(line)) {
			htmlBuffer.WriteString("</code></pre>\n")
			state.inCodeBlock = false
		} else if !state.inCodeBlock {
			htmlBuffer.WriteString("<pre><code>")
			state.inCodeBlock = true
		} else {
			htmlBuffer.WriteString(html.EscapeString(line) + "\n")
		}
	}
}
func parseTable(line string, state *markdownParserState, htmlBuffer *strings.Builder) {
	trimmedLine := strings.TrimSpace(line)

	// Avoid parsing non-table lines as table rows
	if !strings.HasPrefix(trimmedLine, "|") && state.inTable {
		htmlBuffer.WriteString("</tbody>\n</table>\n")
		state.inTable = false
		return
	}

	// Check if the line is a table header or body
	if strings.HasPrefix(trimmedLine, "|") {
		// Check if we are starting a new table
		if !state.inTable {
			htmlBuffer.WriteString("<table>\n")
			state.inTable = true
		}

		// Check for the end of the table
		if len(trimmedLine) == 1 {
			// A lone pipe character '|' on a new line signifies the end of the table
			htmlBuffer.WriteString("</tbody>\n</table>\n")
			state.inTable = false
			return
		}

		// Process the header or a row
		cells := strings.Split(trimmedLine, "|")
		// Remove the first and last element if they are empty
		if len(cells) > 1 && cells[0] == "" {
			cells = cells[1:]
		}
		if len(cells) > 1 && cells[len(cells)-1] == "" {
			cells = cells[:len(cells)-1]
		}

		// If this is a header separator, we should skip adding anything to htmlBuffer
		if headerSeparatorRegex.MatchString(trimmedLine) {
			return
		}

		// Start the header or the body
		if !state.tableHeaderProcessed {
			htmlBuffer.WriteString("<thead>\n<tr>\n")
			for _, cell := range cells {
				htmlBuffer.WriteString("<th>" + strings.TrimSpace(cell) + "</th>\n")
			}
			htmlBuffer.WriteString("</tr>\n</thead>\n<tbody>\n")
			state.tableHeaderProcessed = true
		} else {
			htmlBuffer.WriteString("<tr>\n")
			for _, cell := range cells {
				htmlBuffer.WriteString("<td>" + strings.TrimSpace(cell) + "</td>\n")
			}
			htmlBuffer.WriteString("</tr>\n")
		}
	} else {
		// If the line does not start with a '|' and we are in a table, it's the end of the table
		if state.inTable {
			htmlBuffer.WriteString("</tbody>\n</table>\n")
			state.inTable = false
		}
	}
}

func parseParagraph(line string, state *markdownParserState, htmlBuffer *strings.Builder) {
	// Check if the current line is not empty and if we are already in a paragraph
	if strings.TrimSpace(line) != "" && state.inParagraph {
		// We are in a paragraph and have encountered a non-empty line, so we end the current paragraph
		htmlBuffer.WriteString("</p>\n")
		state.inParagraph = false
	}

	if strings.TrimSpace(line) != "" {
		// If the line is not empty, we start a new paragraph
		if !state.inParagraph {
			htmlBuffer.WriteString("<p>")
			state.inParagraph = true
		}
		htmlBuffer.WriteString(line + "</p>\n") // End the paragraph immediately after the line
		state.inParagraph = false               // Set the state as not in a paragraph since we close it right away
	}
}
