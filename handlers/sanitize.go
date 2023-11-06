package handlers

import (
	"regexp"
)

const MAX_INPUT_LENGTH = 255

// sanitizeInput takes a string and ensures it only contains allowed characters.
// It also trims the input to a maximum length of 255 characters.
func sanitizeInput(input string) string {
	// Extended the pattern to include Markdown characters such as *, _, ~, `, [], and ()
	allowedPattern := regexp.MustCompile(`[^\w\n:,.!/=\?"#*+~` + "`" + `\[\]()-]+`)
	if len(input) > MAX_INPUT_LENGTH {
		input = input[:MAX_INPUT_LENGTH]
	}
	return allowedPattern.ReplaceAllString(input, "")
}
