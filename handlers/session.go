package handlers

import (
	"log"
	"net/http"
)

func isValidSessionToken(token string) bool {
	var sessionCount int
	err := db.QueryRow("SELECT COUNT(*) FROM sessions WHERE token = ? AND expires > datetime('now')", token).Scan(&sessionCount)
	if err != nil {
		log.Println("Error checking session token:", err)
		return false
	}
	return sessionCount > 0
}

func isValidSessionCookie(request *http.Request) (bool, string) {
	// Determine if the user is logged in by checking for a valid session cookie
	cookie, err := request.Cookie("session_token")
	isLoggedIn := false
	username := ""

	// Does a session cookie exist?
	if err == nil {
		// Is the session token in the cookie valid?
		if isValidSessionToken(cookie.Value) {
			isLoggedIn = true
			// Get username from database based on session token
			username, err = getUsernameBySessionToken(cookie.Value)
			if err != nil {
				log.Println(err)
			}
		}
	}

	return isLoggedIn, username
}

func getUsernameBySessionToken(token string) (string, error) {
	var username string
	err := db.QueryRow("SELECT username FROM sessions WHERE token = ?", token).Scan(&username)
	if err != nil {
		log.Println("Error retrieving username by session token:", err)
		return "", err
	}
	return username, nil
}
