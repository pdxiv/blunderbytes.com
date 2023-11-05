package handlers

import "net/http"

func SessionAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		c, err := request.Cookie("session_token")
		if err != nil {
			// No cookie, redirect to login or send unauthorized response
			http.Redirect(w, request, "/login", http.StatusSeeOther)
			return
		}

		// Validate the session token against the database
		if !isValidSessionToken(c.Value) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// If the session token is valid, continue to the actual handler
		next.ServeHTTP(w, request)
	})
}
