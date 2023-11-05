package handlers

import "net/http"

func renderTemplate(w http.ResponseWriter, tmplName string, data TemplateData) {
	tmpl, exists := templates[tmplName]
	if !exists {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	err := tmpl.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
