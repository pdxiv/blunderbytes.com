package handlers

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// uploadExtensions maps an accepted image type to the extension used on disk.
// The client-supplied filename is never reused, so this is the only source of
// extensions.
var uploadExtensions = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpg",
	"image/gif":  ".gif",
	"image/webp": ".webp",
	"image/bmp":  ".bmp",
}

// sniffLength is how many bytes http.DetectContentType needs.
const sniffLength = 512

// handleNew renders the post creation form. Authentication is enforced by
// requireSession on the route rather than repeated here.
func (s *Server) handleNew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := s.newTemplateData(w, r, "New Blog Post")
	s.render(w, http.StatusOK, "upload", data)
}

// handleUpload stores a new post and its image.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, username := s.currentUser(r)

	// Cap the request body as well as the parsed form, so an oversized upload
	// is refused rather than buffered to disk in full.
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes+sniffLength)
	if err := r.ParseMultipartForm(s.cfg.MaxUploadBytes); err != nil {
		http.Error(w, "The uploaded file is too large or the form is malformed",
			http.StatusBadRequest)
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			r.MultipartForm.RemoveAll()
		}
	}()

	if !s.checkCSRF(r) {
		http.Error(w, "Invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	title := sanitizeTitle(r.FormValue("title"))
	content := sanitizeContent(r.FormValue("content"))
	if title == "" || content == "" {
		http.Error(w, "Title and content must be provided", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "An image file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	storedName, err := s.storeUpload(file, header.Size)
	if err != nil {
		var invalid *invalidUploadError
		if errors.As(err, &invalid) {
			http.Error(w, invalid.Error(), http.StatusBadRequest)
			return
		}
		s.serverError(w, err)
		return
	}

	if _, err := s.db.Exec(
		`INSERT INTO blogs (title, content, author, image_path) VALUES (?, ?, ?, ?)`,
		title, content, username, storedName,
	); err != nil {
		// The row is what makes the file reachable; without it the file is
		// orphaned, so clean it up.
		if removeErr := os.Remove(filepath.Join(s.cfg.UploadsDir, storedName)); removeErr != nil {
			logf("removing orphaned upload %q: %v", storedName, removeErr)
		}
		s.serverError(w, fmt.Errorf("inserting blog entry: %w", err))
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// invalidUploadError marks a rejection caused by the submitted data rather
// than by a server fault.
type invalidUploadError struct{ message string }

func (e *invalidUploadError) Error() string { return e.message }

// storeUpload validates and writes an uploaded image, returning the generated
// filename. The client's filename is discarded entirely: reusing it allows a
// crafted value such as "a/../../blog.db" to escape the uploads directory.
func (s *Server) storeUpload(file io.Reader, declaredSize int64) (string, error) {
	if declaredSize > s.cfg.MaxUploadBytes {
		return "", &invalidUploadError{"The uploaded file is too large"}
	}

	header := make([]byte, sniffLength)
	read, err := io.ReadFull(file, header)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading upload: %w", err)
	}
	header = header[:read]
	if read == 0 {
		return "", &invalidUploadError{"The uploaded file is empty"}
	}

	// The content type is sniffed from the bytes; the multipart Content-Type
	// header is attacker-controlled and is not consulted.
	mimeType := detectImageMIME(header, "")
	extension, ok := uploadExtensions[mimeType]
	if !ok {
		return "", &invalidUploadError{"Only PNG, JPEG, GIF, WebP, and BMP images are allowed"}
	}

	if err := os.MkdirAll(s.cfg.UploadsDir, 0o755); err != nil {
		return "", fmt.Errorf("creating uploads directory: %w", err)
	}

	token, err := randomToken(16)
	if err != nil {
		return "", err
	}
	storedName := token + extension
	destinationPath := filepath.Join(s.cfg.UploadsDir, storedName)

	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", fmt.Errorf("creating %q: %w", destinationPath, err)
	}

	written, copyErr := io.Copy(destination,
		io.LimitReader(io.MultiReader(bytes.NewReader(header), file), s.cfg.MaxUploadBytes+1))
	closeErr := destination.Close()

	switch {
	case copyErr != nil:
		os.Remove(destinationPath)
		return "", fmt.Errorf("writing upload: %w", copyErr)
	case closeErr != nil:
		os.Remove(destinationPath)
		return "", fmt.Errorf("closing upload: %w", closeErr)
	case written > s.cfg.MaxUploadBytes:
		os.Remove(destinationPath)
		return "", &invalidUploadError{"The uploaded file is too large"}
	}

	return storedName, nil
}
