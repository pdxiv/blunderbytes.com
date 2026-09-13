package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"time"
)

// dbBlogEntry is one row as stored, before rendering.
type dbBlogEntry struct {
	ID        int
	Title     string
	Content   string
	Author    string
	ImagePath sql.NullString
	CreatedAt time.Time
}

// handleHome renders one page of posts, newest first.
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	// The "/" pattern matches every otherwise-unrouted path, so anything that
	// is not exactly the root is a 404 rather than a second copy of the
	// home page.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	page := 1
	if raw := r.URL.Query().Get("page"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			http.Error(w, "Invalid page number", http.StatusBadRequest)
			return
		}
		page = parsed
	}

	total, err := s.countBlogEntries()
	if err != nil {
		s.serverError(w, err)
		return
	}

	rows, err := s.blogEntriesPage(page, s.cfg.PostsPerPage)
	if err != nil {
		s.serverError(w, err)
		return
	}

	entries := make([]BlogEntry, 0, len(rows))
	for _, row := range rows {
		entry := BlogEntry{
			ID:        row.ID,
			Title:     row.Title,
			Content:   renderMarkdown(row.Content),
			Author:    row.Author,
			CreatedAt: row.CreatedAt,
		}

		if row.ImagePath.Valid && row.ImagePath.String != "" {
			uri, err := s.images.get(s.resolveImagePath(row.ImagePath.String))
			if err != nil {
				// A missing or unreadable image must not take down the page;
				// the post is still rendered without it.
				logf("skipping image for post %d: %v", row.ID, err)
			} else {
				entry.ImageURI = uri
			}
		}

		entries = append(entries, entry)
	}

	lastPage := (total + s.cfg.PostsPerPage - 1) / s.cfg.PostsPerPage
	data := s.newTemplateData(w, r, "Home")
	data.BlogEntries = entries
	data.Pagination = Pagination{
		Page:     page,
		HasPrev:  page > 1,
		HasNext:  page < lastPage,
		PrevPage: page - 1,
		NextPage: page + 1,
	}

	s.render(w, http.StatusOK, "index", data)
}

// resolveImagePath maps a stored image reference onto a path inside the
// configured uploads directory. Only the base name is used, so neither a
// legacy row holding a full relative path nor a hostile one holding "../"
// can read outside that directory.
func (s *Server) resolveImagePath(stored string) string {
	return filepath.Join(s.cfg.UploadsDir, filepath.Base(stored))
}

func (s *Server) countBlogEntries() (int, error) {
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM blogs").Scan(&total); err != nil {
		return 0, fmt.Errorf("counting blog entries: %w", err)
	}
	return total, nil
}

// blogEntriesPage returns one page of posts ordered by creation time, with id
// as a tiebreaker for rows written within the same second.
func (s *Server) blogEntriesPage(page, perPage int) ([]dbBlogEntry, error) {
	rows, err := s.db.Query(`
		SELECT id, title, content, author, image_path, created_at
		FROM blogs
		ORDER BY created_at DESC, id DESC
		LIMIT ? OFFSET ?`, perPage, (page-1)*perPage)
	if err != nil {
		return nil, fmt.Errorf("querying blog entries: %w", err)
	}
	defer rows.Close()

	var entries []dbBlogEntry
	for rows.Next() {
		var entry dbBlogEntry
		if err := rows.Scan(&entry.ID, &entry.Title, &entry.Content,
			&entry.Author, &entry.ImagePath, &entry.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning blog entry: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading blog entries: %w", err)
	}
	return entries, nil
}
