package handlers

import (
	"container/list"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// allowedImageTypes are the MIME types accepted for upload and rendered inline.
// SVG is deliberately excluded: it can carry script and is not sniffable as an
// image anyway.
var allowedImageTypes = map[string]bool{
	"image/png":                true,
	"image/jpeg":               true,
	"image/gif":                true,
	"image/webp":               true,
	"image/bmp":                true,
	"image/vnd.microsoft.icon": true,
	"image/x-icon":             true,
}

// staticAssets holds the site chrome, encoded once at startup from the
// embedded filesystem rather than re-read from disk on every request.
type staticAssets struct {
	CSS                 template.CSS
	LogoDataURI         template.URL
	FaviconDataURI      template.URL
	Placeholder1DataURI template.URL
	Placeholder2DataURI template.URL
}

// loadStaticAssets encodes the embedded static files. The embedded FS is the
// single source of truth, so the binary runs from any working directory.
func loadStaticAssets(staticFS fs.FS) (*staticAssets, error) {
	css, err := fs.ReadFile(staticFS, "css/styles.css")
	if err != nil {
		return nil, fmt.Errorf("reading embedded stylesheet: %w", err)
	}

	assets := &staticAssets{CSS: template.CSS(css)}

	images := []struct {
		path   string
		target *template.URL
	}{
		{"images/logo.png", &assets.LogoDataURI},
		{"images/favicon.ico", &assets.FaviconDataURI},
		{"images/placeholder_image_1.png", &assets.Placeholder1DataURI},
		{"images/placeholder_image_2.png", &assets.Placeholder2DataURI},
	}

	for _, image := range images {
		data, err := fs.ReadFile(staticFS, image.path)
		if err != nil {
			return nil, fmt.Errorf("reading embedded asset %q: %w", image.path, err)
		}
		*image.target = dataURI(detectImageMIME(data, image.path), data)
	}

	return assets, nil
}

// detectImageMIME sniffs the content type from the bytes themselves. The
// client-supplied type is never trusted. The file extension is consulted only
// when sniffing is inconclusive, so a conclusive non-image result (such as
// text/plain) can never be overridden by a misleading ".png" suffix.
func detectImageMIME(data []byte, name string) string {
	detected := stripMIMEParameters(http.DetectContentType(data))
	if detected != "application/octet-stream" {
		return detected
	}

	if byExtension := stripMIMEParameters(mime.TypeByExtension(strings.ToLower(filepath.Ext(name)))); byExtension != "" {
		return byExtension
	}

	return "application/octet-stream"
}

// stripMIMEParameters drops any trailing parameters, e.g. "; charset=utf-8".
func stripMIMEParameters(mimeType string) string {
	if semicolon := strings.IndexByte(mimeType, ';'); semicolon >= 0 {
		mimeType = mimeType[:semicolon]
	}
	return strings.TrimSpace(mimeType)
}

// dataURI builds a base64 data URI. The result is typed template.URL because
// html/template otherwise rejects non-http schemes in attribute position; the
// MIME type here is produced by detectImageMIME, never by the client.
func dataURI(mimeType string, data []byte) template.URL {
	return template.URL("data:" + mimeType + ";base64," + base64.StdEncoding.EncodeToString(data))
}

// cachedImage is one encoded upload plus the stat fields used to detect that
// the file on disk changed underneath us.
type cachedImage struct {
	dataURI  template.URL
	modTime  int64
	size     int64
	byteSize int
}

// imageCache is a bounded LRU of base64-encoded uploads. Encoding a multi-
// megabyte photo on every page view is the single most expensive thing the
// home page does, so results are reused until the file changes.
type imageCache struct {
	mu       sync.Mutex
	entries  map[string]*list.Element
	order    *list.List // front = most recently used
	bytes    int
	maxBytes int
}

type imageCacheEntry struct {
	key   string
	value cachedImage
}

func newImageCache(maxBytes int) *imageCache {
	return &imageCache{
		entries:  make(map[string]*list.Element),
		order:    list.New(),
		maxBytes: maxBytes,
	}
}

// get returns the encoded data URI for path, encoding and caching it on miss.
func (c *imageCache) get(path string) (template.URL, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat %q: %w", path, err)
	}

	c.mu.Lock()
	if element, ok := c.entries[path]; ok {
		entry := element.Value.(*imageCacheEntry)
		if entry.value.modTime == info.ModTime().UnixNano() && entry.value.size == info.Size() {
			c.order.MoveToFront(element)
			uri := entry.value.dataURI
			c.mu.Unlock()
			return uri, nil
		}
		// Stale: drop it and re-encode below.
		c.removeElement(element)
	}
	c.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %q: %w", path, err)
	}

	mimeType := detectImageMIME(data, path)
	if !allowedImageTypes[mimeType] {
		return "", fmt.Errorf("%q has unsupported type %q", path, mimeType)
	}

	value := cachedImage{
		dataURI: dataURI(mimeType, data),
		modTime: info.ModTime().UnixNano(),
		size:    info.Size(),
	}
	value.byteSize = len(value.dataURI)

	c.mu.Lock()
	defer c.mu.Unlock()

	// A single image larger than the whole budget is served but not cached.
	if value.byteSize <= c.maxBytes {
		if existing, ok := c.entries[path]; ok {
			c.removeElement(existing)
		}
		element := c.order.PushFront(&imageCacheEntry{key: path, value: value})
		c.entries[path] = element
		c.bytes += value.byteSize
		for c.bytes > c.maxBytes {
			oldest := c.order.Back()
			if oldest == nil {
				break
			}
			c.removeElement(oldest)
		}
	}

	return value.dataURI, nil
}

// removeElement drops one entry. The caller must hold c.mu.
func (c *imageCache) removeElement(element *list.Element) {
	entry := element.Value.(*imageCacheEntry)
	c.order.Remove(element)
	delete(c.entries, entry.key)
	c.bytes -= entry.value.byteSize
}

// embeddedSubFS narrows a filesystem to one of its directories.
func embeddedSubFS(embedded fs.FS, dir string) (fs.FS, error) {
	sub, err := fs.Sub(embedded, dir)
	if err != nil {
		return nil, fmt.Errorf("locating embedded %q: %w", dir, err)
	}
	return sub, nil
}
