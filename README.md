# blunderbytes.com

An attempt to make a primitive picture blog from scratch in Go.

Posts are written in a small hand-rolled markdown dialect, images are uploaded
through the browser, and the whole page — stylesheet and images included — is
served as a single HTTP GET with everything inlined as `data:` URIs.

## Requirements

- Go 1.19 or newer. Note that the current releases of `mattn/go-sqlite3` and
  `golang.org/x/crypto` require Go 1.21; the pinned versions in `go.mod` are the
  newest that build on 1.19.
- A C compiler, because `mattn/go-sqlite3` uses cgo

## Running it

The first start needs bootstrap credentials; the server refuses to invent a
default account.

```sh
export BLOG_ADMIN_USERNAME=you
export BLOG_ADMIN_PASSWORD='a long passphrase'
export BLOG_SECURE_COOKIES=false   # only for plain-HTTP localhost
go run .
```

Then open http://localhost:8080/. The credentials are read only while the
users table is empty; afterwards they are ignored.

To build a binary instead:

```sh
go build -o blunderbytes.com .
./blunderbytes.com
```

Templates and static assets are embedded in the binary, so it runs from any
working directory. The SQLite database and the uploads directory are created
relative to the process working directory unless configured otherwise.

## Configuration

All settings come from the environment.

| Variable | Default | Meaning |
| --- | --- | --- |
| `BLOG_ADDR` | `:8080` | Listen address |
| `BLOG_DB_PATH` | `./blog.db` | SQLite database file |
| `BLOG_UPLOADS_DIR` | `./uploads` | Where uploaded images are written |
| `BLOG_SESSION_LIFETIME` | `1h` | How long a login lasts |
| `BLOG_MAX_UPLOAD_MB` | `10` | Upload size cap |
| `BLOG_POSTS_PER_PAGE` | `10` | Posts per page on the home page |
| `BLOG_SECURE_COOKIES` | `true` | Set `Secure` on cookies; disable only on plain-HTTP localhost |
| `BLOG_ADMIN_USERNAME` | — | Bootstrap user, first start only |
| `BLOG_ADMIN_PASSWORD` | — | Bootstrap password, first start only |

## Development

```sh
go test ./...          # unit and handler tests
go test -race ./...    # the image cache and rate limiter are concurrent
go vet ./...
gofmt -l .
```

Deploy behind a TLS-terminating reverse proxy. The server sets `Secure` on its
cookies by default and sends a content security policy that forbids scripts
entirely; the site uses none.

## Project layout

| Path | Contents |
| --- | --- |
| `main.go` | Startup, graceful shutdown, embedded assets |
| `config/` | Environment-backed settings |
| `db/` | Schema, connection lifecycle, session sweeping |
| `handlers/` | Routing, sessions, CSRF, rate limiting, request handlers |
| `handlers/markdown.go` | The world's worst markdown parser |
| `templates/`, `static/` | Embedded views and assets |
