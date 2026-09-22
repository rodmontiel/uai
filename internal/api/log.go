package api

import (
	"log/slog"
	"net/http"
)

// problemLog records a non-fatal failure.
//
// It deliberately logs the path and the error and nothing from the body: C3 and
// C4 data must never reach logs (docs/protocol/12-privacy.md section 19.1), and
// a request body is exactly where that data lives.
func problemLog(r *http.Request, msg string, err error) {
	slog.Warn(msg, "err", err, "method", r.Method, "path", r.URL.Path)
}
