package guard

import (
	"context"
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"strings"
	"time"
)

//go:embed web/*
var web embed.FS

func Handler(store *Store) http.Handler {
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, v any, err error) {
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			code := ErrorCode(err)
			status := http.StatusBadRequest
			switch code {
			case "AUTHORITY_UNAVAILABLE", "RESTORE_QUARANTINE", "CLOCK_REGRESSION":
				status = 503
			case "OUTCOME_UNKNOWN":
				status = 503
			case "INTERNAL", "STATE_CORRUPT", "TRUST_MISMATCH":
				status = 500
			case "UNAUTHORIZED", "INVALID_SIGNATURE", "UNKNOWN_IDENTITY", "REVOKED":
				status = 401
			case "POLICY_DENIED":
				status = 403
			case "CONFLICT", "STALE_RESOURCE", "REPLAY":
				status = 409
			case "CAPACITY":
				status = 429
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	}
	parse := func(w http.ResponseWriter, r *http.Request) (Request, error) {
		var req Request
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			return req, fail("CONTENT_TYPE")
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 2*MaxBody))
		if e != nil {
			return req, fail("BODY_LIMIT")
		}
		if StrictJSON(raw, &req) != nil {
			return req, fail("INVALID_REQUEST")
		}
		return req, nil
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { write(w, map[string]string{"status": "alive"}, nil) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if e := store.Ready(ctx); e != nil {
			write(w, nil, e)
			return
		}
		write(w, map[string]string{"status": "ready"}, nil)
	})
	mux.HandleFunc("POST /v1/challenges", func(w http.ResponseWriter, r *http.Request) {
		req, e := parse(w, r)
		if e != nil {
			write(w, nil, e)
			return
		}
		v, e := store.Issue(r.Context(), req)
		write(w, v, e)
	})
	mux.HandleFunc("POST /v1/actions", func(w http.ResponseWriter, r *http.Request) {
		req, e := parse(w, r)
		if e != nil {
			write(w, nil, e)
			return
		}
		v, e := store.Execute(r.Context(), req)
		write(w, v, e)
	})
	auth := func(r *http.Request) (map[string]any, error) {
		v := r.Header.Get("Authorization")
		if !strings.HasPrefix(v, "Bearer ") || len(v) != 71 {
			return nil, fail("UNAUTHORIZED")
		}
		return store.ReadSession(r.Context(), strings.TrimPrefix(v, "Bearer "))
	}
	mux.HandleFunc("GET /v1/state", func(w http.ResponseWriter, r *http.Request) { v, e := auth(r); write(w, v, e) })
	mux.HandleFunc("GET /v1/evidence", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(token) != 64 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			write(w, nil, fail("UNAUTHORIZED"))
			return
		}
		v, e := store.ExportSession(r.Context(), token)
		write(w, v, e)
	})
	files, _ := fs.Sub(web, "web")
	mux.Handle("GET /", http.FileServer(http.FS(files)))
	slots := make(chan struct{}, 32)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			if origin != scheme+"://"+r.Host {
				write(w, nil, fail("ORIGIN_DENIED"))
				return
			}
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			write(w, nil, fail("CAPACITY"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
