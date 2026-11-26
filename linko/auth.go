package main

import (
	"context"
	"crypto/rand"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	pkgerr "github.com/pkg/errors"
)

type contextKey string

const (
	logContextKey  contextKey = "log_context"
	UserContextKey contextKey = "user"
)

type LogContext struct {
	Username string
	Error    error
}

var allowedUsers = map[string]string{
	"frodo":   "$2a$10$B6O/n6teuCzpuh66jrUAdeaJ3WvXcxRkzpN0x7H.di9G9e/NGb9Me",
	"samwise": "$2a$10$EWZpvYhUJtJcEMmm/IBOsOGIcpxUnGIVMRiDlN/nxl1RRwWGkJtty",
	// frodo: "ofTheNineFingers"
	// samwise: "theStrong"
	"saruman": "invalidFormat",
}

func httpError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	if logCtx, ok := ctx.Value(logContextKey).(*LogContext); ok {
		logCtx.Error = err
	}
	http.Error(w, err.Error(), status)
}

func (s *server) requestIdMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestId := r.Header.Get("X-Request-ID")
		if requestId == "" {
			requestId = rand.Text()
		}
		w.Header().Set("X-Request-ID", requestId)
		next.ServeHTTP(w, r)
	})
}

func (s *server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			httpError(r.Context(), w, http.StatusUnauthorized, pkgerr.New("missing or invalid Authorization header"))
			return
		}
		stored, exists := allowedUsers[username]
		if !exists {
			httpError(r.Context(), w, http.StatusUnauthorized, pkgerr.New("user not found"))
			return
		}
		ok, err := s.validatePassword(password, stored)
		if err != nil {
			s.logger.Error("error validating password", "user", username, "error", err)
			httpError(r.Context(), w, http.StatusInternalServerError, pkgerr.Wrap(err, "error validating password"))
			return
		}
		if !ok {
			httpError(r.Context(), w, http.StatusUnauthorized, pkgerr.New("invalid password"))
			return
		}
		if logCtx, ok := r.Context().Value(logContextKey).(*LogContext); ok {
			logCtx.Username = username
		}
		r = r.WithContext(context.WithValue(r.Context(), UserContextKey, username))
		next.ServeHTTP(w, r)
	})
}

func (s *server) validatePassword(password, stored string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		// s.logger.Error(fmt.Sprintf("error validating password: %v", err))
		return false, pkgerr.WithStack(err)
	}
	return true, nil
}
