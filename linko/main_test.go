package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func Test_requestLogger(t *testing.T) {
	logBuffer := &bytes.Buffer{}

	logger := slog.New(slog.NewTextHandler(logBuffer, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Time(slog.TimeKey, time.Date(2023, 10, 1, 12, 34, 57, 0, time.UTC))
			}
			if a.Key == "duration" {
				return slog.Duration("duration", time.Millisecond)
			}
			return a
		},
	}))

	requestLoggerMiddleware := requestLogger(logger)
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	loggedHandler := requestLoggerMiddleware(dummyHandler)

	req := httptest.NewRequest("GET", "http://lin.ko/api/stats", nil)
	rr := httptest.NewRecorder()
	loggedHandler.ServeHTTP(rr, req)

	const expectedLogString = `time=2023-10-01T12:34:57.000Z level=INFO msg="Served request" method=GET path=/api/stats client_ip=192.0.2.1:1234 duration=1ms request_body_bytes=0 response_status=200 response_body_bytes=0` + "\n"
	const expectedStatusCode = http.StatusOK

	if expectedLogString != logBuffer.String() {
		t.Errorf("Expected log string:\n%s\nGot:\n%s", expectedLogString, logBuffer.String())
	}
	if expectedStatusCode != rr.Code {
		t.Errorf("Expected status code: %d, got: %d", expectedStatusCode, rr.Code)
	}
}

func Test_replaceAttrRedactsURLPasswords(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "URL password",
			in:   "https://alice:secret@example.com/path",
			want: "https://alice:xxxxx@example.com/path",
		},
		{
			name: "URL without password",
			in:   "https://alice@example.com/path",
			want: "https://alice@example.com/path",
		},
		{
			name: "not a URL",
			in:   "value with no URL",
			want: "value with no URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := replaceAttr(nil, slog.String("value", tt.in)).Value.String()
			if got != tt.want {
				t.Errorf("replaceAttr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_replaceAttrRedactsUserKey(t *testing.T) {
	got := replaceAttr(nil, slog.String("user", "alice"))
	if got.Value.String() != "[REDACTED]" {
		t.Errorf("replaceAttr() = %q, want [REDACTED]", got.Value.String())
	}
}

func Test_replaceAttrRedactsLongURL(t *testing.T) {
	got := replaceAttr(nil, slog.String("long_url", "https://alice:secret@example.com/path"))
	if got.Value.String() != "[REDACTED]" {
		t.Errorf("replaceAttr() = %q, want [REDACTED]", got.Value.String())
	}
}
