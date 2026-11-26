package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"boot.dev/linko/internal/build"
	"boot.dev/linko/internal/store"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	pkgerr "github.com/pkg/errors"
)

type multiError interface {
	error
	Unwrap() []error
}

type stackTracer interface {
	error
	StackTrace() pkgerr.StackTrace
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	httpPort := flag.Int("port", 8899, "port to listen on")
	dataDir := flag.String("data", "./data", "directory to store data")
	flag.Parse()

	status := run(ctx, cancel, *httpPort, *dataDir)
	cancel()
	os.Exit(status)
}

/*
Message: "Served request"
method: HTTP method of the request
path: URL path of the request
client_ip: Remote IP address of the request
duration: Time taken to serve the request
request_body_bytes: Bytes read from the request body
response_status: HTTP status code of the response
response_body_bytes: Bytes written to the response body
user: Authenticated username, if any
*/
func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			logCtx := &LogContext{}
			r = r.WithContext(context.WithValue(r.Context(), logContextKey, logCtx))

			body := &countingReader{r: r.Body}
			if r.Body != nil {
				r.Body = body
			}
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"client_ip", r.RemoteAddr,
				"duration", time.Since(start),
				"request_body_bytes", body.n,
				"response_status", rec.status,
				"response_body_bytes", rec.bytes,
			}
			if requestID := w.Header().Get("X-Request-ID"); requestID != "" {
				attrs = append(attrs, "request_id", requestID)
			}
			if logCtx.Username != "" {
				attrs = append(attrs, "user", logCtx.Username)
			}
			if logCtx.Error != nil {
				attrs = append(attrs, "error", logCtx.Error)
			}
			logger.Info("Served request", attrs...)
		})
	}
}

type countingReader struct {
	r io.ReadCloser
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func (c *countingReader) Close() error {
	return c.r.Close()
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

var sensitiveKeys = []string{"password", "key", "apikey", "secret", "pin", "creditcardno", "user", "long_url"}

func redactURLPassword(value string) string {
	u, err := url.Parse(value)
	if err != nil || u.User == nil {
		return value
	}
	if _, hasPassword := u.User.Password(); !hasPassword {
		return value
	}
	return u.Redacted()
}

func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if slices.Contains(sensitiveKeys, a.Key) {
		return slog.String(a.Key, "[REDACTED]")
	}
	if a.Value.Kind() == slog.KindString {
		a.Value = slog.StringValue(redactURLPassword(a.Value.String()))
		return a
	}
	if a.Key != "error" {
		return a
	}

	err, ok := a.Value.Any().(error)
	if !ok || err == nil {
		return a
	}
	if me, ok := err.(multiError); ok {
		var errAttrs []slog.Attr
		for i, e := range me.Unwrap() {
			errAttrs = append(errAttrs, slog.String(fmt.Sprintf("error_%d", i+1), redactURLPassword(e.Error())))
		}
		return slog.GroupAttrs("errors", errAttrs...)
	}
	attrs := []slog.Attr{slog.String("message", redactURLPassword(err.Error()))}
	var st stackTracer
	if errors.As(err, &st) {
		attrs = append(attrs, slog.String("stack_trace", redactURLPassword(fmt.Sprintf("%+v", st.StackTrace()))))
	}
	return slog.GroupAttrs("error", attrs...)
}

func initializeLogger(logFile string) (*slog.Logger, io.Closer, error) {
	useColor := isatty.IsCygwinTerminal(os.Stderr.Fd()) || isatty.IsTerminal(os.Stderr.Fd())
	if logFile == "" {
		return slog.New(tint.NewTextHandler(os.Stderr, &tint.Options{Level: slog.LevelDebug, ReplaceAttr: replaceAttr, NoColor: !useColor})), nil, nil
	}
	fileLogger := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    1,
		MaxAge:     28,
		MaxBackups: 10,
		LocalTime:  false,
		Compress:   true,
	}

	handler := slog.NewMultiHandler(
		tint.NewTextHandler(os.Stderr, &tint.Options{Level: slog.LevelDebug, ReplaceAttr: replaceAttr}),
		slog.NewJSONHandler(fileLogger, &slog.HandlerOptions{Level: slog.LevelInfo, ReplaceAttr: replaceAttr}),
	)
	return slog.New(handler), fileLogger, nil
}

func run(ctx context.Context, cancel context.CancelFunc, httpPort int, dataDir string) int {
	logger, logF, err := initializeLogger(os.Getenv("LINKO_LOG_FILE"))
	hostname, _ := os.Hostname()
	logger = logger.With("git_sha", build.GitSHA, "build_time", build.BuildTime, "env", os.Getenv("ENV"), "hostname", hostname)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if logF != nil {
		defer logF.Close()
	}
	st, err := store.New(dataDir, logger)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create store: %v", err))
		return 1
	}
	s := newServer(*st, httpPort, cancel, logger)
	var serverErr error
	go func() {
		serverErr = s.start()
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.shutdown(shutdownCtx); err != nil {
		logger.Error(fmt.Sprintf("failed to shutdown server: %v", err))
		return 1
	}
	if serverErr != nil {
		logger.Error(fmt.Sprintf("server error: %v", serverErr))
		return 1
	}
	return 0
}
