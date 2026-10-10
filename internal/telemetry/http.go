package telemetry

import (
	"context"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Job ends its span before returning. Deferred work supplies links rather than
// keeping native receipt/request spans open through spool or database delays.
func (s *SDK) Job(ctx context.Context, name string, links []trace.Link, run func(context.Context) error) error {
	ctx, finish := s.begin(ctx, name, trace.WithLinks(links...))
	err := run(ctx)
	finish(err, 0)
	return err
}
func (s *SDK) begin(ctx context.Context, name string, options ...trace.SpanStartOption) (context.Context, func(error, int)) {
	name = operation(name)
	attrs := metric.WithAttributes(attribute.String("operation", name))
	s.Metrics.active.Add(ctx, 1, attrs)
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, name, options...)
	return ctx, func(err error, status int) {
		outcome := "success"
		if err != nil || status >= 400 {
			outcome = "failure"
			span.SetStatus(codes.Error, ErrorClass(err))
		}
		span.SetAttributes(attribute.String("outcome", outcome), attribute.String("error_class", ErrorClass(err)))
		if status != 0 {
			span.SetAttributes(attribute.Int("http.response.status_code", status))
		}
		s.Metrics.active.Add(ctx, -1, attrs)
		s.Metrics.duration.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attribute.String("operation", name), attribute.String("outcome", outcome)))
		span.End()
	}
}
func (s *SDK) Handler(name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		ctx := propagation.TraceContext{}.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, finish := s.begin(ctx, name, trace.WithSpanKind(trace.SpanKindServer))
		out := &responseStatus{ResponseWriter: w, status: 200}
		defer func() { finish(nil, out.status) }()
		next.ServeHTTP(out, r.WithContext(ctx))
	})
}

type responseStatus struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *responseStatus) WriteHeader(status int) {
	if !w.wrote {
		w.status = status
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *responseStatus) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(p)
}
func (w *responseStatus) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// HTTPTransport is intended only for vendor adapters, never telemetry exporters.
// It records no URL, body, header, raw error, peer address or baggage.
func (s *SDK) HTTPTransport(backend string, base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return roundTripper(func(r *http.Request) (*http.Response, error) {
		ctx, finish := s.begin(r.Context(), backend, trace.WithSpanKind(trace.SpanKindClient))
		copy := r.Clone(ctx)
		copy.Header = r.Header.Clone()
		copy.Header.Del("Baggage")
		propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(copy.Header))
		response, err := base.RoundTrip(copy)
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		finish(err, status)
		return response, err
	})
}
