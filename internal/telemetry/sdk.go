package telemetry

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/bridges/otellogrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type Identity struct{ Version, Instance, Environment, Host string }
type Exporters struct {
	Logs    sdklog.Exporter
	Traces  sdktrace.SpanExporter
	Metrics sdkmetric.Exporter
}
type SDK struct {
	Logger   *logrus.Logger
	Tracer   trace.Tracer
	Metrics  *Measurements
	logs     *sdklog.LoggerProvider
	traces   *sdktrace.TracerProvider
	metrics  *sdkmetric.MeterProvider
	timeout  time.Duration
	Failures atomic.Uint64
}

var global struct {
	sync.Mutex
	sdk *SDK
}

// Initialize installs the only process-wide providers. A second caller cannot
// replace them or attach a duplicate remote hook. Startup owns this call.
func Initialize(ctx context.Context, c config.Telemetry, id Identity, local io.Writer) (*SDK, error) {
	global.Lock()
	defer global.Unlock()
	if global.sdk != nil {
		return nil, errors.New("telemetry already initialized")
	}
	ex, err := exporters(ctx, c)
	if err != nil {
		return nil, err
	}
	s, err := newSDK(ctx, c, id, ex, local)
	if err != nil {
		return nil, err
	}
	otel.SetTracerProvider(s.traces)
	otel.SetMeterProvider(s.metrics)
	otel.SetLoggerProvider(s.logs)
	otel.SetTextMapPropagator(propagation.TraceContext{}) // no arbitrary baggage
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) { s.Failures.Add(1) }))
	global.sdk = s
	return s, nil
}
func newSDK(_ context.Context, c config.Telemetry, id Identity, ex Exporters, local io.Writer) (*SDK, error) {
	if c.QueueSize < 1 || c.Timeout <= 0 || c.ShutdownTimeout <= 0 || c.TraceSampleRatio < 0 || c.TraceSampleRatio > 1 || local == nil {
		return nil, errors.New("invalid telemetry bounds")
	}
	res := resource.NewWithAttributes("", attribute.String("service.name", "cloud-8021x"), attribute.String("service.version", id.Version), attribute.String("service.instance.id", id.Instance), attribute.String("deployment.environment.name", id.Environment), attribute.String("host.name", id.Host))
	s := &SDK{timeout: c.ShutdownTimeout}
	lo := []sdklog.LoggerProviderOption{sdklog.WithResource(res), sdklog.WithAttributeCountLimit(16), sdklog.WithAttributeValueLengthLimit(128)}
	if c.Enabled && c.Logs && ex.Logs != nil {
		lo = append(lo, sdklog.WithProcessor(sdklog.NewBatchProcessor(ex.Logs, sdklog.WithMaxQueueSize(c.QueueSize), sdklog.WithExportMaxBatchSize(min(c.QueueSize, 256)), sdklog.WithExportTimeout(c.Timeout), sdklog.WithExportInterval(time.Second))))
	}
	s.logs = sdklog.NewLoggerProvider(lo...)
	to := []sdktrace.TracerProviderOption{sdktrace.WithResource(res), sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(c.TraceSampleRatio)))}
	if c.Enabled && c.Traces && ex.Traces != nil {
		to = append(to, sdktrace.WithBatcher(ex.Traces, sdktrace.WithMaxQueueSize(c.QueueSize), sdktrace.WithMaxExportBatchSize(min(c.QueueSize, 256)), sdktrace.WithExportTimeout(c.Timeout), sdktrace.WithBatchTimeout(time.Second)))
	}
	s.traces = sdktrace.NewTracerProvider(to...)
	s.Tracer = s.traces.Tracer("cloud-8021x")
	mo := []sdkmetric.Option{sdkmetric.WithResource(res), sdkmetric.WithCardinalityLimit(128)}
	if c.Enabled && c.Metrics && ex.Metrics != nil {
		mo = append(mo, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(ex.Metrics, sdkmetric.WithInterval(15*time.Second), sdkmetric.WithTimeout(c.Timeout))))
	}
	s.metrics = sdkmetric.NewMeterProvider(mo...)
	s.Metrics = newMeasurements(s.metrics.Meter("cloud-8021x"), &s.Failures)
	logger := logrus.New()
	logger.SetOutput(local)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.AddHook(safeHook{})
	if c.Enabled && c.Logs {
		logger.AddHook(otellogrus.NewHook("cloud-8021x", otellogrus.WithLoggerProvider(s.logs)))
	}
	s.Logger = logger
	return s, nil
}
func (s *SDK) Shutdown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	if errors.Join(s.logs.Shutdown(ctx), s.traces.Shutdown(ctx), s.metrics.Shutdown(ctx)) != nil {
		return errors.New("telemetry shutdown incomplete")
	}
	return nil
}

// Sanitization precedes BOTH local output and the bridge. Call sites log bounded
// machine event names; arbitrary messages, error strings and unknown fields never
// become remote telemetry. Exporter errors only increment an atomic counter.
type safeHook struct{}

func (safeHook) Levels() []logrus.Level { return logrus.AllLevels }
func (safeHook) Fire(e *logrus.Entry) error {
	e.Message = safeClass(e.Message)
	safe := logrus.Fields{}
	for _, k := range []string{"operation", "outcome", "error_class", "backend"} {
		if v, ok := e.Data[k].(string); ok {
			safe[k] = safeClass(v)
		}
	}
	if err, ok := e.Data[logrus.ErrorKey].(error); ok {
		safe["error_class"] = ErrorClass(err)
	}
	e.Data = safe
	return nil
}
func ErrorClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "unavailable"
	}
}
