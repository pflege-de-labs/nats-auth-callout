// Package telemetry provides OTEL metrics exported in Prometheus format.
package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pflege-de-labs/nats-auth-callout/internal/auth"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Metrics records auth callout outcomes.
type Metrics struct {
	registry *prometheus.Registry
	provider *sdkmetric.MeterProvider
	requests metric.Int64Counter
	duration metric.Float64Histogram
}

// New creates a meter provider backed by a dedicated Prometheus registry.
func New() (*Metrics, error) {
	reg := prometheus.NewRegistry()
	exp, err := otelprom.New(otelprom.WithRegisterer(reg))
	if err != nil {
		return nil, fmt.Errorf("prometheus exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exp))
	meter := mp.Meter("github.com/pflege-de-labs/nats-auth-callout")

	m := &Metrics{registry: reg, provider: mp}
	if m.requests, err = meter.Int64Counter("auth_callout.requests",
		metric.WithDescription("Handled auth callout requests by result")); err != nil {
		return nil, err
	}
	if m.duration, err = meter.Float64Histogram("auth_callout.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Time to answer an auth callout request")); err != nil {
		return nil, err
	}
	return m, nil
}

// Observe implements auth.Observer.
func (m *Metrics) Observe(ctx context.Context, r auth.Result, d time.Duration) {
	attrs := metric.WithAttributes(attribute.String("result", string(r)))
	m.requests.Add(ctx, 1, attrs)
	m.duration.Record(ctx, d.Seconds(), attrs)
}

// Handler serves the metrics in Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Shutdown flushes and stops the meter provider.
func (m *Metrics) Shutdown(ctx context.Context) error {
	return m.provider.Shutdown(ctx)
}
