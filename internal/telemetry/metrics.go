package telemetry

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/0x4272616E646F6E/ailuros/internal/classifier"
)

type Metrics struct {
	registry   *prometheus.Registry
	decisions  *prometheus.CounterVec
	latency    *prometheus.HistogramVec
	errors     *prometheus.CounterVec
	breaker    *prometheus.GaugeVec
	downgrades *prometheus.CounterVec
	reloads    *prometheus.CounterVec
}

func NewMetrics() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ailuros_decisions_total", Help: "Decisions by outcome, category, route, and frontend.",
		}, []string{"outcome", "category", "route", "frontend"}),
		latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "ailuros_classifier_latency_seconds", Help: "Classifier call latency.",
			Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"backend"}),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ailuros_classifier_errors_total", Help: "Classifier failures by reason.",
		}, []string{"backend", "reason"}),
		breaker: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ailuros_circuit_breaker_state", Help: "Circuit breaker state: 0 closed, 1 half-open, 2 open.",
		}, []string{"backend"}),
		downgrades: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ailuros_mode_downgrades_total", Help: "Requests inspected in lite mode because the frontend cannot see bodies.",
		}, []string{"frontend"}),
		reloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ailuros_policy_reloads_total", Help: "Policy reload attempts by result.",
		}, []string{"result"}),
	}
	m.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.decisions, m.latency, m.errors, m.breaker, m.downgrades, m.reloads,
	)
	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Metrics) BreakerChanged(backend string, s classifier.BreakerState) {
	m.breaker.WithLabelValues(backend).Set(float64(s))
}

func (m *Metrics) Downgrade(frontend string) { m.downgrades.WithLabelValues(frontend).Inc() }

func (m *Metrics) PolicyReload(ok bool) {
	result := "success"
	if !ok {
		result = "failure"
	}
	m.reloads.WithLabelValues(result).Inc()
}
