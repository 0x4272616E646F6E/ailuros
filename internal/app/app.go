package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/0x4272616E646F6E/decision-waf/internal/backend"
	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/config"
	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/frontend/extauthz"
	"github.com/0x4272616E646F6E/decision-waf/internal/frontend/extproc"
	"github.com/0x4272616E646F6E/decision-waf/internal/frontend/forwardauth"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
	"github.com/0x4272616E646F6E/decision-waf/internal/telemetry"
	"github.com/0x4272616E646F6E/decision-waf/internal/version"
)

const (
	defaultProbeInterval = 5 * time.Second
	minRecvMsgSize       = 4 << 20
	recvMsgHeadroom      = 64 << 10
)

const ShutdownTimeout = 10 * time.Second

type Options struct {
	Classifier    classifier.Classifier
	Probe         func(context.Context) error
	ProbeInterval time.Duration
	Logger        *slog.Logger
}

type App struct {
	cfg           config.Config
	log           *slog.Logger
	metrics       *telemetry.Metrics
	engine        *decision.Engine
	probe         func(context.Context) error
	probeInterval time.Duration
	ready         atomic.Bool
	hup           chan os.Signal
	listeners     []listener
	health        []*health.Server
	forwardAuthLn net.Listener
	extProcLn     net.Listener
	extAuthzLn    net.Listener
	adminLn       net.Listener
}

func New(cfg config.Config, opts Options) (a *App, err error) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer func() {
		if err != nil {
			signal.Stop(hup)
		}
	}()
	log := opts.Logger
	if log == nil {
		log = telemetry.NewLogger(os.Stdout, cfg.LogLevel)
	}
	logStartupWarnings(log, cfg)
	pol, err := policy.Load(cfg.PolicyFile)
	if err != nil {
		return nil, err
	}
	cls, probe := opts.Classifier, opts.Probe
	if cls == nil {
		if cls, probe, err = backend.New(cfg, log); err != nil {
			return nil, err
		}
	}
	if probe == nil {
		probe = func(context.Context) error { return nil }
	}
	interval := opts.ProbeInterval
	if interval == 0 {
		interval = defaultProbeInterval
	}

	metrics := telemetry.NewMetrics()
	breaker := classifier.NewBreaker(classifier.DefaultBreakerSettings, time.Now)
	metrics.BreakerChanged(cfg.Backend, classifier.BreakerClosed)
	breaker.OnChange(func(s classifier.BreakerState) {
		metrics.BreakerChanged(cfg.Backend, s)
		log.Warn("classifier circuit breaker changed state", "backend", cfg.Backend, "state", s.String())
	})
	engine := backend.Engine(cfg, pol, cls, breaker, telemetry.NewRecorder(log, metrics, cfg.Backend))

	a = &App{cfg: cfg, log: log, metrics: metrics, engine: engine, probe: probe, probeInterval: interval, hup: hup}
	if err := a.listen(); err != nil {
		return nil, err
	}
	return a, nil
}

func maxRecvMsgSize(deepMaxBytes int) int {
	return max(minRecvMsgSize, deepMaxBytes+recvMsgHeadroom)
}

func (a *App) listen() (err error) {
	defer func() {
		if err != nil {
			a.closeListeners()
		}
	}()
	admin := http.NewServeMux()
	admin.Handle("GET /metrics", a.metrics.Handler())
	admin.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	admin.HandleFunc("GET /readyz", a.readyz)
	ln, err := a.serve(a.cfg.MetricsAddr, admin)
	if err != nil {
		return err
	}
	a.adminLn = ln

	if a.cfg.ForwardAuthAddr != "" {
		fa := forwardauth.New(a.engine, a.cfg.InspectionMode, a.cfg.ExposeVerdict,
			func() { a.metrics.Downgrade(forwardauth.FrontendName) }, a.log)
		if a.forwardAuthLn, err = a.serve(a.cfg.ForwardAuthAddr, fa); err != nil {
			return err
		}
	}
	if a.cfg.ExtProcAddr != "" {
		ep := extproc.New(a.engine, extproc.Config{
			Mode: a.cfg.InspectionMode, BodyMaxBytes: a.cfg.BodyMaxBytes,
			DeepMaxBytes: a.cfg.DeepMaxBytes, DeepOversize: a.cfg.DeepOversize, DeepMaxMessages: a.cfg.DeepMaxMessages,
			ExposeVerdict: a.cfg.ExposeVerdict, JA4Header: a.cfg.JA4Header,
		}, func() { a.metrics.Downgrade(extproc.FrontendName) }, a.log)
		if a.extProcLn, err = a.serveGRPC(a.cfg.ExtProcAddr, func(s *grpc.Server) { extprocv3.RegisterExternalProcessorServer(s, ep) }); err != nil {
			return err
		}
	}
	if a.cfg.ExtAuthzAddr != "" {
		ea := extauthz.New(a.engine, a.cfg.InspectionMode, a.cfg.ExposeVerdict, a.cfg.JA4Header,
			func() { a.metrics.Downgrade(extauthz.FrontendName) }, a.log)
		if a.extAuthzLn, err = a.serveGRPC(a.cfg.ExtAuthzAddr, func(s *grpc.Server) { authv3.RegisterAuthorizationServer(s, ea) }); err != nil {
			return err
		}
	}
	return nil
}

type listener struct {
	ln    net.Listener
	serve func(net.Listener) error
	stop  func(context.Context)
	grpc  bool
}

func (a *App) serve(addr string, h http.Handler) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	a.listeners = append(a.listeners, listener{
		ln: ln,
		serve: func(ln net.Listener) error {
			if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
		stop: func(ctx context.Context) {
			if err := srv.Shutdown(ctx); err != nil {
				a.log.Warn("server shutdown error", "error", err)
			}
		},
	})
	return ln, nil
}

func (a *App) serveGRPC(addr string, register func(*grpc.Server)) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	s := grpc.NewServer(grpc.MaxRecvMsgSize(maxRecvMsgSize(a.cfg.DeepMaxBytes)))
	register(s)
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	healthpb.RegisterHealthServer(s, hs)
	a.listeners = append(a.listeners, listener{
		ln: ln,
		serve: func(ln net.Listener) error {
			if err := s.Serve(ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				return err
			}
			return nil
		},
		stop: func(ctx context.Context) { gracefulStop(ctx, s) },
		grpc: true,
	})
	a.health = append(a.health, hs)
	return ln, nil
}

func (a *App) closeListeners() {
	for _, l := range a.listeners {
		_ = l.ln.Close()
	}
}

func addr(ln net.Listener) string {
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}

func (a *App) ForwardAuthAddr() string { return addr(a.forwardAuthLn) }
func (a *App) ExtProcAddr() string     { return addr(a.extProcLn) }
func (a *App) ExtAuthzAddr() string    { return addr(a.extAuthzLn) }
func (a *App) AdminAddr() string       { return a.adminLn.Addr().String() }

func (a *App) readyz(w http.ResponseWriter, _ *http.Request) {
	if a.ready.Load() {
		_, _ = w.Write([]byte("ready\n"))
		return
	}
	http.Error(w, "classifier not ready", http.StatusServiceUnavailable)
}

func (a *App) Run(ctx context.Context) error {
	defer signal.Stop(a.hup)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, len(a.listeners))
	for _, l := range a.listeners {
		go func() {
			if err := l.serve(l.ln); err != nil {
				errc <- err
			}
		}()
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.probeUntilReady(ctx) }()
	go func() { defer wg.Done(); a.watchPolicy(ctx) }()
	a.log.Info("decision-waf started",
		"version", version.Version,
		"backend", a.cfg.Backend, "model", a.cfg.Model, "mode", a.cfg.InspectionMode, "failure_mode", a.cfg.FailureMode,
		"extproc_addr", a.ExtProcAddr(), "extauthz_addr", a.ExtAuthzAddr(),
		"forward_auth_addr", a.ForwardAuthAddr(), "admin_addr", a.AdminAddr())

	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	cancel()
	sctx, scancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer scancel()
	for _, hs := range a.health {
		hs.Shutdown()
	}
	var stopped sync.WaitGroup
	for _, l := range a.listeners {
		if l.grpc {
			stopped.Go(func() { l.stop(sctx) })
		}
	}
	for _, l := range a.listeners {
		if !l.grpc {
			l.stop(sctx)
		}
	}
	stopped.Wait()
	wg.Wait()
	return err
}

func gracefulStop(ctx context.Context, s *grpc.Server) {
	done := make(chan struct{})
	go func() { s.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		s.Stop()
		<-done
	}
}

func (a *App) probeUntilReady(ctx context.Context) {
	for {
		pctx, cancel := context.WithTimeout(ctx, backend.ProbeTimeout)
		err := a.probe(pctx)
		cancel()
		if err == nil {
			a.ready.Store(true)
			for _, hs := range a.health {
				hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
			}
			a.log.Info("classifier ready", "backend", a.cfg.Backend)
			return
		}
		a.log.Error("classifier probe failed; retrying", "backend", a.cfg.Backend, "error", err, "retry_in", a.probeInterval.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(a.probeInterval):
		}
	}
}
