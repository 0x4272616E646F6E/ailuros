package frontendtest

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

func Engine(c classifier.Classifier, failure policy.FailureMode, obs decision.Observer) *decision.Engine {
	guard := classifier.NewGuard(c, 2*time.Second, classifier.NewBreaker(classifier.DefaultBreakerSettings, time.Now))
	return decision.NewEngine(guard, policy.Default(), policy.Defaults{Threshold: 0.8, FailureMode: failure}, obs)
}

func Dial(t testing.TB, register func(*grpc.Server)) *grpc.ClientConn {
	t.Helper()
	srv := grpc.NewServer()
	register(srv)
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

type PanicObserver struct{ Always, OnBlock bool }

func (o PanicObserver) Observe(_ context.Context, _ *inspect.Request, d decision.Decision) {
	if o.Always || o.OnBlock && d.Outcome == decision.Block {
		panic("observer bug")
	}
}

type Recorder struct {
	PanicNext    atomic.Bool
	PanicAlways  atomic.Bool
	PanicOnBlock atomic.Bool

	mu        sync.Mutex
	decisions []decision.Decision
}

func (o *Recorder) Observe(_ context.Context, _ *inspect.Request, d decision.Decision) {
	if o.PanicAlways.Load() || o.PanicOnBlock.Load() && d.Outcome == decision.Block {
		panic("observer bug")
	}
	if o.PanicNext.CompareAndSwap(true, false) {
		panic("observer bug")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.decisions = append(o.decisions, d)
}

func (o *Recorder) All() []decision.Decision {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]decision.Decision(nil), o.decisions...)
}

func (o *Recorder) Last() *decision.Decision {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.decisions) == 0 {
		return nil
	}
	d := o.decisions[len(o.decisions)-1]
	return &d
}
