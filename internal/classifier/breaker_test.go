package classifier

import (
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var testBreakerSettings = BreakerSettings{MinCalls: 5, Ratio: 0.5, Window: 10 * time.Second, Cooldown: 10 * time.Second}

func newTestBreaker() (*Breaker, *clock, *[]BreakerState) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	b := NewBreaker(testBreakerSettings, c.now)
	var mu sync.Mutex
	var changes []BreakerState
	b.OnChange(func(s BreakerState) {
		mu.Lock()
		defer mu.Unlock()
		changes = append(changes, s)
	})
	return b, c, &changes
}

func allow(t *testing.T, b *Breaker) Ticket {
	t.Helper()
	tk, ok := b.Allow()
	if !ok {
		t.Fatalf("Allow refused in state %v", b.State())
	}
	return tk
}

func trip(t *testing.T, b *Breaker) {
	t.Helper()
	for i := 0; i < 5; i++ {
		b.Failure(allow(t, b))
	}
	if b.State() != BreakerOpen {
		t.Fatalf("state = %v after 5 failures, want open", b.State())
	}
}

func refused(b *Breaker) bool { _, ok := b.Allow(); return !ok }

func TestBreakerOpensAtMinimumVolume(t *testing.T) {
	b, _, changes := newTestBreaker()
	for i := 0; i < 4; i++ {
		b.Failure(allow(t, b))
	}
	if b.State() != BreakerClosed || refused(b) {
		t.Fatal("opened before 5 failures")
	}
	b.Failure(allow(t, b))
	if b.State() != BreakerOpen || !refused(b) {
		t.Fatalf("state = %v after 5 failures, want open and denying", b.State())
	}
	if len(*changes) != 1 || (*changes)[0] != BreakerOpen {
		t.Errorf("changes = %v", *changes)
	}
}

func TestBreakerOpensOnRatio(t *testing.T) {
	b, _, _ := newTestBreaker()
	for range 3 {
		b.Success(allow(t, b))
	}
	b.Failure(allow(t, b))
	b.Failure(allow(t, b))
	if b.State() != BreakerClosed {
		t.Fatal("opened at 2 failures in 5 calls (40%)")
	}
	b.Failure(allow(t, b))
	if b.State() != BreakerOpen {
		t.Errorf("state = %v at 3 failures in 6 calls (50%%), want open", b.State())
	}
}

func TestBreakerWindowForgets(t *testing.T) {
	b, c, _ := newTestBreaker()
	for range 4 {
		b.Failure(allow(t, b))
	}
	c.advance(11 * time.Second)
	b.Failure(allow(t, b))
	if b.State() != BreakerClosed {
		t.Errorf("state = %v, want closed: only one failure is inside the window", b.State())
	}
}

func TestBreakerDefaultsResistAFewFailingRequests(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	b := NewBreaker(DefaultBreakerSettings, c.now)
	for i := range 200 {
		tk := allow(t, b)
		if i%4 == 0 {
			b.Failure(tk)
		} else {
			b.Success(tk)
		}
		c.advance(50 * time.Millisecond)
	}
	for range 10 {
		b.Failure(allow(t, b))
	}
	if b.State() != BreakerClosed {
		t.Errorf("state = %v, want closed", b.State())
	}
	start := c.now()
	for b.State() == BreakerClosed && c.now().Sub(start) < 10*time.Second {
		b.Failure(allow(t, b))
		c.advance(50 * time.Millisecond)
	}
	if b.State() != BreakerOpen {
		t.Errorf("state = %v after 10 s of failures, want open", b.State())
	}
}

func TestBreakerHalfOpenSingleProbe(t *testing.T) {
	b, c, _ := newTestBreaker()
	trip(t, b)
	c.advance(9 * time.Second)
	if !refused(b) {
		t.Fatal("allowed before cooldown")
	}
	c.advance(time.Second)
	probe, ok := b.Allow()
	if !ok || b.State() != BreakerHalfOpen {
		t.Fatalf("probe not allowed after cooldown; state %v", b.State())
	}
	if !refused(b) {
		t.Fatal("second concurrent probe allowed")
	}
	b.Success(probe)
	if b.State() != BreakerClosed || refused(b) {
		t.Error("successful probe did not close the breaker")
	}
}

func TestBreakerFailedProbeReopens(t *testing.T) {
	b, c, _ := newTestBreaker()
	trip(t, b)
	c.advance(10 * time.Second)
	b.Failure(allow(t, b))
	if b.State() != BreakerOpen || !refused(b) {
		t.Error("failed probe did not reopen the breaker")
	}
}

func TestBreakerAbortReleasesProbe(t *testing.T) {
	b, c, _ := newTestBreaker()
	trip(t, b)
	c.advance(10 * time.Second)
	b.Abort(allow(t, b))
	if refused(b) {
		t.Error("aborted probe was not released; breaker is wedged half-open")
	}
}

func TestBreakerLateSuccessDoesNotCloseOpenBreaker(t *testing.T) {
	b, _, _ := newTestBreaker()
	slow := allow(t, b)
	trip(t, b)
	b.Success(slow)
	if b.State() != BreakerOpen || !refused(b) {
		t.Errorf("state = %v after a late success, want still open", b.State())
	}
}

func TestBreakerLateOutcomesDoNotDisturbTheProbe(t *testing.T) {
	for _, late := range []struct {
		name   string
		report func(*Breaker, Ticket)
	}{
		{"failure", (*Breaker).Failure},
		{"abort", (*Breaker).Abort},
		{"success", (*Breaker).Success},
	} {
		t.Run(late.name, func(t *testing.T) {
			b, c, _ := newTestBreaker()
			slow := allow(t, b)
			trip(t, b)
			c.advance(10 * time.Second)
			probe := allow(t, b)
			late.report(b, slow)
			if b.State() != BreakerHalfOpen {
				t.Fatalf("state = %v after a late %s, want half-open with the probe still running", b.State(), late.name)
			}
			if !refused(b) {
				t.Fatalf("a late %s admitted a second probe", late.name)
			}
			b.Success(probe)
			if b.State() != BreakerClosed {
				t.Errorf("the probe's own success did not close the breaker (state %v)", b.State())
			}
		})
	}
}

func TestBreakerLateFailureAfterRecoveryIsIgnored(t *testing.T) {
	b, c, _ := newTestBreaker()
	slow := allow(t, b)
	trip(t, b)
	c.advance(10 * time.Second)
	b.Success(allow(t, b))
	for i := 0; i < 4; i++ {
		b.Failure(allow(t, b))
	}
	b.Failure(slow)
	if b.State() != BreakerClosed {
		t.Errorf("a stale failure counted toward the threshold (state %v)", b.State())
	}
}

func TestBreakerConcurrentStress(t *testing.T) {
	b, c, _ := newTestBreaker()
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Go(func() {
			for i := range 500 {
				tk, ok := b.Allow()
				if !ok {
					c.advance(time.Second)
					continue
				}
				switch (g + i) % 3 {
				case 0:
					b.Success(tk)
				case 1:
					b.Failure(tk)
				default:
					b.Abort(tk)
				}
			}
		})
	}
	wg.Wait()
	if s := b.State(); s != BreakerClosed && s != BreakerOpen && s != BreakerHalfOpen {
		t.Errorf("invalid state %v", s)
	}
}

func TestBreakerCallbacksArriveInOrder(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	b := NewBreaker(BreakerSettings{MinCalls: 1, Ratio: 0.5, Window: time.Second, Cooldown: time.Second}, c.now)
	entered, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var delivered []BreakerState
	b.OnChange(func(s BreakerState) {
		if s == BreakerOpen {
			close(entered)
			<-release
		}
		mu.Lock()
		defer mu.Unlock()
		delivered = append(delivered, s)
	})
	tk, _ := b.Allow()
	opened := make(chan struct{})
	go func() { b.Failure(tk); close(opened) }()
	<-entered
	c.advance(time.Second)
	probed := make(chan struct{})
	go func() { _, _ = b.Allow(); close(probed) }()
	time.Sleep(50 * time.Millisecond)
	close(release)
	<-opened
	<-probed
	mu.Lock()
	defer mu.Unlock()
	if len(delivered) == 0 || delivered[len(delivered)-1] != BreakerHalfOpen || b.State() != BreakerHalfOpen {
		t.Errorf("delivered %v, breaker %v; want the last delivered state to be half_open", delivered, b.State())
	}
}

func TestBreakerDropsAnOvertakenChange(t *testing.T) {
	b, _, changes := newTestBreaker()
	b.notifyMu.Lock()
	opened := make(chan struct{})
	go func() {
		for range 5 {
			tk, _ := b.Allow()
			b.Failure(tk)
		}
		close(opened)
	}()
	for b.State() != BreakerOpen {
		time.Sleep(time.Millisecond)
	}
	b.delivered = 2
	b.notifyMu.Unlock()
	<-opened
	if len(*changes) != 0 {
		t.Errorf("delivered %v after generation 2; want the older change dropped", *changes)
	}
}
