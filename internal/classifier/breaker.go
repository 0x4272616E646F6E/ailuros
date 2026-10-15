package classifier

import (
	"sync"
	"time"
)

type BreakerState int

const (
	BreakerClosed BreakerState = iota
	BreakerHalfOpen
	BreakerOpen
)

func (s BreakerState) String() string {
	switch s {
	case BreakerHalfOpen:
		return "half_open"
	case BreakerOpen:
		return "open"
	}
	return "closed"
}

type BreakerSettings struct {
	MinCalls int
	Ratio    float64
	Window   time.Duration
	Cooldown time.Duration
}

var DefaultBreakerSettings = BreakerSettings{MinCalls: 20, Ratio: 0.5, Window: 10 * time.Second, Cooldown: 10 * time.Second}

const breakerBuckets = 10

type bucket struct {
	slot       int64
	ok, failed int
}

type Breaker struct {
	mu        sync.Mutex
	settings  BreakerSettings
	now       func() time.Time
	state     BreakerState
	buckets   [breakerBuckets]bucket
	openedAt  time.Time
	probing   bool
	gen       uint64
	onChange  func(BreakerState)
	notifyMu  sync.Mutex
	delivered uint64
}

type Ticket struct{ gen uint64 }

func NewBreaker(s BreakerSettings, now func() time.Time) *Breaker {
	return &Breaker{settings: s, now: now}
}

func (b *Breaker) OnChange(fn func(BreakerState)) {
	b.mu.Lock()
	b.onChange = fn
	b.mu.Unlock()
}

func (b *Breaker) State() BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

func (b *Breaker) Allow() (t Ticket, allowed bool) {
	b.update(func() bool {
		defer func() { t = Ticket{b.gen} }()
		switch b.state {
		case BreakerOpen:
			if b.now().Sub(b.openedAt) < b.settings.Cooldown {
				return false
			}
			b.probing, allowed = true, true
			return b.set(BreakerHalfOpen)
		case BreakerHalfOpen:
			if !b.probing {
				b.probing, allowed = true, true
			}
			return false
		}
		allowed = true
		return false
	})
	return t, allowed
}

func (b *Breaker) current(t Ticket) bool { return t.gen == b.gen }

func (b *Breaker) Success(t Ticket) {
	b.update(func() bool {
		if !b.current(t) {
			return false
		}
		b.probing = false
		if b.state == BreakerHalfOpen {
			b.buckets = [breakerBuckets]bucket{}
			return b.set(BreakerClosed)
		}
		b.bucket().ok++
		return false
	})
}

func (b *Breaker) Failure(t Ticket) {
	b.update(func() bool {
		if !b.current(t) {
			return false
		}
		b.probing = false
		if b.state == BreakerHalfOpen {
			b.openedAt = b.now()
			return b.set(BreakerOpen)
		}
		b.bucket().failed++
		if b.tripped() {
			b.openedAt = b.now()
			return b.set(BreakerOpen)
		}
		return false
	})
}

func (b *Breaker) Abort(t Ticket) {
	b.update(func() bool {
		if !b.current(t) {
			return false
		}
		b.probing = false
		return false
	})
}

func (b *Breaker) update(f func() bool) {
	b.mu.Lock()
	changed := f()
	state, gen, fn := b.state, b.gen, b.onChange
	b.mu.Unlock()
	if !changed || fn == nil {
		return
	}
	b.notifyMu.Lock()
	defer b.notifyMu.Unlock()
	if gen <= b.delivered {
		return
	}
	b.delivered = gen
	fn(state)
}

func (b *Breaker) bucket() *bucket {
	slot := b.slot()
	bk := &b.buckets[slot%breakerBuckets]
	if bk.slot != slot {
		*bk = bucket{slot: slot}
	}
	return bk
}

func (b *Breaker) slot() int64 {
	width := max(b.settings.Window/breakerBuckets, 1)
	return b.now().UnixNano() / int64(width)
}

func (b *Breaker) tripped() bool {
	now := b.slot()
	var ok, failed int
	for _, bk := range b.buckets {
		if bk.slot > now-breakerBuckets {
			ok, failed = ok+bk.ok, failed+bk.failed
		}
	}
	calls := ok + failed
	return calls >= b.settings.MinCalls && float64(failed) >= b.settings.Ratio*float64(calls)
}

func (b *Breaker) set(s BreakerState) bool {
	if b.state == s {
		return false
	}
	b.state = s
	b.gen++
	return true
}
