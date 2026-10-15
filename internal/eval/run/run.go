package run

import (
	"cmp"
	"context"
	"maps"
	"math"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/0x4272616E646F6E/ailuros/internal/classifier"
	"github.com/0x4272616E646F6E/ailuros/internal/decision"
	"github.com/0x4272616E646F6E/ailuros/internal/eval/dataset"
	"github.com/0x4272616E646F6E/ailuros/internal/eval/results"
	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
)

var source = decision.Source{Frontend: "ailuros-eval", Mode: inspect.ModeStandard}

func NewBreaker() *classifier.Breaker {
	return classifier.NewBreaker(classifier.BreakerSettings{MinCalls: math.MaxInt, Ratio: 1, Window: time.Hour, Cooldown: time.Hour}, time.Now)
}

func Run(ctx context.Context, eng *decision.Engine, entries []dataset.Entry, done map[string]bool,
	bodyMax, concurrency int, w *results.Writer, progress func()) error {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		jobs     = make(chan dataset.Entry)
		wg       sync.WaitGroup
		errOnce  sync.Once
		writeErr error
	)
	for range max(concurrency, 1) {
		wg.Go(func() {
			for e := range jobs {
				d := eng.Decide(ctx, e.Request(bodyMax), source)
				if ctx.Err() != nil {
					continue
				}
				if err := w.Write(ResultOf(e, d)); err != nil {
					errOnce.Do(func() { writeErr = err })
					cancel()
					continue
				}
				if progress != nil {
					progress()
				}
			}
		})
	}
feed:
	for _, e := range entries {
		if done[e.ID] {
			continue
		}
		select {
		case jobs <- e:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if writeErr != nil {
		return writeErr
	}
	return parent.Err()
}

func ResultOf(e dataset.Entry, d decision.Decision) results.Result {
	r := results.Result{ID: e.ID, Label: e.Label, Tags: e.Tags, Outcome: string(d.Outcome), LatencyMS: d.Latency.Milliseconds()}
	if d.Note == decision.NoteLimit {
		one := 1.0
		r.AttackScore, r.Limit = &one, d.Limit
		return r
	}
	if d.Classified {
		s := d.Verdict.AttackScore()
		r.AttackScore, r.Category = &s, d.Verdict.Category
	} else {
		r.Error = cmp.Or(string(d.Reason), string(d.Note), "unknown")
	}
	return r
}

func Sample(entries []dataset.Entry, n int, seed uint64) []dataset.Entry {
	if n <= 0 || n >= len(entries) {
		return entries
	}
	byLabel := map[string][]int{}
	for i, e := range entries {
		byLabel[e.Label] = append(byLabel[e.Label], i)
	}
	labels := slices.Sorted(maps.Keys(byLabel))
	quota := map[string]int{}
	type remainder struct {
		label string
		frac  float64
	}
	var rems []remainder
	total := 0
	for _, l := range labels {
		exact := float64(n) * float64(len(byLabel[l])) / float64(len(entries))
		q := int(exact)
		quota[l] = q
		total += q
		rems = append(rems, remainder{l, exact - float64(q)})
	}
	slices.SortStableFunc(rems, func(a, b remainder) int { return cmp.Compare(b.frac, a.frac) })
	for i := 0; total < n; i++ {
		quota[rems[i].label]++
		total++
	}
	if n >= len(labels) {
		for _, l := range labels {
			if quota[l] > 0 {
				continue
			}
			donor := labels[0]
			for _, d := range labels {
				if quota[d] > quota[donor] {
					donor = d
				}
			}
			quota[donor]--
			quota[l]++
		}
	}
	rng := rand.New(rand.NewPCG(seed, 0)) //nolint:gosec // G404: sampling must be reproducible from --seed, not unpredictable
	var chosen []int
	for _, l := range labels {
		idx := slices.Clone(byLabel[l])
		rng.Shuffle(len(idx), func(i, j int) { idx[i], idx[j] = idx[j], idx[i] })
		chosen = append(chosen, idx[:quota[l]]...)
	}
	slices.Sort(chosen)
	out := make([]dataset.Entry, len(chosen))
	for i, c := range chosen {
		out[i] = entries[c]
	}
	return out
}
