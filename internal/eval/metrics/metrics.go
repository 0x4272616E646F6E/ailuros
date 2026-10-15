package metrics

import (
	"cmp"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"

	"github.com/0x4272616E646F6E/ailuros/internal/eval/results"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

const MinPerClass = 100

const LookalikeTag = "lookalike"

type Point struct {
	Threshold float64 `json:"threshold"`
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	TN        int     `json:"tn"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	FPR       float64 `json:"fpr"`
	F1        float64 `json:"f1"`
}

type Category struct {
	Label      string  `json:"label"`
	Total      int     `json:"total"`
	Detected   int     `json:"detected"`
	Recall     float64 `json:"recall"`
	Attributed int     `json:"attributed"`
	Errors     int     `json:"errors"`
}

type Benign struct {
	Total                   int     `json:"total"`
	FalsePositives          int     `json:"false_positives"`
	FPR                     float64 `json:"fpr"`
	Lookalikes              int     `json:"lookalikes"`
	LookalikeFalsePositives int     `json:"lookalike_false_positives"`
	Errors                  int     `json:"errors"`
}

type Latency struct {
	P50 int64 `json:"p50_ms"`
	P95 int64 `json:"p95_ms"`
	P99 int64 `json:"p99_ms"`
}

type Tag struct {
	Tag string `json:"tag"`
	Point
}

type Options struct {
	Threshold float64
	MaxFPR    float64
	ByTag     bool
}

func (o Options) ThresholdFor(h results.Header) float64 {
	if o.Threshold == 0 {
		return h.Threshold
	}
	return o.Threshold
}

type Summary struct {
	Threshold           float64        `json:"threshold"`
	MaxFPR              float64        `json:"max_fpr"`
	Total               int            `json:"total"`
	Scored              int            `json:"scored"`
	Errors              int            `json:"errors"`
	ErrorRate           float64        `json:"error_rate"`
	ErrorsByReason      map[string]int `json:"errors_by_reason"`
	Detection           Point          `json:"detection"`
	Categories          []Category     `json:"categories"`
	Benign              Benign         `json:"benign"`
	Attribution         float64        `json:"attribution"`
	AttributionDetected int            `json:"attribution_detected"`
	Sweep               []Point        `json:"sweep"`
	BestF1              *Point         `json:"best_f1"`
	BestRecall          *Point         `json:"best_recall"`
	Latency             Latency        `json:"latency"`
	Tags                []Tag          `json:"tags,omitempty"`
	Warnings            []string       `json:"warnings"`
}

func At(rs []results.Result, t float64) Point {
	p := Point{Threshold: t}
	for _, r := range rs {
		if r.Failed() {
			continue
		}
		flagged := policy.Blocks(*r.AttackScore, t)
		switch {
		case r.Attack() && flagged:
			p.TP++
		case r.Attack():
			p.FN++
		case flagged:
			p.FP++
		default:
			p.TN++
		}
	}
	p.Precision = ratio(p.TP, p.TP+p.FP)
	p.Recall = ratio(p.TP, p.TP+p.FN)
	p.FPR = ratio(p.FP, p.FP+p.TN)
	if p.Precision+p.Recall > 0 {
		p.F1 = 2 * p.Precision * p.Recall / (p.Precision + p.Recall)
	}
	return p
}

func Sweep(rs []results.Result) []Point {
	pts := make([]Point, 0, 19)
	for i := 1; i <= 19; i++ {
		pts = append(pts, At(rs, float64(i)/20))
	}
	return pts
}

func BestF1(pts []Point) *Point {
	var best *Point
	for i := range pts {
		if pts[i].F1 > 0 && (best == nil || pts[i].F1 >= best.F1) {
			best = &pts[i]
		}
	}
	return clone(best)
}

func BestRecall(pts []Point, maxFPR float64) *Point {
	var best *Point
	for i := range pts {
		if pts[i].FP+pts[i].TN > 0 && pts[i].FPR <= maxFPR && pts[i].Recall > 0 && (best == nil || pts[i].Recall >= best.Recall) {
			best = &pts[i]
		}
	}
	return clone(best)
}

func clone(p *Point) *Point {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}

func Summarize(f *results.File, o Options) Summary {
	t := o.ThresholdFor(f.Header)
	rs := f.Results
	s := Summary{Threshold: t, MaxFPR: o.MaxFPR, Total: len(rs), ErrorsByReason: map[string]int{}, Warnings: []string{}}
	s.Detection = At(rs, t)
	cats := map[string]*Category{}
	lat := make([]int64, 0, len(rs))
	detected, attributed := 0, 0
	for _, r := range rs {
		if r.Limit == "" {
			lat = append(lat, r.LatencyMS)
		}
		if r.Failed() {
			s.Errors++
			s.ErrorsByReason[cmp.Or(r.Error, "unknown")]++
		} else {
			s.Scored++
		}
		if !r.Attack() {
			switch {
			case r.Failed():
				s.Benign.Errors++
			case slices.Contains(r.Tags, LookalikeTag):
				s.Benign.Lookalikes++
				if policy.Blocks(*r.AttackScore, t) {
					s.Benign.LookalikeFalsePositives++
				}
			}
			continue
		}
		c := cats[r.Label]
		if c == nil {
			c = &Category{Label: r.Label}
			cats[r.Label] = c
		}
		if r.Failed() {
			c.Errors++
			continue
		}
		c.Total++
		if policy.Blocks(*r.AttackScore, t) {
			c.Detected++
			if r.Limit == "" {
				detected++
				if r.Category == r.Label {
					c.Attributed++
					attributed++
				}
			}
		}
	}
	for _, l := range slices.Sorted(maps.Keys(cats)) {
		c := cats[l]
		c.Recall = ratio(c.Detected, c.Total)
		s.Categories = append(s.Categories, *c)
	}
	s.Benign.Total, s.Benign.FalsePositives, s.Benign.FPR = s.Detection.TN+s.Detection.FP, s.Detection.FP, s.Detection.FPR
	s.Attribution, s.AttributionDetected = ratio(attributed, detected), detected
	s.ErrorRate = ratio(s.Errors, s.Total)
	s.Sweep = Sweep(rs)
	s.BestF1 = BestF1(s.Sweep)
	s.BestRecall = BestRecall(s.Sweep, o.MaxFPR)
	slices.Sort(lat)
	s.Latency = Latency{P50: percentile(lat, 50), P95: percentile(lat, 95), P99: percentile(lat, 99)}
	if o.ByTag {
		byTag := map[string][]results.Result{}
		for _, r := range rs {
			seen := map[string]bool{}
			for _, tg := range r.Tags {
				if !seen[tg] {
					seen[tg] = true
					byTag[tg] = append(byTag[tg], r)
				}
			}
		}
		for _, tg := range slices.Sorted(maps.Keys(byTag)) {
			s.Tags = append(s.Tags, Tag{Tag: tg, Point: At(byTag[tg], t)})
		}
	}
	s.Warnings = warnings(f.Header, s)
	return s
}

func warnings(h results.Header, s Summary) []string {
	w := []string{}
	expected := h.Dataset.Entries
	if h.Sample > 0 {
		expected = min(expected, h.Sample)
	}
	if s.Total < expected {
		w = append(w, fmt.Sprintf("results cover %d of %d requests; rerun with --resume to finish", s.Total, expected))
	}
	if s.Errors > 0 {
		w = append(w, fmt.Sprintf("%d of %d requests failed and are excluded from detection metrics (%s)", s.Errors, s.Total, Reasons(s.ErrorsByReason)))
	}
	benign, attacks := s.Detection.TN+s.Detection.FP, s.Detection.TP+s.Detection.FN
	if benign < MinPerClass || attacks < MinPerClass {
		w = append(w, fmt.Sprintf("only %d benign and %d attack requests were scored; the sweep and recommendations need at least %d of each to be meaningful", benign, attacks, MinPerClass))
	}
	return w
}

func Reasons(m map[string]int) string {
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	return sorted[min(max(i, 0), len(sorted)-1)]
}
