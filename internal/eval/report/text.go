package report

import (
	"cmp"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/0x4272616E646F6E/decision-waf/internal/eval/metrics"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/results"
)

func Text(w io.Writer, h results.Header, s metrics.Summary) error {
	var b strings.Builder
	runHeader(&b, h)
	fmt.Fprintf(&b, "threshold %s: %d requests, %d scored, %d errors\n", thr(s.Threshold), s.Total, s.Scored, s.Errors)
	for _, warn := range s.Warnings {
		fmt.Fprintf(&b, "warning: %s\n", warn)
	}
	d := s.Detection
	b.WriteString("\ndetection (attack vs benign, errors excluded)\n")
	fmt.Fprintf(&b, "  precision %s  recall %s  f1 %s  false-positive rate %s\n", pr(d), rec(d), f1(d), fpr(d))
	fmt.Fprintf(&b, "  TP %d  FP %d  TN %d  FN %d\n", d.TP, d.FP, d.TN, d.FN)
	if len(s.Categories) > 0 {
		fmt.Fprintf(&b, "\n%-22s %6s %9s %7s %11s %7s\n", "attacks by label", "total", "detected", "recall", "attributed", "errors")
		for _, c := range s.Categories {
			fmt.Fprintf(&b, "  %-20s %6d %9d %7s %11d %7d\n", c.Label, c.Total, c.Detected, rate(c.Recall, c.Total), c.Attributed, c.Errors)
		}
		fmt.Fprintf(&b, "  category attribution %s (detected attacks whose top category is the label)\n", attribution(s))
	}
	bn := s.Benign
	fmt.Fprintf(&b, "\nbenign: %d scored, %d blocked (fpr %s); lookalikes: %d scored, %d blocked; %d errors\n",
		bn.Total, bn.FalsePositives, rate(bn.FPR, bn.Total), bn.Lookalikes, bn.LookalikeFalsePositives, bn.Errors)
	fmt.Fprintf(&b, "\nthreshold sweep\n  %-9s %9s %7s %6s %6s\n", "threshold", "precision", "recall", "fpr", "f1")
	for _, p := range s.Sweep {
		fmt.Fprintf(&b, "  %-9.2f %9s %7s %6s %6s\n", p.Threshold, pr(p), rec(p), fpr(p), f1(p))
	}
	fmt.Fprintf(&b, "\nrecommended\n  best F1: %s\n  best recall with fpr <= %.3f: %s\n", point(s.BestF1), s.MaxFPR, point(s.BestRecall))
	fmt.Fprintf(&b, "\nlatency p50 %d ms, p95 %d ms, p99 %d ms\n", s.Latency.P50, s.Latency.P95, s.Latency.P99)
	fmt.Fprintf(&b, "errors %s\n", errorDetail(s))
	if len(s.Tags) > 0 {
		fmt.Fprintf(&b, "\n%-22s %9s %7s %6s %6s %5s %5s %5s %5s\n", "by tag", "precision", "recall", "fpr", "f1", "TP", "FP", "TN", "FN")
		for _, tg := range s.Tags {
			p := tg.Point
			fmt.Fprintf(&b, "  %-20s %9s %7s %6s %6s %5d %5d %5d %5d\n", tg.Tag, pr(p), rec(p), fpr(p), f1(p), p.TP, p.FP, p.TN, p.FN)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func runHeader(b *strings.Builder, h results.Header) {
	fmt.Fprintf(b, "dataset  %s (%s, sha256 %s, %d requests%s)\n",
		cmp.Or(h.Dataset.Name, "unnamed"), h.Dataset.Path, short(h.Dataset.SHA256), h.Dataset.Entries, sampleNote(h))
	fmt.Fprintf(b, "backend  %s, model %s%s, policy %s, run threshold %s, ailuros %s, started %s\n",
		h.Backend, h.Model, serverNote(h), h.Policy, thr(h.Threshold), h.AilurosVersion, h.Started.UTC().Format(time.RFC3339))
}

func serverNote(h results.Header) string {
	var s string
	if h.BaseURL != "" {
		s += " at " + h.BaseURL
	}
	if h.TimeoutMS > 0 {
		s += fmt.Sprintf(", timeout %s", time.Duration(h.TimeoutMS)*time.Millisecond)
	}
	return s
}

func sampleNote(h results.Header) string {
	if h.Sample == 0 {
		return ""
	}
	return fmt.Sprintf(", sample of %d with seed %d", h.Sample, h.Seed)
}

func errorDetail(s metrics.Summary) string {
	if s.Errors == 0 {
		return "none"
	}
	return fmt.Sprintf("%d of %d (%.1f%%): %s", s.Errors, s.Total, 100*s.ErrorRate, metrics.Reasons(s.ErrorsByReason))
}

func point(p *metrics.Point) string {
	if p == nil {
		return "none"
	}
	return fmt.Sprintf("threshold %.2f (precision %s, recall %s, fpr %s, f1 %s)", p.Threshold, pr(*p), rec(*p), fpr(*p), f1(*p))
}

func thr(t float64) string { return strconv.FormatFloat(t, 'f', -1, 64) }

func attribution(s metrics.Summary) string {
	return rate(s.Attribution, s.AttributionDetected)
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func rate(v float64, denom int) string {
	if denom == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.3f", v)
}

func pr(p metrics.Point) string  { return rate(p.Precision, p.TP+p.FP) }
func rec(p metrics.Point) string { return rate(p.Recall, p.TP+p.FN) }
func fpr(p metrics.Point) string { return rate(p.FPR, p.FP+p.TN) }

func f1(p metrics.Point) string {
	if p.TP+p.FP == 0 || p.TP+p.FN == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.3f", p.F1)
}
