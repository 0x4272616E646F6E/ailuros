package report

import (
	"cmp"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/0x4272616E646F6E/decision-waf/internal/eval/metrics"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/results"
)

func Markdown(w io.Writer, h results.Header, s metrics.Summary) error {
	var b strings.Builder
	b.WriteString("# decision-waf-eval report\n\n| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Dataset | %s (`%s`, sha256 `%s`, %d requests%s) |\n",
		md(cmp.Or(h.Dataset.Name, "unnamed")), md(h.Dataset.Path), short(h.Dataset.SHA256), h.Dataset.Entries, sampleNote(h))
	fmt.Fprintf(&b, "| Backend | %s, model `%s`%s |\n", md(h.Backend), md(h.Model), md(serverNote(h)))
	fmt.Fprintf(&b, "| Policy | %s |\n", md(h.Policy))
	fmt.Fprintf(&b, "| Threshold | %s (run: %s) |\n", thr(s.Threshold), thr(h.Threshold))
	fmt.Fprintf(&b, "| decision-waf | %s |\n", md(h.DecisionWafVersion))
	fmt.Fprintf(&b, "| Started | %s |\n", h.Started.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "| Requests | %d (%d scored, %d errors) |\n", s.Total, s.Scored, s.Errors)
	for _, warn := range s.Warnings {
		fmt.Fprintf(&b, "\n> **Warning:** %s\n", md(warn))
	}
	d := s.Detection
	b.WriteString("\n## Detection\n\nAttack vs benign; errors excluded.\n\n")
	b.WriteString("| Precision | Recall | F1 | FPR | TP | FP | TN | FN |\n|---|---|---|---|---|---|---|---|\n")
	fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %d | %d | %d |\n", pr(d), rec(d), f1(d), fpr(d), d.TP, d.FP, d.TN, d.FN)
	if len(s.Categories) > 0 {
		b.WriteString("\n## Attacks by label\n\n| Label | Total | Detected | Recall | Attributed | Errors |\n|---|---|---|---|---|---|\n")
		for _, c := range s.Categories {
			fmt.Fprintf(&b, "| %s | %d | %d | %s | %d | %d |\n", md(c.Label), c.Total, c.Detected, rate(c.Recall, c.Total), c.Attributed, c.Errors)
		}
		fmt.Fprintf(&b, "\nCategory attribution: %s (detected attacks whose top category is the label).\n", attribution(s))
	}
	bn := s.Benign
	b.WriteString("\n## Benign\n\n| Scored | Blocked | FPR | Lookalikes | Lookalikes blocked | Errors |\n|---|---|---|---|---|---|\n")
	fmt.Fprintf(&b, "| %d | %d | %s | %d | %d | %d |\n", bn.Total, bn.FalsePositives, rate(bn.FPR, bn.Total), bn.Lookalikes, bn.LookalikeFalsePositives, bn.Errors)
	b.WriteString("\n## Threshold sweep\n\n| Threshold | Precision | Recall | FPR | F1 |\n|---|---|---|---|---|\n")
	for _, p := range s.Sweep {
		fmt.Fprintf(&b, "| %.2f | %s | %s | %s | %s |\n", p.Threshold, pr(p), rec(p), fpr(p), f1(p))
	}
	fmt.Fprintf(&b, "\n- Best F1: %s\n- Best recall with FPR ≤ %.3f: %s\n", point(s.BestF1), s.MaxFPR, point(s.BestRecall))
	fmt.Fprintf(&b, "\n## Latency and errors\n\n- Latency: p50 %d ms, p95 %d ms, p99 %d ms\n", s.Latency.P50, s.Latency.P95, s.Latency.P99)
	fmt.Fprintf(&b, "- Errors: %s\n", errorDetail(s))
	if len(s.Tags) > 0 {
		b.WriteString("\n## By tag\n\n| Tag | Precision | Recall | FPR | F1 | TP | FP | TN | FN |\n|---|---|---|---|---|---|---|---|---|\n")
		for _, tg := range s.Tags {
			p := tg.Point
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %d | %d | %d | %d |\n", md(tg.Tag), pr(p), rec(p), fpr(p), f1(p), p.TP, p.FP, p.TN, p.FN)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func md(s string) string { return strings.ReplaceAll(s, "|", `\|`) }
