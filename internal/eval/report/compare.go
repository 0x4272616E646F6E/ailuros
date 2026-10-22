package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/0x4272616E646F6E/decision-waf/internal/eval/metrics"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/results"
)

func CheckComparable(a, b results.Header, allowDifferent bool) error {
	if allowDifferent || (a.Dataset.SHA256 == b.Dataset.SHA256 && a.Sample == b.Sample && a.Seed == b.Seed) {
		return nil
	}
	return fmt.Errorf("the runs used different datasets or samples (sha256 %s sample %d vs sha256 %s sample %d); pass --allow-different-datasets to compare anyway",
		short(a.Dataset.SHA256), a.Sample, short(b.Dataset.SHA256), b.Sample)
}

func Compare(w io.Writer, a, b *results.File, o metrics.Options) error {
	o.Threshold = o.ThresholdFor(a.Header)
	sa, sb := metrics.Summarize(a, o), metrics.Summarize(b, o)
	var buf strings.Builder
	fmt.Fprintf(&buf, "compare at threshold %s\n", thr(o.Threshold))
	for _, r := range []struct {
		name string
		h    results.Header
	}{{"A", a.Header}, {"B", b.Header}} {
		fmt.Fprintf(&buf, "%s  %s / %s on %s (sha256 %s%s), decision-waf %s\n", r.name, r.h.Backend, r.h.Model,
			r.h.Dataset.Name, short(r.h.Dataset.SHA256), sampleNote(r.h), r.h.DecisionWafVersion)
	}
	if pa, pb := max(a.Header.PromptVersion, 1), max(b.Header.PromptVersion, 1); pa != pb {
		fmt.Fprintf(&buf, "warning: prompt versions differ (A %d, B %d); scores are not directly comparable\n", pa, pb)
	}
	row := func(name, x, y string) { fmt.Fprintf(&buf, "%-30s %-20s %s\n", name, x, y) }
	buf.WriteString("\n")
	row("", "A", "B")
	row("backend / model", a.Header.Backend+" / "+a.Header.Model, b.Header.Backend+" / "+b.Header.Model)
	row("scored / errors", fmt.Sprintf("%d / %d", sa.Scored, sa.Errors), fmt.Sprintf("%d / %d", sb.Scored, sb.Errors))
	row("precision", pr(sa.Detection), pr(sb.Detection))
	row("recall", rec(sa.Detection), rec(sb.Detection))
	row("f1", f1(sa.Detection), f1(sb.Detection))
	row("false-positive rate", fpr(sa.Detection), fpr(sb.Detection))
	row("latency p50 / p95 ms", fmt.Sprintf("%d / %d", sa.Latency.P50, sa.Latency.P95), fmt.Sprintf("%d / %d", sb.Latency.P50, sb.Latency.P95))
	row("best F1 threshold", threshold(sa.BestF1), threshold(sb.BestF1))
	row(fmt.Sprintf("best recall, fpr <= %.3f", o.MaxFPR), threshold(sa.BestRecall), threshold(sb.BestRecall))
	for _, x := range []struct {
		name string
		s    metrics.Summary
	}{{"A", sa}, {"B", sb}} {
		for _, warn := range x.s.Warnings {
			fmt.Fprintf(&buf, "warning (%s): %s\n", x.name, warn)
		}
	}
	_, err := io.WriteString(w, buf.String())
	return err
}

func threshold(p *metrics.Point) string {
	if p == nil {
		return "none"
	}
	return fmt.Sprintf("%.2f", p.Threshold)
}
