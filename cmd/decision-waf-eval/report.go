package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/0x4272616E646F6E/decision-waf/internal/eval/metrics"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/report"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/results"
)

func (c cli) reportCmd(args []string) error {
	flags := newFlags("report")
	threshold := flags.Float64("threshold", 0, "threshold to report at (default: the run's)")
	maxFPR := flags.Float64("max-fpr", 0.01, "false-positive ceiling for the recall recommendation")
	byTag := flags.Bool("by-tag", false, "add metrics per tag")
	asJSON := flags.Bool("json", false, "write JSON")
	asMD := flags.Bool("markdown", false, "write Markdown")
	pos, err := parse(flags, args)
	switch {
	case err != nil:
		return err
	case len(pos) != 1:
		return usageError{errors.New("report takes one results file")}
	case *asJSON && *asMD:
		return usageError{errors.New("--json and --markdown are exclusive")}
	}
	if err := checkRates(*threshold, *maxFPR); err != nil {
		return err
	}
	f, err := readResults(pos[0])
	if err != nil {
		return err
	}
	s := metrics.Summarize(f, metrics.Options{Threshold: *threshold, MaxFPR: *maxFPR, ByTag: *byTag})
	switch {
	case *asJSON:
		return report.JSON(c.stdout, f.Header, s)
	case *asMD:
		return report.Markdown(c.stdout, f.Header, s)
	}
	return report.Text(c.stdout, f.Header, s)
}

func (c cli) compareCmd(args []string) error {
	flags := newFlags("compare")
	threshold := flags.Float64("threshold", 0, "threshold to compare at (default: A's run threshold)")
	maxFPR := flags.Float64("max-fpr", 0.01, "false-positive ceiling for the recall recommendation")
	allow := flags.Bool("allow-different-datasets", false, "compare runs over different datasets or samples")
	pos, err := parse(flags, args)
	switch {
	case err != nil:
		return err
	case len(pos) != 2:
		return usageError{errors.New("compare takes two results files")}
	}
	if err := checkRates(*threshold, *maxFPR); err != nil {
		return err
	}
	a, err := readResults(pos[0])
	if err != nil {
		return err
	}
	b, err := readResults(pos[1])
	if err != nil {
		return err
	}
	if err := report.CheckComparable(a.Header, b.Header, *allow); err != nil {
		return invalidError{err}
	}
	return report.Compare(c.stdout, a, b, metrics.Options{Threshold: *threshold, MaxFPR: *maxFPR})
}

func checkRates(threshold, maxFPR float64) error {
	if !(threshold >= 0 && threshold <= 1) {
		return usageError{fmt.Errorf("--threshold must be in (0, 1], got %v", threshold)}
	}
	if !(maxFPR >= 0 && maxFPR <= 1) {
		return usageError{fmt.Errorf("--max-fpr must be in [0, 1], got %v", maxFPR)}
	}
	return nil
}

func readResults(path string) (*results.File, error) {
	f, err := results.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return nil, invalidError{err}
	}
	if len(f.Results) == 0 {
		return nil, invalidError{fmt.Errorf("%s has no results yet", path)}
	}
	return f, nil
}
