package main

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/0x4272616E646F6E/decision-waf/internal/backend"
	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/config"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/dataset"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/metrics"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/results"
	"github.com/0x4272616E646F6E/decision-waf/internal/eval/run"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
	"github.com/0x4272616E646F6E/decision-waf/internal/version"
)

func (c cli) runCmd(ctx context.Context, args []string) (err error) {
	flags := newFlags("run")
	dsPath := flags.String("dataset", "", "labelled dataset (JSON Lines)")
	out := flags.String("out", "", "results file")
	sample := flags.Int("sample", 0, "evaluate a stratified random sample of N requests")
	seed := flags.Uint64("seed", 1, "sampling seed")
	concurrency := flags.Int("concurrency", 1, "requests in flight at once")
	resume := flags.Bool("resume", false, "continue an interrupted results file")
	pos, err := parse(flags, args)
	switch {
	case err != nil:
		return err
	case len(pos) > 0:
		return usageError{fmt.Errorf("run takes no arguments, got %q", pos)}
	case *dsPath == "":
		return usageError{errors.New("--dataset is required")}
	case *sample < 0:
		return usageError{errors.New("--sample must not be negative")}
	case *concurrency < 1:
		return usageError{errors.New("--concurrency must be at least 1")}
	}

	if err := config.CheckRenamed(c.environ()); err != nil {
		return invalidError{fmt.Errorf("invalid configuration:\n%w", err)}
	}
	cfg, err := config.Load(c.lookup, c.readFile)
	if err != nil {
		return invalidError{fmt.Errorf("invalid configuration:\n%w", err)}
	}
	pol, policySHA := policy.Default(), ""
	if cfg.PolicyFile != "" {
		raw, err := c.readFile(cfg.PolicyFile)
		if err != nil {
			return invalidError{fmt.Errorf("policy: %w", err)}
		}
		if pol, err = policy.Parse(raw); err != nil {
			return invalidError{err}
		}
		policySHA = fmt.Sprintf("%x", sha256.Sum256(raw))
	}
	ds, err := dataset.LoadFile(*dsPath, classifier.Labels(pol.Categories))
	if err != nil {
		return invalidError{err}
	}
	entries := run.Sample(ds.Entries, *sample, *seed)
	h := results.Header{
		Version: results.Version,
		Dataset: results.DatasetInfo{Path: *dsPath, Name: ds.Header.Name, Description: ds.Header.Description, SHA256: ds.SHA256, Entries: len(ds.Entries)},
		Backend: cfg.Backend, BaseURL: withoutUserinfo(cfg.BaseURL), Model: cfg.Model, TimeoutMS: cfg.Timeout.Milliseconds(),
		Threshold: cfg.BlockThreshold,
		Policy:    cmp.Or(cfg.PolicyFile, "default"), PolicySHA256: policySHA, BodyMaxBytes: cfg.BodyMaxBytes,
		PromptVersion:      classifier.PromptVersion,
		DecisionWafVersion: version.Version, Started: c.now().UTC(),
	}
	if len(entries) < len(ds.Entries) {
		h.Sample, h.Seed = len(entries), *seed
	}
	path := cmp.Or(*out, defaultOut(*dsPath, cfg.Model))

	existing, err := checkResults(path, h, *resume)
	if err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(c.stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cls, probe, err := c.backend(cfg, log)
	if err != nil {
		return invalidError{err}
	}
	pctx, cancel := context.WithTimeout(ctx, backend.ProbeTimeout)
	err = probe(pctx)
	cancel()
	if err != nil {
		return fmt.Errorf("classifier %s at %s is not ready: %w", cfg.Model, withoutUserinfo(cfg.BaseURL), err)
	}

	w, done, closeFile, err := openResults(path, h, existing)
	if err != nil {
		return err
	}
	closeFile = sync.OnceValue(closeFile)
	defer func() {
		if cerr := closeFile(); err == nil {
			err = cerr
		}
	}()
	todo := 0
	for _, e := range entries {
		if !done[e.ID] {
			todo++
		}
	}
	fmt.Fprintf(c.stderr, "evaluating %d of %d requests with %s model %s; results in %s\n", todo, len(entries), cfg.Backend, cfg.Model, path)
	var mu sync.Mutex
	n := 0
	progress := func() {
		mu.Lock()
		defer mu.Unlock()
		if n++; n%10 == 0 || n == todo {
			fmt.Fprintf(c.stderr, "  %d/%d\n", n, todo)
		}
	}
	eng := backend.Engine(cfg, pol, cls, run.NewBreaker(), nil)
	if err := run.Run(ctx, eng, entries, done, cfg.BodyMaxBytes, *concurrency, w, progress); err != nil {
		if errors.Is(err, context.Canceled) {
			return interruptedError{path: path, err: err}
		}
		return err
	}
	if err := closeFile(); err != nil {
		return err
	}
	if rf, err := results.ReadFile(path); err == nil {
		if s := metrics.Summarize(rf, metrics.Options{}); s.Errors > 0 {
			fmt.Fprintf(c.stderr, "%d of %d requests failed (%s); see decision-waf-eval report\n", s.Errors, s.Total, metrics.Reasons(s.ErrorsByReason))
		}
	}
	_, err = fmt.Fprintln(c.stdout, path)
	return err
}

type interruptedError struct {
	path string
	err  error
}

func (e interruptedError) Error() string { return e.err.Error() }
func (e interruptedError) Unwrap() error { return e.err }

func checkResults(path string, h results.Header, resume bool) (existing *results.File, err error) {
	existing, err = results.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case err != nil && !resume:
		return nil, invalidError{fmt.Errorf("%s already exists and is not a results file; choose another --out", path)}
	case err != nil:
		return nil, invalidError{err}
	case !resume:
		return nil, invalidError{fmt.Errorf("%s already exists; pass --resume to continue it or choose another --out", path)}
	case !existing.Header.SameRun(h):
		return nil, invalidError{fmt.Errorf("%s was produced by a different run (dataset, backend, model server, model, classifier timeout, threshold, policy, body limit, prompt version, sample, seed, or decision-waf version differ); choose another --out", path)}
	}
	return existing, nil
}

func openResults(path string, h results.Header, existing *results.File) (*results.Writer, map[string]bool, func() error, error) {
	if existing == nil {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, nil, nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the path is the results file the user named
		if err != nil {
			return nil, nil, nil, err
		}
		w, err := results.NewWriter(f, h)
		if err != nil {
			f.Close()
			return nil, nil, nil, err
		}
		return w, nil, f.Close, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // G304: the path is the results file the user named
	if err != nil {
		return nil, nil, nil, err
	}
	if err := f.Truncate(existing.Complete); err != nil {
		f.Close()
		return nil, nil, nil, err
	}
	if _, err := f.Seek(existing.Complete, io.SeekStart); err != nil {
		f.Close()
		return nil, nil, nil, err
	}
	done := make(map[string]bool, len(existing.Results))
	for _, r := range existing.Results {
		done[r.ID] = true
	}
	return results.AppendWriter(f), done, f.Close, nil
}

func defaultOut(datasetPath, model string) string {
	clean := func(s string) string {
		return strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
				return r
			}
			return '_'
		}, s)
	}
	name := strings.TrimSuffix(filepath.Base(datasetPath), filepath.Ext(datasetPath))
	return filepath.Join("bin", "eval", clean(name)+"-"+clean(model)+".jsonl")
}

func withoutUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}
