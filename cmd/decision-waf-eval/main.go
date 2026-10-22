package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0x4272616E646F6E/decision-waf/internal/backend"
	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/config"
)

const usage = `usage:
  decision-waf-eval run     --dataset FILE [--out FILE] [--sample N] [--seed 1] [--concurrency 1] [--resume]
  decision-waf-eval report  RESULTS [--threshold T] [--max-fpr 0.01] [--by-tag] [--json|--markdown]
  decision-waf-eval compare A B [--threshold T] [--max-fpr 0.01] [--allow-different-datasets]

run reads the classifier settings from the same DECISION_WAF_* variables as decision-waf:
DECISION_WAF_CLASSIFIER_BACKEND, _BASE_URL, _MODEL, _API_KEY (or _API_KEY_FILE),
_TIMEOUT, DECISION_WAF_POLICY_FILE, DECISION_WAF_BLOCK_THRESHOLD, DECISION_WAF_BODY_MAX_BYTES.
Results default to bin/eval/<dataset>-<model>.jsonl.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli{
		stdout: os.Stdout, stderr: os.Stderr,
		lookup: os.LookupEnv, environ: os.Environ, readFile: os.ReadFile,
		backend: backend.New, now: time.Now,
	}.main(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

type backendFunc func(config.Config, *slog.Logger) (classifier.Classifier, func(context.Context) error, error)

type cli struct {
	stdout, stderr io.Writer
	lookup         func(string) (string, bool)
	environ        func() []string
	readFile       func(string) ([]byte, error)
	backend        backendFunc
	now            func() time.Time
}

type usageError struct{ error }

type invalidError struct{ error }

func (c cli) main(ctx context.Context, args []string) int {
	err := c.dispatch(ctx, args)
	var ue usageError
	var ie invalidError
	var inter interruptedError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ue):
		fmt.Fprintf(c.stderr, "decision-waf-eval: %v\n\n%s", err, usage)
		return 2
	case errors.As(err, &ie):
		fmt.Fprintf(c.stderr, "decision-waf-eval: %v\n", err)
		return 2
	case errors.As(err, &inter):
		fmt.Fprintf(c.stderr, "decision-waf-eval: interrupted; rerun with --resume --out %s to continue\n", inter.path)
		return 1
	case errors.Is(err, context.Canceled):
		fmt.Fprintln(c.stderr, "decision-waf-eval: interrupted")
		return 1
	default:
		fmt.Fprintf(c.stderr, "decision-waf-eval: %v\n", err)
		return 1
	}
}

func (c cli) dispatch(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError{errors.New("missing command")}
	}
	switch args[0] {
	case "run":
		return c.runCmd(ctx, args[1:])
	case "report":
		return c.reportCmd(args[1:])
	case "compare":
		return c.compareCmd(args[1:])
	case "help", "-h", "--help":
		_, err := io.WriteString(c.stdout, usage)
		return err
	}
	return usageError{fmt.Errorf("unknown command %q", args[0])}
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, usageError{err}
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}
