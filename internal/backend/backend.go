package backend

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/0x4272616E646F6E/decision-waf/internal/classifier"
	"github.com/0x4272616E646F6E/decision-waf/internal/classifier/jev"
	"github.com/0x4272616E646F6E/decision-waf/internal/classifier/openai"
	"github.com/0x4272616E646F6E/decision-waf/internal/config"
	"github.com/0x4272616E646F6E/decision-waf/internal/decision"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

const ProbeTimeout = 30 * time.Second

func New(cfg config.Config, log *slog.Logger) (classifier.Classifier, func(context.Context) error, error) {
	hc := classifier.NewHTTPClient()
	switch cfg.Backend {
	case config.BackendOpenAI:
		c := openai.New(cfg.BaseURL, cfg.Model, string(cfg.APIKey), hc)
		var unmatched sync.Once
		c.OnUnmatchedLogprobs = func() {
			unmatched.Do(func() {
				log.Warn("classifier logprobs do not spell the answer, so its confidence is taken as 1.0 and the attack score is exactly 0 or 1; logged once")
			})
		}
		probe := func(ctx context.Context) error {
			caps, err := c.Probe(ctx)
			if err != nil {
				return err
			}
			log.Info("classifier capabilities detected", "json_schema", caps.JSONSchema, "logprobs", caps.Logprobs)
			if caps.SchemaIgnored {
				log.Warn("classifier accepted json_schema but answered outside its labels; answers outside the label set follow AILUROS_BAD_OUTPUT")
			}
			if !caps.Logprobs {
				log.Warn("classifier does not return logprobs; every label has probability 1.0, so the attack-probability threshold acts as plain allow/block")
			}
			return nil
		}
		return c, probe, nil
	case config.BackendJev:
		c := jev.New(cfg.BaseURL, cfg.Model, string(cfg.APIKey), hc)
		return c, c.Probe, nil
	}
	return nil, nil, fmt.Errorf("unknown classifier backend %q", cfg.Backend)
}

func Engine(cfg config.Config, pol *policy.Policy, cls classifier.Classifier, breaker *classifier.Breaker, obs decision.Observer) *decision.Engine {
	return decision.NewEngine(
		classifier.NewGuard(cls, cfg.Timeout, breaker),
		pol,
		policy.Defaults{Threshold: cfg.BlockThreshold, FailureMode: cfg.FailureMode, BadOutput: cfg.BadOutput},
		obs,
	)
}
