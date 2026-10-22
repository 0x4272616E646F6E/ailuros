package app

import (
	"fmt"
	"log/slog"

	"github.com/0x4272616E646F6E/decision-waf/internal/config"
	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
)

func logStartupWarnings(log *slog.Logger, cfg config.Config) {
	if cfg.LogLevel <= slog.LevelDebug {
		log.Warn("debug logging writes redacted, truncated request bodies to logs")
	}
	if cfg.ExposeVerdict {
		log.Warn("DECISION_WAF_EXPOSE_VERDICT sends classification categories to clients; use only for testing")
	}
	if cfg.ExtProcAddr != "" && cfg.InspectionMode == inspect.ModeDeep && cfg.DeepOversize == inspect.OversizeAllow {
		log.Warn("DECISION_WAF_DEEP_OVERSIZE=allow lets request bodies and gRPC messages over DECISION_WAF_DEEP_MAX_BYTES, and gRPC messages decision-waf cannot decompress, through without classification",
			"deep_max_bytes", cfg.DeepMaxBytes)
	}
	if name, limit := bodyLimit(cfg); limit > largeBodyLimit {
		log.Warn(fmt.Sprintf("bodies up to %d bytes (%s) are sent to the classifier; prompts that large risk classifier timeouts, which follow DECISION_WAF_FAILURE_MODE", limit, name),
			"inspection_mode", cfg.InspectionMode)
	}
}

const largeBodyLimit = 32 << 10

func bodyLimit(cfg config.Config) (string, int) {
	if cfg.ExtProcAddr == "" {
		return "", 0
	}
	switch cfg.InspectionMode {
	case inspect.ModeStandard:
		return "DECISION_WAF_BODY_MAX_BYTES", cfg.BodyMaxBytes
	case inspect.ModeDeep:
		return "DECISION_WAF_DEEP_MAX_BYTES", cfg.DeepMaxBytes
	}
	return "", 0
}
