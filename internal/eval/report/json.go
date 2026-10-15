package report

import (
	"encoding/json"
	"io"

	"github.com/0x4272616E646F6E/ailuros/internal/eval/metrics"
	"github.com/0x4272616E646F6E/ailuros/internal/eval/results"
)

func JSON(w io.Writer, h results.Header, s metrics.Summary) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Run     results.Header  `json:"run"`
		Summary metrics.Summary `json:"summary"`
	}{h, s})
}
