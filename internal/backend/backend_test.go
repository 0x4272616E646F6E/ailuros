package backend

import (
	"io"
	"log/slog"
	"testing"

	"github.com/0x4272616E646F6E/decision-waf/internal/config"
)

func TestNew(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, b := range []string{config.BackendJev, config.BackendOpenAI} {
		cls, probe, err := New(config.Config{Backend: b, BaseURL: "http://127.0.0.1:1", Model: "m"}, log)
		if err != nil || cls == nil || probe == nil {
			t.Errorf("%s: New = %v, probe set %v, err %v", b, cls, probe != nil, err)
		}
	}
	if _, _, err := New(config.Config{Backend: "nope"}, log); err == nil {
		t.Error("unknown backend: want an error")
	}
}
