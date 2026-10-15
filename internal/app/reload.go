package app

import (
	"context"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

const reloadDebounce = 200 * time.Millisecond

func (a *App) Reload() error {
	p, err := policy.Load(a.cfg.PolicyFile)
	if err != nil {
		a.metrics.PolicyReload(false)
		a.log.Error("policy reload failed; keeping the current policy", "file", a.cfg.PolicyFile, "error", err)
		return err
	}
	a.engine.SetPolicy(p)
	a.metrics.PolicyReload(true)
	a.log.Info("policy reloaded", "file", a.cfg.PolicyFile, "categories", len(p.Categories), "routes", len(p.Routes))
	return nil
}

func (a *App) watchPolicy(ctx context.Context) {
	hup := a.hup

	var events <-chan fsnotify.Event
	var errs <-chan error
	if a.cfg.PolicyFile != "" {
		w, err := fsnotify.NewWatcher()
		if err != nil {
			a.log.Error("cannot watch policy file; reload with SIGHUP", "error", err)
		} else {
			defer w.Close()
			if err := w.Add(filepath.Dir(a.cfg.PolicyFile)); err != nil {
				a.log.Error("cannot watch policy file; reload with SIGHUP", "error", err)
			} else {
				events, errs = w.Events, w.Errors
			}
		}
	}

	var debounce <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			_ = a.Reload()
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if base := filepath.Base(ev.Name); base != filepath.Base(a.cfg.PolicyFile) && base != "..data" {
				continue
			}
			debounce = time.After(reloadDebounce)
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			a.log.Warn("policy file watcher error", "error", err)
		case <-debounce:
			debounce = nil
			_ = a.Reload()
		}
	}
}
