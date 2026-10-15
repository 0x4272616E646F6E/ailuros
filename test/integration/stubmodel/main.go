//go:build integration

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	markerFail    = "stub-fail"
	markerGarbage = "stub-garbage"
	markerOff     = "stub-offformat"
	markerSlow    = "stub-slow"
	markerAttack  = "attack"
	markerXSS     = "xss-marker"
	maxPrompts    = 10000
	largeState    = 32 << 10
	benignLabel   = "benign"
)

type question struct {
	Type     string             `json:"type"`
	Criteria map[string]*string `json:"criteria"`
}

type request struct {
	State     string              `json:"state"`
	Model     string              `json:"model"`
	Questions map[string]question `json:"questions"`
}

type answer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice"`
	Probabilities map[string]float64 `json:"probabilities"`
}

type response struct {
	Model   string            `json:"model"`
	Answers map[string]answer `json:"answers"`
}

type server struct {
	slow    time.Duration
	mu      sync.Mutex
	prompts []string
}

func newServer(slow time.Duration) *server { return &server{slow: slow} }

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/systemone", s.systemOne)
	mux.HandleFunc("GET /prompts", s.listPrompts)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	return mux
}

func (s *server) record(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prompts = append(s.prompts, state)
	if len(s.prompts) > maxPrompts {
		s.prompts = s.prompts[len(s.prompts)-maxPrompts:]
	}
}

func (s *server) systemOne(w http.ResponseWriter, r *http.Request) {
	var in request
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.record(in.State)
	switch {
	case strings.Contains(in.State, markerFail):
		http.Error(w, "stub: model unavailable", http.StatusServiceUnavailable)
		return
	case strings.Contains(in.State, markerGarbage):
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answers": {"verdict": [`))
		return
	case strings.Contains(in.State, markerSlow), len(in.State) > largeState:
		select {
		case <-time.After(s.slow):
		case <-r.Context().Done():
			return
		}
	}
	out := response{Model: in.Model, Answers: map[string]answer{}}
	for id, q := range in.Questions {
		out.Answers[id] = decide(in.State, q.Criteria)
		if strings.Contains(in.State, markerOff) {
			out.Answers[id] = answer{Type: "choice", Choice: "needs_review", Probabilities: map[string]float64{"needs_review": 1}}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func decide(state string, criteria map[string]*string) answer {
	choice := benignLabel
	switch {
	case strings.Contains(state, markerAttack):
		choice = pick(criteria, "sqli")
	case strings.Contains(state, markerXSS):
		choice = pick(criteria, "xss")
	}
	probs := make(map[string]float64, len(criteria))
	for label := range criteria {
		probs[label] = 0
	}
	if choice == benignLabel {
		probs[benignLabel] = 0.99
		if others := len(criteria) - 1; others > 0 {
			for label := range criteria {
				if label != benignLabel {
					probs[label] = 0.01 / float64(others)
				}
			}
		}
	} else {
		probs[benignLabel] = 0.01
		probs[choice] = 0.99
	}
	return answer{Type: "choice", Choice: choice, Probabilities: probs}
}

func pick(criteria map[string]*string, want string) string {
	if _, ok := criteria[want]; ok {
		return want
	}
	labels := make([]string, 0, len(criteria))
	for label := range criteria {
		if label != benignLabel {
			labels = append(labels, label)
		}
	}
	if len(labels) == 0 {
		return benignLabel
	}
	slices.Sort(labels)
	return labels[0]
}

func (s *server) listPrompts(w http.ResponseWriter, r *http.Request) {
	marker := r.URL.Query().Get("contains")
	s.mu.Lock()
	out := []string{}
	for _, p := range s.prompts {
		if strings.Contains(p, marker) {
			out = append(out, p)
		}
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func healthcheck(url string) error {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	slow := flag.Duration("slow", 3*time.Second, "delay for requests containing "+markerSlow)
	check := flag.String("healthcheck", "", "probe this URL and exit 0 if it answers 200")
	flag.Parse()
	if *check != "" {
		if err := healthcheck(*check); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
		return
	}
	log.Printf("stubmodel listening on %s", *addr)
	log.Fatal((&http.Server{Addr: *addr, Handler: newServer(*slow).handler(), ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
}
