package results

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/0x4272616E646F6E/ailuros/internal/eval/strictjson"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

const Version = 1

type DatasetInfo struct {
	Path        string `json:"path"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	SHA256      string `json:"sha256"`
	Entries     int    `json:"entries"`
}

type Header struct {
	Version        int         `json:"ailuros_eval_results"`
	Dataset        DatasetInfo `json:"dataset"`
	Backend        string      `json:"backend"`
	BaseURL        string      `json:"base_url,omitempty"`
	Model          string      `json:"model"`
	TimeoutMS      int64       `json:"timeout_ms,omitempty"`
	Threshold      float64     `json:"threshold"`
	Policy         string      `json:"policy"`
	PolicySHA256   string      `json:"policy_sha256,omitempty"`
	BodyMaxBytes   int         `json:"body_max_bytes"`
	PromptVersion  int         `json:"prompt_version,omitempty"`
	Sample         int         `json:"sample,omitempty"`
	Seed           uint64      `json:"seed,omitempty"`
	AilurosVersion string      `json:"ailuros_version"`
	Started        time.Time   `json:"started"`
}

func (h Header) SameRun(o Header) bool {
	h.Started, o.Started = time.Time{}, time.Time{}
	h.Dataset.Path, o.Dataset.Path = "", ""
	return h == o
}

type Result struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Tags        []string `json:"tags,omitempty"`
	AttackScore *float64 `json:"attack_score,omitempty"`
	Category    string   `json:"category,omitempty"`
	Limit       string   `json:"limit,omitempty"`
	Outcome     string   `json:"outcome"`
	Error       string   `json:"error,omitempty"`
	LatencyMS   int64    `json:"latency_ms"`
}

func (r Result) Attack() bool { return r.Label != policy.Benign }
func (r Result) Failed() bool { return r.AttackScore == nil }

type File struct {
	Header   Header
	Results  []Result
	Complete int64
}

func ReadFile(path string) (*File, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is the results file the user named
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rf, err := Read(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rf, nil
}

func Read(r io.Reader) (*File, error) {
	br := bufio.NewReader(r)
	var f File
	header := false
	seen := map[string]int{}
	for n := 1; ; n++ {
		line, err := br.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		f.Complete += int64(len(line))
		text := bytes.TrimSpace(line)
		if len(text) == 0 {
			continue
		}
		if !header {
			header = true
			if err := strictjson.Decode(text, &f.Header); err != nil {
				return nil, fmt.Errorf("line %d: header: %w", n, err)
			}
			if f.Header.Version != Version {
				return nil, fmt.Errorf("line %d: unsupported results version %d (want %d)", n, f.Header.Version, Version)
			}
			continue
		}
		var res Result
		if err := strictjson.Decode(text, &res); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		if res.ID == "" {
			return nil, fmt.Errorf("line %d: missing id", n)
		}
		if first, dup := seen[res.ID]; dup {
			return nil, fmt.Errorf("line %d: duplicate id %q (first on line %d)", n, res.ID, first)
		}
		seen[res.ID] = n
		f.Results = append(f.Results, res)
	}
	if !header {
		return nil, errors.New("not a results file: no header line")
	}
	return &f, nil
}

type Writer struct {
	mu  sync.Mutex
	w   io.Writer
	err error
}

func NewWriter(w io.Writer, h Header) (*Writer, error) {
	h.Version = Version
	b, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	return &Writer{w: w}, nil
}

func AppendWriter(w io.Writer) *Writer { return &Writer{w: w} }

func (w *Writer) Write(r Result) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	if _, err := w.w.Write(append(b, '\n')); err != nil {
		w.err = err
		return err
	}
	return nil
}
