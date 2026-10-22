//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/0x4272616E646F6E/decision-waf/internal/eval/results"
)

func TestEvalAgainstStub(t *testing.T) {
	c := &composeEnvironment{project: "ailuros-it-eval", files: []string{filepath.Join(composeDir, "common.yaml")}, vars: composeEnv(nil)}
	startProject(t, newStack("eval", c, proxy{}), c, "stubmodel")
	stub := "http://" + c.port(t, "stubmodel", stubPort)

	bin := filepath.Join(t.TempDir(), "ailuros-eval")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/decision-waf-eval").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	resultsPath := filepath.Join(t.TempDir(), "results.jsonl")
	run := exec.Command(bin, "run", "--dataset", samplePath, "--out", resultsPath, "--concurrency", "4")
	run.Env = append(composeEnv(nil),
		"AILUROS_CLASSIFIER_BACKEND=jev", "AILUROS_CLASSIFIER_BASE_URL="+stub,
		"AILUROS_CLASSIFIER_MODEL=stub", "AILUROS_CLASSIFIER_TIMEOUT=5s")
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("ailuros-eval run: %v\n%s", err, out)
	}

	f, err := results.ReadFile(resultsPath)
	if err != nil {
		t.Fatal(err)
	}
	sample := loadSample(t)
	if len(f.Results) != len(sample.Entries) || f.Header.Dataset.SHA256 != sample.SHA256 {
		t.Fatalf("%d results for %d entries (dataset sha %s vs %s)", len(f.Results), len(sample.Entries), f.Header.Dataset.SHA256, sample.SHA256)
	}
	for _, r := range f.Results {
		if r.AttackScore == nil || r.Error != "" {
			t.Errorf("%s: score %v error %q, want a score and no error", r.ID, r.AttackScore, r.Error)
		}
	}
	var prompts []string
	hc := &http.Client{Timeout: 5 * time.Second}
	if err := getJSON(hc, stub+"/prompts?contains=shop.example.com", &prompts); err != nil {
		t.Fatal(err)
	}
	if len(prompts) != len(sample.Entries) {
		t.Errorf("stub received %d prompts, want %d", len(prompts), len(sample.Entries))
	}

	rep, err := exec.Command(bin, "report", resultsPath, "--json").Output()
	if err != nil {
		t.Fatalf("ailuros-eval report: %v", err)
	}
	var got struct {
		Summary struct{ Total, Errors int }
	}
	if err := json.Unmarshal(rep, &got); err != nil || got.Summary.Total != len(sample.Entries) || got.Summary.Errors != 0 {
		t.Errorf("report: %+v err %v\n%s", got.Summary, err, rep)
	}
}
