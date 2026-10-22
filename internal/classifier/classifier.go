package classifier

import (
	"context"
	"math"

	"github.com/0x4272616E646F6E/decision-waf/internal/inspect"
	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

type Verdict struct {
	Benign     float64
	Category   string
	Confidence float64
	Probs      map[string]float64
}

func (v Verdict) AttackScore() float64 { return 1 - v.Benign }

func (v Verdict) Validate() error {
	if !isProbability(v.Benign) {
		return Errorf(ReasonBadResponse, "benign probability %v is not in [0, 1]", v.Benign)
	}
	if !isProbability(v.Confidence) {
		return Errorf(ReasonBadResponse, "confidence %v is not in [0, 1]", v.Confidence)
	}
	for label, p := range v.Probs {
		if !isProbability(p) {
			return Errorf(ReasonBadResponse, "probability %v for %q is not in [0, 1]", p, label)
		}
	}
	if v.Category == policy.Benign {
		return Errorf(ReasonBadResponse, "category must name an attack, not %q", policy.Benign)
	}
	return nil
}

func isProbability(p float64) bool { return !math.IsNaN(p) && p >= 0 && p <= 1 }

type Classifier interface {
	Classify(ctx context.Context, r *inspect.Request, cats []policy.Category) (Verdict, error)
}

func Labels(cats []policy.Category) []string {
	labels := []string{policy.Benign}
	for _, c := range cats {
		labels = append(labels, c.Name)
	}
	return labels
}

var ProbeCategories = []policy.Category{{Name: "attack", Description: "Any malicious request."}}

func ProbeRequest() *inspect.Request { return &inspect.Request{Method: "GET", Path: "/"} }
