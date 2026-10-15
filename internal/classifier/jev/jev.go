package jev

import (
	"context"
	"fmt"
	"net/http"

	"github.com/0x4272616E646F6E/ailuros/internal/classifier"
	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

const questionID = "verdict"

type Client struct {
	classifier.Endpoint
}

func New(baseURL, model, apiKey string, hc *http.Client) *Client {
	return &Client{classifier.NewEndpoint(baseURL, model, apiKey, hc)}
}

type question struct {
	Type         string             `json:"type"`
	Instructions string             `json:"instructions"`
	Criteria     map[string]*string `json:"criteria"`
}

type request struct {
	State     string              `json:"state"`
	Model     string              `json:"model"`
	Questions map[string]question `json:"questions"`
}

type choiceAnswer struct {
	Choice        string             `json:"choice"`
	Probabilities map[string]float64 `json:"probabilities"`
}

type response struct {
	Answers map[string]choiceAnswer `json:"answers"`
}

func (c *Client) Classify(ctx context.Context, r *inspect.Request, cats []policy.Category) (classifier.Verdict, error) {
	benign := classifier.BenignDescription
	criteria := map[string]*string{policy.Benign: &benign}
	for _, cat := range cats {
		if cat.Description == "" {
			criteria[cat.Name] = nil
		} else {
			d := cat.Description
			criteria[cat.Name] = &d
		}
	}
	in := request{
		State: classifier.Prompt(r),
		Model: c.Model(),
		Questions: map[string]question{
			questionID: {Type: "choice", Instructions: classifier.Instructions, Criteria: criteria},
		},
	}
	var out response
	if err := c.Post(ctx, "/v1/systemone", in, &out); err != nil {
		return classifier.Verdict{}, fmt.Errorf("jev: %w", err)
	}

	ans, ok := out.Answers[questionID]
	if !ok {
		return classifier.Verdict{}, classifier.Errorf(classifier.ReasonBadResponse, "jev: response has no %q answer", questionID)
	}
	if _, known := criteria[ans.Choice]; !known {
		return classifier.Verdict{}, classifier.Errorf(classifier.ReasonBadOutput, "jev: unknown choice %q", ans.Choice)
	}
	v, err := verdictFrom(ans.Probabilities, cats)
	if err != nil {
		return classifier.Verdict{}, fmt.Errorf("jev: %w", err)
	}
	return v, nil
}

func verdictFrom(probs map[string]float64, cats []policy.Category) (classifier.Verdict, error) {
	benign, ok := probs[policy.Benign]
	if !ok {
		return classifier.Verdict{}, classifier.Errorf(classifier.ReasonBadResponse, "no probability for %q", policy.Benign)
	}
	v := classifier.Verdict{Benign: benign, Probs: probs}
	for _, c := range cats {
		if p, ok := probs[c.Name]; ok && (v.Category == "" || p > v.Confidence) {
			v.Category, v.Confidence = c.Name, p
		}
	}
	if err := v.Validate(); err != nil {
		return classifier.Verdict{}, err
	}
	return v, nil
}

func (c *Client) Probe(ctx context.Context) error {
	_, err := c.Classify(ctx, classifier.ProbeRequest(), classifier.ProbeCategories)
	return err
}
