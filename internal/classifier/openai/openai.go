package openai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/0x4272616E646F6E/ailuros/internal/classifier"
	"github.com/0x4272616E646F6E/ailuros/internal/inspect"
	"github.com/0x4272616E646F6E/ailuros/internal/policy"
)

type Capabilities struct {
	JSONSchema    bool
	Logprobs      bool
	SchemaIgnored bool
}

type Client struct {
	classifier.Endpoint
	caps                atomic.Pointer[Capabilities]
	OnUnmatchedLogprobs func()
}

func New(baseURL, model, apiKey string, hc *http.Client) *Client {
	c := &Client{Endpoint: classifier.NewEndpoint(baseURL, model, apiKey, hc)}
	c.caps.Store(&Capabilities{})
	return c
}

func (c *Client) Capabilities() Capabilities { return *c.caps.Load() }

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type jsonSchema struct {
	Name   string         `json:"name"`
	Strict bool           `json:"strict"`
	Schema map[string]any `json:"schema"`
}

type responseFormat struct {
	Type       string      `json:"type"`
	JSONSchema *jsonSchema `json:"json_schema,omitempty"`
}

type chatRequest struct {
	Model          string         `json:"model"`
	Messages       []message      `json:"messages"`
	Temperature    float64        `json:"temperature"`
	ResponseFormat responseFormat `json:"response_format"`
	Logprobs       bool           `json:"logprobs,omitempty"`
}

type tokenLogprob struct {
	Token   string  `json:"token"`
	Logprob float64 `json:"logprob"`
}

type chatResponse struct {
	Error   json.RawMessage `json:"error"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Logprobs *struct {
			Content []tokenLogprob `json:"content"`
		} `json:"logprobs"`
	} `json:"choices"`
}

func (c *Client) Classify(ctx context.Context, r *inspect.Request, cats []policy.Category) (classifier.Verdict, error) {
	resp, err := c.complete(ctx, c.buildRequest(r, cats, c.Capabilities()))
	if err != nil {
		return classifier.Verdict{}, err
	}
	v, unmatched, err := parseVerdict(resp, classifier.Labels(cats))
	if unmatched && c.OnUnmatchedLogprobs != nil {
		c.OnUnmatchedLogprobs()
	}
	return v, err
}

func (c *Client) Probe(ctx context.Context) (Capabilities, error) {
	cats := classifier.ProbeCategories
	r := classifier.ProbeRequest()
	var lastErr error
	for _, try := range []Capabilities{{JSONSchema: true, Logprobs: true}, {JSONSchema: true}, {Logprobs: true}, {}} {
		resp, err := c.complete(ctx, c.buildRequest(r, cats, try))
		if err != nil {
			lastErr = err
			if formatRejected(err) {
				continue
			}
			return Capabilities{}, err
		}
		got := Capabilities{JSONSchema: try.JSONSchema, Logprobs: try.Logprobs && hasLogprobs(resp)}
		if _, _, err := parseVerdict(resp, classifier.Labels(cats)); err != nil {
			lastErr = err
			if classifier.ReasonOf(err) != classifier.ReasonBadOutput || !answeredInFormat(resp) {
				continue
			}
			got.SchemaIgnored = try.JSONSchema
		}
		c.caps.Store(&got)
		return got, nil
	}
	return Capabilities{}, fmt.Errorf("openai: no supported request format: %w", lastErr)
}

func (c *Client) buildRequest(r *inspect.Request, cats []policy.Category, caps Capabilities) chatRequest {
	req := chatRequest{
		Model: c.Model(),
		Messages: []message{
			{Role: "system", Content: classifier.Instructions + "\n\nCategories:\n" + classifier.CategoryList(cats) +
				"\nRespond with only a JSON object of the form {\"category\": \"<name>\"}."},
			{Role: "user", Content: classifier.Prompt(r)},
		},
		Temperature:    0,
		ResponseFormat: responseFormat{Type: "json_object"},
		Logprobs:       caps.Logprobs,
	}
	if caps.JSONSchema {
		req.ResponseFormat = responseFormat{Type: "json_schema", JSONSchema: &jsonSchema{
			Name:   "verdict",
			Strict: true,
			Schema: map[string]any{
				"type":                 "object",
				"properties":           map[string]any{"category": map[string]any{"type": "string", "enum": classifier.Labels(cats)}},
				"required":             []string{"category"},
				"additionalProperties": false,
			},
		}}
	}
	return req
}

func (c *Client) complete(ctx context.Context, req chatRequest) (*chatResponse, error) {
	var out chatResponse
	if err := c.Post(ctx, "/chat/completions", req, &out); err != nil {
		return nil, fmt.Errorf("openai: %w", err)
	}
	return &out, nil
}

func hasLogprobs(resp *chatResponse) bool {
	return len(resp.Choices) > 0 && resp.Choices[0].Logprobs != nil && len(resp.Choices[0].Logprobs.Content) > 0
}

func parseVerdict(resp *chatResponse, labels []string) (v classifier.Verdict, unmatched bool, err error) {
	if len(resp.Choices) == 0 {
		if msg := errorMessage(resp.Error); msg != "" {
			return classifier.Verdict{}, false, classifier.Errorf(classifier.ReasonBadResponse, "openai: server error: %s (check the base URL, which usually ends in /v1)", msg)
		}
		return classifier.Verdict{}, false, classifier.Errorf(classifier.ReasonBadResponse, "openai: response has no choices")
	}
	choice := resp.Choices[0]
	var out struct {
		Category string `json:"category"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(choice.Message.Content)), &out); err != nil {
		return classifier.Verdict{}, false, classifier.Errorf(classifier.ReasonBadOutput, "openai: output is not JSON: %v", err)
	}
	if !slices.Contains(labels, out.Category) {
		return classifier.Verdict{}, false, classifier.Errorf(classifier.ReasonBadOutput, "openai: unknown category %q", out.Category)
	}
	confidence := 1.0
	if choice.Logprobs != nil {
		if p, ok := valueProbability(choice.Message.Content, out.Category, choice.Logprobs.Content); ok {
			confidence = p
		} else {
			unmatched = len(choice.Logprobs.Content) > 0
		}
	}
	v = labelVerdict(out.Category, confidence)
	if err := v.Validate(); err != nil {
		return classifier.Verdict{}, false, fmt.Errorf("openai: %w", err)
	}
	return v, unmatched, nil
}

func labelVerdict(label string, c float64) classifier.Verdict {
	probs := map[string]float64{label: c}
	if label == policy.Benign {
		return classifier.Verdict{Benign: c, Probs: probs}
	}
	return classifier.Verdict{Benign: 1 - c, Category: label, Confidence: c, Probs: probs}
}

func valueProbability(content, value string, tokens []tokenLogprob) (float64, bool) {
	const key = `"category"`
	k := strings.Index(content, key)
	if k < 0 {
		return 0, false
	}
	rel := strings.Index(content[k+len(key):], `"`+value+`"`)
	if rel < 0 {
		return 0, false
	}
	start := k + len(key) + rel + 1
	end := start + len(value)

	var sum float64
	pos, found := 0, false
	for _, t := range tokens {
		tStart, tEnd := pos, pos+len(t.Token)
		pos = tEnd
		if tEnd > start && tStart < end {
			sum += t.Logprob
			found = true
		}
	}
	if !found || pos != len(content) {
		return 0, false
	}
	return math.Exp(sum), true
}

func errorMessage(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &o) == nil && o.Message != "" {
		return o.Message
	}
	return string(raw)
}

func formatRejected(err error) bool {
	var e *classifier.Error
	if !errors.As(err, &e) {
		return false
	}
	switch e.Status {
	case http.StatusBadRequest, http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
		return true
	}
	return false
}

func answeredInFormat(resp *chatResponse) bool {
	if len(resp.Choices) == 0 {
		return false
	}
	var out struct {
		Category *string `json:"category"`
	}
	return json.Unmarshal([]byte(strings.TrimSpace(resp.Choices[0].Message.Content)), &out) == nil && out.Category != nil
}
