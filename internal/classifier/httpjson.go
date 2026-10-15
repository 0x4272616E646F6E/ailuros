package classifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	maxResponseBytes = 1 << 20
	drainBytes       = 64 << 10
	idleConnsPerHost = 64
)

func NewHTTPClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 2 * idleConnsPerHost
	t.MaxIdleConnsPerHost = idleConnsPerHost
	return &http.Client{
		Transport:     t,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func PostJSON(ctx context.Context, hc *http.Client, url, apiKey string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return &Error{Reason: ReasonInternal, Err: fmt.Errorf("encode request: %w", err)}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainBytes))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if loc := resp.Header.Get("Location"); resp.StatusCode/100 == 3 && loc != "" {
			return &Error{Reason: StatusReason(resp.StatusCode), Status: resp.StatusCode, Err: fmt.Errorf("HTTP %d redirect to %s, not followed; set the base URL to the final address", resp.StatusCode, loc)}
		}
		return &Error{Reason: StatusReason(resp.StatusCode), Status: resp.StatusCode, Err: fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(msg))}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return &Error{Reason: ReasonBadResponse, Err: fmt.Errorf("decode response: %w", err)}
	}
	return nil
}

type Endpoint struct {
	baseURL string
	model   string
	apiKey  string
	http    *http.Client
}

func NewEndpoint(baseURL, model, apiKey string, hc *http.Client) Endpoint {
	if hc == nil {
		hc = http.DefaultClient
	}
	return Endpoint{baseURL: strings.TrimRight(baseURL, "/"), model: model, apiKey: apiKey, http: hc}
}

func (e Endpoint) Model() string { return e.model }

func (e Endpoint) Post(ctx context.Context, path string, in, out any) error {
	return PostJSON(ctx, e.http, e.baseURL+path, e.apiKey, in, out)
}
