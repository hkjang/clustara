// Package prometheus is a minimal client for the Prometheus HTTP query API, used as an external
// latency-metric source (the Kubernetes core API does not expose per-workload request latency).
package prometheus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		token:   strings.TrimSpace(token),
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// Sample is one instant-vector result: its label set and scalar value.
type Sample struct {
	Labels map[string]string
	Value  float64
}

type queryResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  []any             `json:"value"`
		} `json:"result"`
	} `json:"data"`
	Error string `json:"error"`
}

// Query runs an instant PromQL query and returns the vector result. parseVector does the
// response decoding and is unit-testable without a live Prometheus.
func (c *Client) Query(ctx context.Context, promQL string) ([]Sample, error) {
	if c.baseURL == "" {
		return nil, fmt.Errorf("prometheus URL is not configured")
	}
	endpoint := c.baseURL + "/api/v1/query?query=" + url.QueryEscape(promQL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("prometheus query returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return parseVector(body)
}

func parseVector(body []byte) ([]Sample, error) {
	var qr queryResponse
	if err := json.Unmarshal(body, &qr); err != nil {
		return nil, err
	}
	if qr.Status != "success" {
		return nil, fmt.Errorf("prometheus query failed: %s", qr.Error)
	}
	out := []Sample{}
	for _, r := range qr.Data.Result {
		if len(r.Value) != 2 {
			continue
		}
		valStr, ok := r.Value[1].(string)
		if !ok {
			continue
		}
		v, err := strconv.ParseFloat(valStr, 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			continue // unparseable / NaN / Inf → skip
		}
		out = append(out, Sample{Labels: r.Metric, Value: v})
	}
	return out, nil
}
