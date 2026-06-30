package kube

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Discoverer is an optional capability for fetching raw Kubernetes discovery + OpenAPI documents.
// Implemented by *HTTPClient. Callers parse the bytes (see analyzer.ParseAggregatedDiscovery /
// ParseOpenAPIV3Root) — keeping this layer a thin transport.
type Discoverer interface {
	// RawGet fetches a path with the given Accept header (empty → application/json) and returns the
	// response body. Used for aggregated discovery (/apis, /api) and /openapi/v3 documents.
	RawGet(ctx context.Context, path, accept string) ([]byte, error)
}

// AggregatedDiscoveryAccept requests the aggregated discovery v2 representation, which returns the
// whole cluster's resource catalog in a single response (APIGroupDiscoveryList).
const AggregatedDiscoveryAccept = "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList,application/json"

// RawGet implements Discoverer.
func (c *HTTPClient) RawGet(ctx context.Context, path, accept string) ([]byte, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if accept == "" {
		accept = "application/json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.ServerURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // cap at 32MB (OpenAPI docs can be large)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := body
		if len(snippet) > 2048 {
			snippet = snippet[:2048]
		}
		return nil, fmt.Errorf("Kubernetes API %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return body, nil
}
