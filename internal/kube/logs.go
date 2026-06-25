package kube

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// PodLogOptions mirrors the safe, read-only kubectl logs options exposed by Clustara.
type PodLogOptions struct {
	Container    string
	Previous     bool
	Follow       bool
	TailLines    int
	SinceSeconds int
	SinceTime    string
	Timestamps   bool
	LimitBytes   int
}

// PodLogs reads a Pod's log subresource from the Kubernetes API server.
func (c *HTTPClient) PodLogs(ctx context.Context, namespace, pod string, opts PodLogOptions) (string, error) {
	req, path, err := c.podLogRequest(ctx, namespace, pod, opts)
	if err != nil {
		return "", err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("Kubernetes API GET %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxLogResponseBytes(opts.LimitBytes))))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// PodLogsStream follows a Pod log stream. The caller must close the returned body.
func (c *HTTPClient) PodLogsStream(ctx context.Context, namespace, pod string, opts PodLogOptions) (io.ReadCloser, error) {
	opts.Follow = true
	req, path, err := c.podLogRequest(ctx, namespace, pod, opts)
	if err != nil {
		return nil, err
	}
	streamClient := *c.client
	streamClient.Timeout = 0
	resp, err := streamClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("Kubernetes API GET %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return resp.Body, nil
}

func (c *HTTPClient) podLogRequest(ctx context.Context, namespace, pod string, opts PodLogOptions) (*http.Request, string, error) {
	namespace = strings.TrimSpace(namespace)
	pod = strings.TrimSpace(pod)
	if namespace == "" || pod == "" {
		return nil, "", fmt.Errorf("namespace and pod are required")
	}
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(pod) + "/log"
	u, err := url.Parse(c.cfg.ServerURL + path)
	if err != nil {
		return nil, "", err
	}
	q := u.Query()
	if opts.Container != "" {
		q.Set("container", strings.TrimSpace(opts.Container))
	}
	if opts.Previous {
		q.Set("previous", "true")
	}
	if opts.Follow {
		q.Set("follow", "true")
	}
	if opts.TailLines > 0 {
		q.Set("tailLines", strconv.Itoa(opts.TailLines))
	}
	if opts.SinceSeconds > 0 {
		q.Set("sinceSeconds", strconv.Itoa(opts.SinceSeconds))
	}
	if opts.SinceTime != "" {
		q.Set("sinceTime", strings.TrimSpace(opts.SinceTime))
	}
	if opts.Timestamps {
		q.Set("timestamps", "true")
	}
	if opts.LimitBytes > 0 {
		q.Set("limitBytes", strconv.Itoa(opts.LimitBytes))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	return req, path, nil
}

func maxLogResponseBytes(limitBytes int) int {
	if limitBytes > 0 && limitBytes < 10*1024*1024 {
		return limitBytes + 1
	}
	return 10 * 1024 * 1024
}
