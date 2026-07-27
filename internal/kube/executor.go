package kube

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Executor is the write surface of a cluster client. HTTPClient implements it; handlers obtain
// it via a type assertion so the read-only Client interface stays unchanged. All methods are
// gated behind the action approval workflow at the proxy layer.
type Executor interface {
	Scale(ctx context.Context, kind, namespace, name string, replicas int) error
	RolloutRestart(ctx context.Context, kind, namespace, name string) error
	SetCordon(ctx context.Context, node string, unschedulable bool) error
	DeletePod(ctx context.Context, namespace, name string) error
}

type RolloutRestartMetadata struct {
	RestartedAt string
	RestartedBy string
	ActionID    string
	Reason      string
}

type DetailedRolloutExecutor interface {
	RolloutRestartWithMetadata(ctx context.Context, kind, namespace, name string, meta RolloutRestartMetadata) error
}

type RolloutRollbackExecutor interface {
	RollbackDeploymentTemplate(ctx context.Context, namespace, name string, template map[string]any, meta RolloutRestartMetadata) error
}

func workloadResourcePlural(kind string) (string, bool) {
	switch normalizeWorkloadKind(kind) {
	case "deployment":
		return "deployments", true
	case "statefulset":
		return "statefulsets", true
	case "daemonset":
		return "daemonsets", true
	}
	return "", false
}

func normalizeWorkloadKind(kind string) string {
	k := strings.ToLower(strings.TrimSpace(kind))
	k = strings.TrimPrefix(k, "apps/v1/")
	k = strings.TrimPrefix(k, "apps/v1 ")
	k = strings.TrimPrefix(k, "apps/")
	k = strings.TrimPrefix(k, "app/")
	k = strings.TrimSuffix(k, ".apps")
	k = strings.TrimSuffix(k, ".apps/v1")
	k = strings.TrimSuffix(k, "s")
	switch k {
	case "deploy", "deployment":
		return "deployment"
	case "sts", "statefulset":
		return "statefulset"
	case "ds", "daemonset":
		return "daemonset"
	default:
		return k
	}
}

func unsupportedWorkloadKindError(action, kind string) error {
	if strings.EqualFold(strings.TrimSpace(kind), "Pod") || strings.EqualFold(strings.TrimSpace(kind), "pods") {
		return fmt.Errorf("%s unsupported for kind %q: Pod는 직접 rollout restart할 수 없습니다. owner Deployment/StatefulSet/DaemonSet을 대상으로 요청하세요", action, kind)
	}
	return fmt.Errorf("%s unsupported for kind %q: supported kinds are Deployment, StatefulSet, DaemonSet", action, kind)
}

// write performs a mutating request (PATCH/DELETE) and returns an error for non-2xx responses.
func (c *HTTPClient) write(ctx context.Context, method, path, contentType string, body []byte) error {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.ServerURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("Kubernetes API %s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (c *HTTPClient) Scale(ctx context.Context, kind, namespace, name string, replicas int) error {
	plural, ok := workloadResourcePlural(kind)
	if !ok {
		return unsupportedWorkloadKindError("scale", kind)
	}
	if replicas < 0 {
		return fmt.Errorf("replicas must be >= 0")
	}
	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/%s/%s/scale", namespace, plural, name)
	body := []byte(fmt.Sprintf(`{"spec":{"replicas":%d}}`, replicas))
	return c.write(ctx, http.MethodPatch, path, "application/merge-patch+json", body)
}

func (c *HTTPClient) RolloutRestart(ctx context.Context, kind, namespace, name string) error {
	return c.RolloutRestartWithMetadata(ctx, kind, namespace, name, RolloutRestartMetadata{})
}

func (c *HTTPClient) RolloutRestartWithMetadata(ctx context.Context, kind, namespace, name string, meta RolloutRestartMetadata) error {
	plural, ok := workloadResourcePlural(kind)
	if !ok {
		return unsupportedWorkloadKindError("rollout restart", kind)
	}
	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/%s/%s", namespace, plural, name)
	ts := strings.TrimSpace(meta.RestartedAt)
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}
	annotations := map[string]string{
		"clustara.io/restartedAt":           ts,
		"kubectl.kubernetes.io/restartedAt": ts,
	}
	if v := strings.TrimSpace(meta.RestartedBy); v != "" {
		annotations["clustara.io/restartedBy"] = v
	}
	if v := strings.TrimSpace(meta.ActionID); v != "" {
		annotations["clustara.io/actionId"] = v
	}
	if v := strings.TrimSpace(meta.Reason); v != "" {
		annotations["clustara.io/reason"] = v
	}
	body, err := json.Marshal(map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"annotations": annotations}}}})
	if err != nil {
		return err
	}
	return c.write(ctx, http.MethodPatch, path, "application/strategic-merge-patch+json", body)
}

func (c *HTTPClient) RollbackDeploymentTemplate(ctx context.Context, namespace, name string, template map[string]any, meta RolloutRestartMetadata) error {
	if len(template) == 0 {
		return errors.New("rollback template is empty")
	}
	cloned, err := json.Marshal(template)
	if err != nil {
		return err
	}
	var restored map[string]any
	if err := json.Unmarshal(cloned, &restored); err != nil {
		return err
	}
	metadata, _ := restored["metadata"].(map[string]any)
	if metadata == nil {
		metadata = map[string]any{}
		restored["metadata"] = metadata
	}
	annotations, _ := metadata["annotations"].(map[string]any)
	if annotations == nil {
		annotations = map[string]any{}
		metadata["annotations"] = annotations
	}
	// Strategic merge retains unspecified map keys. Explicit nulls remove the restart trigger
	// annotations when the saved template predates this rollout.
	annotations["clustara.io/restartedAt"] = nil
	annotations["kubectl.kubernetes.io/restartedAt"] = nil
	annotations["clustara.io/rollbackAt"] = firstNonEmptyString(meta.RestartedAt, time.Now().UTC().Format(time.RFC3339))
	annotations["clustara.io/rollbackBy"] = meta.RestartedBy
	annotations["clustara.io/actionId"] = meta.ActionID
	body, err := json.Marshal(map[string]any{"spec": map[string]any{"template": restored}})
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", namespace, name)
	return c.write(ctx, http.MethodPatch, path, "application/strategic-merge-patch+json", body)
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (c *HTTPClient) SetCordon(ctx context.Context, node string, unschedulable bool) error {
	path := fmt.Sprintf("/api/v1/nodes/%s", node)
	body := []byte(fmt.Sprintf(`{"spec":{"unschedulable":%t}}`, unschedulable))
	return c.write(ctx, http.MethodPatch, path, "application/merge-patch+json", body)
}

func (c *HTTPClient) DeletePod(ctx context.Context, namespace, name string) error {
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", namespace, name)
	return c.write(ctx, http.MethodDelete, path, "", nil)
}
