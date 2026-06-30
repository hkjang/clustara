package kube

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// StackApplier is the server-side-apply write surface used by Application Stack deploys. It is kept
// separate from Executor so the read-only Client and the action Executor interfaces stay unchanged;
// handlers obtain it via a type assertion. Apply uses Kubernetes Server-Side Apply (SSA), which is
// declarative and idempotent — re-applying the same manifest is a no-op.
type StackApplier interface {
	Apply(ctx context.Context, apiVersion, kind, namespace, name string, manifestYAML []byte, dryRun bool) error
}

// Apply performs a Server-Side Apply (SSA) of one manifest document. fieldManager identifies
// Clustara as the owner; force=true resolves field-ownership conflicts in Clustara's favour. When
// dryRun is set the API server validates and merges without persisting (dryRun=All).
func (c *HTTPClient) Apply(ctx context.Context, apiVersion, kind, namespace, name string, manifestYAML []byte, dryRun bool) error {
	path, err := apiResourcePath(apiVersion, kind, namespace, name)
	if err != nil {
		return err
	}
	q := url.Values{}
	q.Set("fieldManager", "clustara")
	q.Set("force", "true")
	if dryRun {
		q.Set("dryRun", "All")
	}
	return c.write(ctx, http.MethodPatch, path+"?"+q.Encode(), "application/apply-patch+yaml", manifestYAML)
}

// clusterScopedKinds are not namespaced; their REST path omits /namespaces/{ns}.
var clusterScopedKinds = map[string]bool{
	"Namespace":                true,
	"Node":                     true,
	"PersistentVolume":         true,
	"ClusterRole":              true,
	"ClusterRoleBinding":       true,
	"StorageClass":             true,
	"CustomResourceDefinition": true,
	"PriorityClass":            true,
	"ClusterIssuer":            true,
}

// apiResourcePath builds the Kubernetes REST path for a resource from its apiVersion + kind. Core
// group ("v1") uses /api/{version}; grouped resources use /apis/{group}/{version}. Cluster-scoped
// kinds omit the namespace segment. The name is appended for SSA (PATCH on the named resource).
func apiResourcePath(apiVersion, kind, namespace, name string) (string, error) {
	apiVersion = strings.TrimSpace(apiVersion)
	kind = strings.TrimSpace(kind)
	name = strings.TrimSpace(name)
	if apiVersion == "" || kind == "" || name == "" {
		return "", fmt.Errorf("apiVersion, kind and name are required (got %q/%q/%q)", apiVersion, kind, name)
	}
	var base string
	if strings.Contains(apiVersion, "/") {
		parts := strings.SplitN(apiVersion, "/", 2)
		base = fmt.Sprintf("/apis/%s/%s", parts[0], parts[1])
	} else {
		base = fmt.Sprintf("/api/%s", apiVersion)
	}
	plural := pluralizeKind(kind)
	if clusterScopedKinds[kind] {
		return fmt.Sprintf("%s/%s/%s", base, plural, name), nil
	}
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		ns = "default"
	}
	return fmt.Sprintf("%s/namespaces/%s/%s/%s", base, ns, plural, name), nil
}

// pluralizeKind lowercases a Kind and pluralizes it following the conventional Kubernetes rules used
// by the API discovery for built-in resources (Ingress→ingresses, NetworkPolicy→networkpolicies,
// Gateway→gateways, etc.). Covers the common built-ins; unusual CRDs may need explicit mapping.
func pluralizeKind(kind string) string {
	lower := strings.ToLower(kind)
	// Irregulars / already-plural built-ins.
	switch lower {
	case "endpoints":
		return "endpoints"
	case "networkpolicy":
		return "networkpolicies"
	case "podsecuritypolicy":
		return "podsecuritypolicies"
	case "priorityclass":
		return "priorityclasses"
	case "storageclass":
		return "storageclasses"
	case "ingressclass":
		return "ingressclasses"
	}
	switch {
	case strings.HasSuffix(lower, "s"), strings.HasSuffix(lower, "x"),
		strings.HasSuffix(lower, "ch"), strings.HasSuffix(lower, "sh"):
		return lower + "es"
	case strings.HasSuffix(lower, "y") && !endsInVowelY(lower):
		return strings.TrimSuffix(lower, "y") + "ies"
	default:
		return lower + "s"
	}
}

func endsInVowelY(s string) bool {
	if len(s) < 2 {
		return false
	}
	switch s[len(s)-2] {
	case 'a', 'e', 'i', 'o', 'u':
		return true
	}
	return false
}
