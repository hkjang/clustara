package kube

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"clustara/internal/store"
)

type Client interface {
	Probe(ctx context.Context) (ProbeResult, error)
	Collect(ctx context.Context) (CollectResult, error)
}

type ProbeResult struct {
	OK                bool   `json:"ok"`
	ServerURL         string `json:"server_url"`
	KubernetesVersion string `json:"kubernetes_version"`
	NodeCount         int    `json:"node_count"`
	NamespaceCount    int    `json:"namespace_count"`
	Message           string `json:"message"`
}

type CollectResult struct {
	Resources     []store.K8sInventoryItem `json:"resources"`
	Events        []store.K8sEvent         `json:"events"`
	Metrics       []store.K8sMetricSample  `json:"metrics"`
	FullSyncKinds []string                 `json:"full_sync_kinds,omitempty"`
}

type HTTPClientConfig struct {
	ServerURL     string
	Token         string
	CACertPEM     []byte
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	InsecureTLS   bool
	Timeout       time.Duration
	UserAgent     string
}

type HTTPClient struct {
	cfg    HTTPClientConfig
	client *http.Client
}

func NewClient(cluster store.K8sCluster, credentialKind string, credentialPayload string) (Client, error) {
	cfg, err := clientConfigFromCredential(cluster, credentialKind, credentialPayload)
	if err != nil {
		return nil, err
	}
	return NewHTTPClient(cfg)
}

func NewHTTPClient(cfg HTTPClientConfig) (*HTTPClient, error) {
	cfg.ServerURL = strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("Kubernetes API server URL is empty")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "clustara-k8s-ops"
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.InsecureTLS {
		tlsConf.InsecureSkipVerify = true //nolint:gosec // kubeconfig may explicitly request this for private clusters.
	}
	if len(cfg.CACertPEM) > 0 {
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(cfg.CACertPEM); !ok {
			return nil, fmt.Errorf("invalid certificate-authority-data")
		}
		tlsConf.RootCAs = pool
	}
	if len(cfg.ClientCertPEM) > 0 || len(cfg.ClientKeyPEM) > 0 {
		cert, err := tls.X509KeyPair(cfg.ClientCertPEM, cfg.ClientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("invalid client certificate/key: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConf
	return &HTTPClient{cfg: cfg, client: &http.Client{Timeout: cfg.Timeout, Transport: transport}}, nil
}

func (c *HTTPClient) Probe(ctx context.Context) (ProbeResult, error) {
	version, err := c.version(ctx)
	if err != nil {
		return ProbeResult{OK: false, ServerURL: c.cfg.ServerURL, Message: err.Error()}, err
	}
	namespaces, nsErr := c.list(ctx, "/api/v1/namespaces")
	if nsErr != nil {
		return ProbeResult{OK: false, ServerURL: c.cfg.ServerURL, KubernetesVersion: version, Message: nsErr.Error()}, nsErr
	}
	nodes, nodeErr := c.list(ctx, "/api/v1/nodes")
	if nodeErr != nil {
		return ProbeResult{OK: false, ServerURL: c.cfg.ServerURL, KubernetesVersion: version, NamespaceCount: len(namespaces), Message: nodeErr.Error()}, nodeErr
	}
	return ProbeResult{
		OK:                true,
		ServerURL:         c.cfg.ServerURL,
		KubernetesVersion: version,
		NamespaceCount:    len(namespaces),
		NodeCount:         len(nodes),
		Message:           "Kubernetes API 연결 테스트 성공",
	}, nil
}

func (c *HTTPClient) Collect(ctx context.Context) (CollectResult, error) {
	out := CollectResult{Resources: []store.K8sInventoryItem{}, Events: []store.K8sEvent{}, Metrics: []store.K8sMetricSample{}}
	for _, target := range DefaultInventoryTargets() {
		items, err := c.list(ctx, target.Path)
		if err != nil {
			if target.Optional || isOptionalAPI(target.Path) {
				continue
			}
			return out, err
		}
		out.FullSyncKinds = append(out.FullSyncKinds, target.Kind)
		for _, obj := range items {
			out.Resources = append(out.Resources, inventoryFromObject(target.Kind, target.APIVersion, obj))
		}
	}
	events, err := c.list(ctx, "/api/v1/events")
	if err == nil {
		for _, obj := range events {
			out.Events = append(out.Events, eventFromObject(obj))
		}
	}
	if podMetrics, err := c.list(ctx, "/apis/metrics.k8s.io/v1beta1/pods"); err == nil {
		for _, obj := range podMetrics {
			out.Metrics = append(out.Metrics, podMetricFromObject(obj))
		}
	}
	if nodeMetrics, err := c.list(ctx, "/apis/metrics.k8s.io/v1beta1/nodes"); err == nil {
		for _, obj := range nodeMetrics {
			out.Metrics = append(out.Metrics, nodeMetricFromObject(obj))
		}
	}
	return out, nil
}

func (c *HTTPClient) version(ctx context.Context) (string, error) {
	var body map[string]any
	if err := c.getJSON(ctx, "/version", &body); err != nil {
		return "", err
	}
	if v := str(body["gitVersion"]); v != "" {
		return v, nil
	}
	major, minor := str(body["major"]), str(body["minor"])
	if major != "" || minor != "" {
		return strings.Trim(major+"."+minor, "."), nil
	}
	return "unknown", nil
}

func (c *HTTPClient) list(ctx context.Context, path string) ([]map[string]any, error) {
	out := []map[string]any{}
	continueToken := ""
	for {
		pagePath, err := listPagePath(path, continueToken)
		if err != nil {
			return nil, err
		}
		var body struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []map[string]any `json:"items"`
		}
		if err := c.getJSON(ctx, pagePath, &body); err != nil {
			return nil, err
		}
		out = append(out, body.Items...)
		continueToken = strings.TrimSpace(body.Metadata.Continue)
		if continueToken == "" {
			break
		}
	}
	return out, nil
}

func listPagePath(path string, continueToken string) (string, error) {
	u, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if strings.TrimSpace(q.Get("limit")) == "" {
		q.Set("limit", "500")
	}
	if strings.TrimSpace(continueToken) != "" {
		q.Set("continue", continueToken)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c *HTTPClient) getJSON(ctx context.Context, path string, out any) error {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.ServerURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.cfg.UserAgent)
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
		return fmt.Errorf("Kubernetes API %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func clientConfigFromCredential(cluster store.K8sCluster, kind string, payload string) (HTTPClientConfig, error) {
	mode := NormalizeAuthMode(cluster.AuthMode)
	kind = strings.ToLower(strings.TrimSpace(kind))
	payload = strings.TrimSpace(payload)
	if mode == "in_cluster" {
		return inClusterConfig()
	}
	switch kind {
	case "kubeconfig":
		return parseKubeconfig(payload, cluster.ServerURL)
	case "token", "service_account":
		if payload == "" {
			return HTTPClientConfig{}, fmt.Errorf("service account token is empty")
		}
		return HTTPClientConfig{ServerURL: cluster.ServerURL, Token: payload}, nil
	case "":
		if mode == "service_account" || mode == "token" {
			return HTTPClientConfig{ServerURL: cluster.ServerURL, Token: payload}, nil
		}
		return HTTPClientConfig{ServerURL: cluster.ServerURL}, nil
	default:
		return HTTPClientConfig{}, fmt.Errorf("unsupported credential kind %q", kind)
	}
}

func inClusterConfig() (HTTPClientConfig, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return HTTPClientConfig{}, fmt.Errorf("in-cluster Kubernetes service environment is not available")
	}
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return HTTPClientConfig{}, fmt.Errorf("read service account token: %w", err)
	}
	ca, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	return HTTPClientConfig{ServerURL: "https://" + host + ":" + port, Token: strings.TrimSpace(string(token)), CACertPEM: ca}, nil
}

type kubeconfigFile struct {
	Clusters []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token                 string `yaml:"token"`
			TokenFile             string `yaml:"tokenFile"`
			TokenFileDash         string `yaml:"token-file"`
			ClientCertificate     string `yaml:"client-certificate"`
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKey             string `yaml:"client-key"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
}

func parseKubeconfig(raw string, fallbackServer string) (HTTPClientConfig, error) {
	var kc kubeconfigFile
	if err := yaml.Unmarshal([]byte(raw), &kc); err != nil {
		return HTTPClientConfig{}, fmt.Errorf("parse kubeconfig: %w", err)
	}
	clusterName, userName := "", ""
	for _, ctx := range kc.Contexts {
		if ctx.Name == kc.CurrentContext || (kc.CurrentContext == "" && clusterName == "") {
			clusterName, userName = ctx.Context.Cluster, ctx.Context.User
		}
	}
	cfg := HTTPClientConfig{ServerURL: fallbackServer}
	for _, cl := range kc.Clusters {
		if cl.Name == clusterName || (clusterName == "" && cfg.ServerURL == "") {
			cfg.ServerURL = cl.Cluster.Server
			cfg.InsecureTLS = cl.Cluster.InsecureSkipTLSVerify
			if cl.Cluster.CertificateAuthorityData != "" {
				ca, err := base64.StdEncoding.DecodeString(cl.Cluster.CertificateAuthorityData)
				if err != nil {
					return HTTPClientConfig{}, fmt.Errorf("decode certificate-authority-data: %w", err)
				}
				cfg.CACertPEM = ca
			} else if cl.Cluster.CertificateAuthority != "" {
				ca, err := readKubeconfigFile(cl.Cluster.CertificateAuthority, "certificate-authority")
				if err != nil {
					return HTTPClientConfig{}, err
				}
				cfg.CACertPEM = ca
			}
			break
		}
	}
	for _, u := range kc.Users {
		if u.Name == userName || (userName == "" && cfg.Token == "") {
			cfg.Token = u.User.Token
			tokenFile := firstNonEmpty(u.User.TokenFile, u.User.TokenFileDash)
			if cfg.Token == "" && tokenFile != "" {
				b, err := readKubeconfigFile(tokenFile, "tokenFile")
				if err != nil {
					return HTTPClientConfig{}, err
				}
				cfg.Token = strings.TrimSpace(string(b))
			}
			if u.User.ClientCertificateData != "" || u.User.ClientKeyData != "" {
				cert, err := base64.StdEncoding.DecodeString(u.User.ClientCertificateData)
				if err != nil {
					return HTTPClientConfig{}, fmt.Errorf("decode client-certificate-data: %w", err)
				}
				key, err := base64.StdEncoding.DecodeString(u.User.ClientKeyData)
				if err != nil {
					return HTTPClientConfig{}, fmt.Errorf("decode client-key-data: %w", err)
				}
				cfg.ClientCertPEM = cert
				cfg.ClientKeyPEM = key
			} else if u.User.ClientCertificate != "" || u.User.ClientKey != "" {
				cert, err := readKubeconfigFile(u.User.ClientCertificate, "client-certificate")
				if err != nil {
					return HTTPClientConfig{}, err
				}
				key, err := readKubeconfigFile(u.User.ClientKey, "client-key")
				if err != nil {
					return HTTPClientConfig{}, err
				}
				cfg.ClientCertPEM = cert
				cfg.ClientKeyPEM = key
			}
			break
		}
	}
	if cfg.ServerURL == "" {
		return HTTPClientConfig{}, fmt.Errorf("kubeconfig server URL is empty")
	}
	return cfg, nil
}

func readKubeconfigFile(pathValue, field string) ([]byte, error) {
	pathValue = strings.TrimSpace(pathValue)
	if pathValue == "" {
		return nil, fmt.Errorf("kubeconfig %s path is empty", field)
	}
	path := expandKubeconfigPath(pathValue)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read kubeconfig %s file %q: %w", field, pathValue, err)
	}
	return b, nil
}

func expandKubeconfigPath(pathValue string) string {
	pathValue = os.ExpandEnv(strings.TrimSpace(pathValue))
	if pathValue == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(pathValue, "~/") || strings.HasPrefix(pathValue, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, pathValue[2:])
		}
	}
	return pathValue
}

func inventoryFromObject(kind, apiVersion string, obj map[string]any) store.K8sInventoryItem {
	meta := asMap(obj["metadata"])
	status := summarizeStatus(kind, obj)
	spec := asMap(obj["spec"])
	if refs := meta["ownerReferences"]; refs != nil {
		next := map[string]any{}
		for k, v := range spec {
			next[k] = v
		}
		next["ownerReferences"] = refs
		spec = next
	}
	// Some resources carry their editable body outside .spec. Fold those fields into Spec so
	// analyzers/revisions can diff them, then Manifest Viewer expands them back to top level.
	switch kind {
	case "ConfigMap":
		spec = topLevelResourceBody(obj, "data", "binaryData", "immutable")
	case "ServiceAccount":
		spec = topLevelResourceBody(obj, "automountServiceAccountToken", "secrets", "imagePullSecrets")
	case "Role", "ClusterRole":
		if obj["rules"] != nil {
			spec = map[string]any{"rules": obj["rules"]}
		}
	case "RoleBinding", "ClusterRoleBinding":
		spec = map[string]any{"roleRef": obj["roleRef"], "subjects": obj["subjects"]}
	case "Secret":
		// Never store secret data. Keep only the type and, for TLS secrets, the PUBLIC
		// certificate (tls.crt) so cert expiry/CN/SAN can be analyzed (SEC-07). tls.key is dropped.
		typ := str(obj["type"])
		spec = map[string]any{"type": typ}
		if typ == "kubernetes.io/tls" {
			if crt := str(asMap(obj["data"])["tls.crt"]); crt != "" {
				if dec, err := base64.StdEncoding.DecodeString(crt); err == nil {
					spec["tls_crt_pem"] = string(dec)
				}
			}
		}
	}
	return store.K8sInventoryItem{
		Kind:         kind,
		Namespace:    str(meta["namespace"]),
		Name:         str(meta["name"]),
		UID:          str(meta["uid"]),
		APIVersion:   firstNonEmpty(str(obj["apiVersion"]), apiVersion),
		Status:       status,
		Spec:         spec,
		StatusObject: asMap(obj["status"]),
		Labels:       stringMap(meta["labels"]),
		Annotations:  stringMap(meta["annotations"]),
	}
}

func topLevelResourceBody(obj map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, key := range keys {
		if v, ok := obj[key]; ok {
			out[key] = v
		}
	}
	return out
}

func eventFromObject(obj map[string]any) store.K8sEvent {
	meta := asMap(obj["metadata"])
	involved := asMap(obj["involvedObject"])
	return store.K8sEvent{
		Namespace:    firstNonEmpty(str(involved["namespace"]), str(meta["namespace"])),
		InvolvedKind: str(involved["kind"]),
		InvolvedName: str(involved["name"]),
		Reason:       str(obj["reason"]),
		Type:         str(obj["type"]),
		Message:      str(obj["message"]),
		Count:        intValue(obj["count"]),
		Source:       sourceName(obj["source"], obj["reportingComponent"]),
		FirstSeen:    firstNonEmpty(str(obj["firstTimestamp"]), str(obj["eventTime"]), str(meta["creationTimestamp"])),
		LastSeen:     firstNonEmpty(str(obj["lastTimestamp"]), str(obj["eventTime"]), str(meta["creationTimestamp"])),
	}
}

func podMetricFromObject(obj map[string]any) store.K8sMetricSample {
	meta := asMap(obj["metadata"])
	out := store.K8sMetricSample{Namespace: str(meta["namespace"]), ResourceKind: "Pod", ResourceName: str(meta["name"]), ObservedAt: str(obj["timestamp"])}
	for _, c := range asSlice(obj["containers"]) {
		usage := asMap(asMap(c)["usage"])
		out.CPUMillicores += parseCPU(str(usage["cpu"]))
		out.MemoryBytes += parseBytes(str(usage["memory"]))
	}
	return out
}

func nodeMetricFromObject(obj map[string]any) store.K8sMetricSample {
	meta := asMap(obj["metadata"])
	usage := asMap(obj["usage"])
	return store.K8sMetricSample{
		ResourceKind:  "Node",
		ResourceName:  str(meta["name"]),
		CPUMillicores: parseCPU(str(usage["cpu"])),
		MemoryBytes:   parseBytes(str(usage["memory"])),
		ObservedAt:    str(obj["timestamp"]),
	}
}

func summarizeStatus(kind string, obj map[string]any) string {
	status := asMap(obj["status"])
	spec := asMap(obj["spec"])
	switch kind {
	case "Pod":
		if reason := podWaitingReason(status); reason != "" {
			return reason
		}
		return firstNonEmpty(str(status["phase"]), "Unknown")
	case "Node":
		for _, raw := range asSlice(status["conditions"]) {
			c := asMap(raw)
			if str(c["type"]) == "Ready" {
				if str(c["status"]) == "True" {
					return "Ready"
				}
				return "NotReady"
			}
		}
		return "Unknown"
	case "Deployment", "StatefulSet":
		ready := intValue(status["readyReplicas"])
		available := intValue(status["availableReplicas"])
		desired := intValue(firstAny(spec["replicas"], status["desiredNumberScheduled"], status["currentNumberScheduled"]))
		if desired == 0 {
			return "ScaledToZero"
		}
		if available < desired || ready < desired {
			return fmt.Sprintf("Unavailable %d/%d", maxInt(ready, available), desired)
		}
		return fmt.Sprintf("Available %d/%d", maxInt(ready, available), desired)
	case "DaemonSet":
		ready := intValue(status["numberReady"])
		available := intValue(status["numberAvailable"])
		desired := intValue(status["desiredNumberScheduled"])
		if desired == 0 {
			return "ScaledToZero"
		}
		if available < desired || ready < desired {
			return fmt.Sprintf("Unavailable %d/%d", maxInt(ready, available), desired)
		}
		return fmt.Sprintf("Available %d/%d", maxInt(ready, available), desired)
	case "PersistentVolumeClaim":
		return firstNonEmpty(str(status["phase"]), "Unknown")
	case "Job":
		if intValue(status["failed"]) > 0 {
			return "Failed"
		}
		if intValue(status["succeeded"]) > 0 {
			return "Succeeded"
		}
		return "Running"
	default:
		return firstNonEmpty(str(status["phase"]), str(spec["type"]), "Observed")
	}
}

func podWaitingReason(status map[string]any) string {
	for _, raw := range asSlice(status["containerStatuses"]) {
		st := asMap(asMap(raw)["state"])
		waiting := asMap(st["waiting"])
		if reason := str(waiting["reason"]); reason != "" {
			return reason
		}
		terminated := asMap(st["terminated"])
		if reason := str(terminated["reason"]); reason != "" {
			return reason
		}
	}
	return ""
}

func isOptionalAPI(path string) bool {
	return strings.Contains(path, "/ingresses") || strings.Contains(path, "/cronjobs") ||
		strings.Contains(path, "rbac.authorization.k8s.io") || strings.Contains(path, "/networkpolicies") ||
		strings.Contains(path, "/horizontalpodautoscalers") || strings.Contains(path, "/secrets")
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func asSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func stringMap(v any) map[string]string {
	out := map[string]string{}
	for k, val := range asMap(v) {
		out[k] = str(val)
	}
	return out
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if math.Trunc(t) == t {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func intValue(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}

func firstAny(values ...any) any {
	for _, v := range values {
		if str(v) != "" && str(v) != "0" {
			return v
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func sourceName(values ...any) string {
	for _, v := range values {
		if s := str(v); s != "" {
			if m := asMap(v); len(m) > 0 {
				return firstNonEmpty(str(m["component"]), str(m["host"]))
			}
			return s
		}
	}
	return ""
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func parseCPU(raw string) float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	mult := 1000.0
	switch {
	case strings.HasSuffix(raw, "n"):
		mult = 0.000001
		raw = strings.TrimSuffix(raw, "n")
	case strings.HasSuffix(raw, "u"):
		mult = 0.001
		raw = strings.TrimSuffix(raw, "u")
	case strings.HasSuffix(raw, "m"):
		mult = 1
		raw = strings.TrimSuffix(raw, "m")
	}
	v, _ := strconv.ParseFloat(raw, 64)
	return v * mult
}

func parseBytes(raw string) float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	units := []struct {
		suffix string
		mult   float64
	}{
		{"Ki", 1024}, {"Mi", 1024 * 1024}, {"Gi", 1024 * 1024 * 1024}, {"Ti", 1024 * 1024 * 1024 * 1024},
		{"K", 1000}, {"M", 1000 * 1000}, {"G", 1000 * 1000 * 1000}, {"T", 1000 * 1000 * 1000 * 1000},
	}
	for _, u := range units {
		if strings.HasSuffix(raw, u.suffix) {
			v, _ := strconv.ParseFloat(strings.TrimSuffix(raw, u.suffix), 64)
			return v * u.mult
		}
	}
	v, _ := strconv.ParseFloat(raw, 64)
	return v
}
