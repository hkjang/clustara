package kube

import (
	"fmt"
	"net/url"
	"strings"
)

var supportedAuthModes = map[string]struct{}{
	"kubeconfig":      {},
	"service_account": {},
	"token":           {},
	"in_cluster":      {},
}

func NormalizeAuthMode(raw string) string {
	mode := strings.ToLower(strings.TrimSpace(raw))
	mode = strings.ReplaceAll(mode, "-", "_")
	if mode == "" {
		return "kubeconfig"
	}
	return mode
}

func ValidateClusterRegistration(name, serverURL, authMode string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("cluster name is required")
	}
	mode := NormalizeAuthMode(authMode)
	if _, ok := supportedAuthModes[mode]; !ok {
		return fmt.Errorf("unsupported auth_mode %q", authMode)
	}
	if strings.TrimSpace(serverURL) == "" {
		if mode == "in_cluster" || mode == "service_account" {
			return nil
		}
		return fmt.Errorf("server_url is required unless auth_mode is in_cluster or service_account")
	}
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("server_url must be an absolute URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("server_url scheme must be http or https")
	}
	return nil
}

func RedactCredentialPreview(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if len(raw) <= 12 {
		return "********"
	}
	return raw[:4] + "********" + raw[len(raw)-4:]
}
