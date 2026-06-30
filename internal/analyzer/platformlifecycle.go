package analyzer

import (
	"sort"
	"strings"
)

// Platform Lifecycle Center (CLU-OCP-08).
//
// Absorbs OpenShift's ClusterVersion/upgrade UX as a generic notion: an upgrade-readiness score for
// a cluster from deprecated API usage (reuses the Discovery compatibility radar), kubelet version
// skew across nodes, open critical incidents, and an outdated collector agent. Pure.

// UpgradeReadinessInput is one cluster's lifecycle signals.
type UpgradeReadinessInput struct {
	KubernetesVersion string   // control-plane version, e.g. "v1.29.4"
	NodeKubeletVers   []string // per-node kubelet versions
	DeprecatedAPIs    int      // deprecated group-versions in use (from DetectDeprecatedAPIs)
	CriticalIncidents int
	OutdatedAgent     bool
}

// UpgradeReadiness is the scored result.
type UpgradeReadiness struct {
	Score             int      `json:"score"` // 0..100 (higher = more ready)
	Level             string   `json:"level"` // ready | caution | blocked
	KubernetesVersion string   `json:"kubernetes_version"`
	VersionSkew       []string `json:"version_skew"` // node kubelet versions differing from control plane
	DeprecatedAPIs    int      `json:"deprecated_apis"`
	Reasons           []string `json:"reasons"`
	Blockers          []string `json:"blockers"`
}

// ScoreUpgradeReadiness rates how safe a cluster upgrade is right now.
func ScoreUpgradeReadiness(in UpgradeReadinessInput) UpgradeReadiness {
	out := UpgradeReadiness{
		Score: 100, KubernetesVersion: in.KubernetesVersion, DeprecatedAPIs: in.DeprecatedAPIs,
		VersionSkew: []string{}, Reasons: []string{}, Blockers: []string{},
	}

	// Version skew: any node kubelet minor != control-plane minor is a readiness risk.
	cpMinor := minorOf(in.KubernetesVersion)
	skewSet := map[string]bool{}
	for _, v := range in.NodeKubeletVers {
		if cpMinor != "" && minorOf(v) != "" && minorOf(v) != cpMinor && !skewSet[v] {
			skewSet[v] = true
			out.VersionSkew = append(out.VersionSkew, v)
		}
	}
	sort.Strings(out.VersionSkew)
	if len(out.VersionSkew) > 0 {
		out.Score -= 25
		out.Reasons = append(out.Reasons, "노드 kubelet 버전 skew")
	}

	if in.DeprecatedAPIs > 0 {
		p := in.DeprecatedAPIs * 10
		if p > 40 {
			p = 40
		}
		out.Score -= p
		msg := "deprecated/removed API 사용 " + itoaLifecycle(in.DeprecatedAPIs) + "건"
		out.Reasons = append(out.Reasons, msg)
		out.Blockers = append(out.Blockers, msg)
	}
	if in.CriticalIncidents > 0 {
		out.Score -= 25
		msg := "미해결 critical incident " + itoaLifecycle(in.CriticalIncidents) + "건"
		out.Reasons = append(out.Reasons, msg)
		out.Blockers = append(out.Blockers, msg)
	}
	if in.OutdatedAgent {
		out.Score -= 10
		out.Reasons = append(out.Reasons, "오래된 Clustara agent")
	}

	out.Score = clampScore(out.Score)
	switch {
	case len(out.Blockers) > 0 || out.Score < 50:
		out.Level = "blocked"
	case out.Score < 80:
		out.Level = "caution"
	default:
		out.Level = "ready"
	}
	if len(out.Reasons) == 0 {
		out.Reasons = append(out.Reasons, "업그레이드 차단 신호 없음")
	}
	return out
}

// minorOf extracts the "major.minor" from a version string ("v1.29.4" → "1.29").
func minorOf(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

func itoaLifecycle(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
