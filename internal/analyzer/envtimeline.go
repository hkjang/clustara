package analyzer

import (
	"sort"
	"strings"

	"clustara/internal/store"
)

// Env Change Timeline: merge the revisions of the ConfigMaps/Secrets a Pod consumes with the Pod's
// own revisions into one time-ordered view, so an operator can see whether a config/secret change
// landed just before the Pod degraded ("장애 직전 설정 변경"). Pure over its inputs.

// EnvTimelineEntry is one env-relevant change, newest first.
type EnvTimelineEntry struct {
	At     string `json:"at"`
	Type   string `json:"type"` // configmap_change | secret_change | pod_change
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Change string `json:"change"` // created | updated
	Detail string `json:"detail"`
}

// EnvTimelineInput carries the gathered revisions.
type EnvTimelineInput struct {
	PodRevisions    []store.K8sResourceRevision // the Pod's own revisions
	SourceRevisions []store.K8sResourceRevision // referenced ConfigMap/Secret revisions
}

// BuildEnvChangeTimeline merges and time-orders the env-relevant changes (newest first).
func BuildEnvChangeTimeline(in EnvTimelineInput) []EnvTimelineEntry {
	out := []EnvTimelineEntry{}
	add := func(rev store.K8sResourceRevision, typ string) {
		detail := rev.ChangeKind
		if rev.ImageSet != "" {
			detail = "image: " + rev.ImageSet
		}
		out = append(out, EnvTimelineEntry{
			At: rev.ObservedAt, Type: typ, Kind: rev.Kind, Name: rev.Name,
			Change: rev.ChangeKind, Detail: detail,
		})
	}
	for _, rev := range in.SourceRevisions {
		typ := "configmap_change"
		if strings.EqualFold(rev.Kind, "Secret") {
			typ = "secret_change"
		}
		add(rev, typ)
	}
	for _, rev := range in.PodRevisions {
		add(rev, "pod_change")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At > out[j].At }) // RFC3339 sorts lexically
	return out
}

// EnvReferencedSources extracts the distinct ConfigMap/Secret names a Pod's env references, so the
// caller knows which revisions to gather for the timeline.
func EnvReferencedSources(m EnvSourceMap) (configMaps, secrets []string) {
	cmSeen, scSeen := map[string]bool{}, map[string]bool{}
	for _, v := range m.Vars {
		switch v.SourceType {
		case "configmap", "configmap_all":
			if v.SourceName != "" && !cmSeen[v.SourceName] {
				cmSeen[v.SourceName] = true
				configMaps = append(configMaps, v.SourceName)
			}
		case "secret", "secret_all":
			if v.SourceName != "" && !scSeen[v.SourceName] {
				scSeen[v.SourceName] = true
				secrets = append(secrets, v.SourceName)
			}
		}
	}
	sort.Strings(configMaps)
	sort.Strings(secrets)
	return configMaps, secrets
}
