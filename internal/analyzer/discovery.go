package analyzer

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// K8s API Discovery + OpenAPI v3 Schema Registry (CLU-DISC-01/02/04/05).
//
// Parses the cluster's aggregated discovery (APIGroupDiscoveryList) and the /openapi/v3 root index
// into structured registry rows. Pure: the kube client fetches the raw bytes, these turn them into
// the catalog (which resources exist, with what verbs/scope) and the schema-document index (which
// group/version OpenAPI docs exist, with their content hash). Foundation for dynamic inventory,
// schema-aware validation, CRD auto-discovery, and MCP tool generation.

// APIResourceInfo is one discovered API resource (group/version/resource) with its capabilities.
type APIResourceInfo struct {
	Group      string   `json:"group"`   // "" for the core group
	Version    string   `json:"version"`
	Resource   string   `json:"resource"` // plural, e.g. "deployments"
	Kind       string   `json:"kind"`
	Namespaced bool     `json:"namespaced"`
	Verbs      []string `json:"verbs"`
	ShortNames []string `json:"short_names,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Listable   bool     `json:"listable"` // supports list+watch → an inventory-collection candidate
}

// GroupVersion renders the group/version label ("v1" for core, "apps/v1" otherwise).
func (r APIResourceInfo) GroupVersion() string {
	if r.Group == "" {
		return r.Version
	}
	return r.Group + "/" + r.Version
}

// ParseAggregatedDiscovery parses an APIGroupDiscoveryList (aggregated discovery v2) into resources.
// Subresources (those whose resource name contains "/", e.g. "pods/status") are skipped.
func ParseAggregatedDiscovery(raw []byte) ([]APIResourceInfo, error) {
	var doc struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Versions []struct {
				Version   string `json:"version"`
				Resources []struct {
					Resource     string   `json:"resource"`
					ResponseKind struct {
						Kind string `json:"kind"`
					} `json:"responseKind"`
					Scope      string   `json:"scope"` // Namespaced | Cluster
					Verbs      []string `json:"verbs"`
					ShortNames []string `json:"shortNames"`
					Categories []string `json:"categories"`
				} `json:"resources"`
			} `json:"versions"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := []APIResourceInfo{}
	for _, g := range doc.Items {
		for _, v := range g.Versions {
			for _, r := range v.Resources {
				if strings.Contains(r.Resource, "/") {
					continue // subresource
				}
				out = append(out, APIResourceInfo{
					Group: g.Metadata.Name, Version: v.Version, Resource: r.Resource,
					Kind: r.ResponseKind.Kind, Namespaced: strings.EqualFold(r.Scope, "Namespaced"),
					Verbs: r.Verbs, ShortNames: r.ShortNames, Categories: r.Categories,
					Listable: hasVerb(r.Verbs, "list") && hasVerb(r.Verbs, "watch"),
				})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].GroupVersion() != out[j].GroupVersion() {
			return out[i].GroupVersion() < out[j].GroupVersion()
		}
		return out[i].Resource < out[j].Resource
	})
	return out, nil
}

// OpenAPIDocRef indexes one group/version OpenAPI v3 document.
type OpenAPIDocRef struct {
	GroupVersion      string `json:"group_version"`       // e.g. "apis/apps/v1" or "api/v1"
	ServerRelativeURL string `json:"server_relative_url"` // path to fetch the doc
	Hash              string `json:"hash"`                // content hash from the URL's ?hash= query
}

// ParseOpenAPIV3Root parses the /openapi/v3 index ({"paths":{"<gv>":{"serverRelativeURL":"..."}}}).
func ParseOpenAPIV3Root(raw []byte) ([]OpenAPIDocRef, error) {
	var doc struct {
		Paths map[string]struct {
			ServerRelativeURL string `json:"serverRelativeURL"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := make([]OpenAPIDocRef, 0, len(doc.Paths))
	for gv, p := range doc.Paths {
		out = append(out, OpenAPIDocRef{
			GroupVersion: gv, ServerRelativeURL: p.ServerRelativeURL, Hash: hashFromURL(p.ServerRelativeURL),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].GroupVersion < out[j].GroupVersion })
	return out, nil
}

// DiscoverySummary rolls up a discovery snapshot for the registry header.
type DiscoverySummary struct {
	TotalResources  int      `json:"total_resources"`
	Listable        int      `json:"listable"`
	Namespaced      int      `json:"namespaced"`
	Groups          int      `json:"groups"`
	CRDResources    int      `json:"crd_resources"` // resources in a non–built-in group (contains a dot)
	SchemaDocuments int      `json:"schema_documents"`
	GroupList       []string `json:"group_list"`
}

// SummarizeDiscovery tallies a resource catalog + schema-doc index.
func SummarizeDiscovery(resources []APIResourceInfo, docs []OpenAPIDocRef) DiscoverySummary {
	s := DiscoverySummary{TotalResources: len(resources), SchemaDocuments: len(docs)}
	groups := map[string]bool{}
	for _, r := range resources {
		if r.Listable {
			s.Listable++
		}
		if r.Namespaced {
			s.Namespaced++
		}
		if !groups[r.Group] {
			groups[r.Group] = true
		}
		// Built-in groups have no dot (apps, batch, ""); CRD groups are DNS-style (e.g. monitoring.coreos.com).
		if strings.Contains(r.Group, ".") {
			s.CRDResources++
		}
	}
	s.Groups = len(groups)
	s.GroupList = []string{}
	for g := range groups {
		if g == "" {
			g = "(core)"
		}
		s.GroupList = append(s.GroupList, g)
	}
	sort.Strings(s.GroupList)
	return s
}

func hasVerb(verbs []string, want string) bool {
	for _, v := range verbs {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

// hashFromURL extracts the ?hash= query value from an OpenAPI serverRelativeURL.
func hashFromURL(raw string) string {
	i := strings.IndexByte(raw, '?')
	if i < 0 {
		return ""
	}
	q, err := url.ParseQuery(raw[i+1:])
	if err != nil {
		return ""
	}
	return q.Get("hash")
}
