package store

import "strings"

// Some annotations carry a verbatim copy of the whole object rather than a value of their own.
// kubectl writes the applied manifest into last-applied-configuration, so on a Secret that copy
// contains exactly the `data` the collector refuses to store, and on a workload it contains every
// container env value — the payload every other reader masks. Inventory rows are served raw by
// GET /admin/k8s/inventory and expanded into the Manifest Viewer (which advertises masked: true),
// so the copy has to be dropped before it is stored, not at each reader.
//
// Every ingestion path (live collect, agent push, offline snapshot import) lands in
// UpsertK8sInventory, and every reader goes through scanK8sInventory, so both ends drop it: the
// write keeps it out of the database, the read keeps rows collected by an older build from
// reaching a response before their next collection overwrites them.
var objectCopyAnnotations = map[string]struct{}{
	"kubectl.kubernetes.io/last-applied-configuration": {},
}

// IsObjectCopyAnnotation reports whether an annotation key holds a full copy of the object.
func IsObjectCopyAnnotation(key string) bool {
	_, ok := objectCopyAnnotations[strings.ToLower(strings.TrimSpace(key))]
	return ok
}

// StripObjectCopyAnnotations returns the annotations without the full-object copies. The input
// map is left untouched; when there is nothing to drop the same map is returned.
func StripObjectCopyAnnotations(in map[string]string) map[string]string {
	drop := false
	for k := range in {
		if IsObjectCopyAnnotation(k) {
			drop = true
			break
		}
	}
	if !drop {
		return in
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if IsObjectCopyAnnotation(k) {
			continue
		}
		out[k] = v
	}
	return out
}
