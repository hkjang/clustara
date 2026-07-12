package proxy

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"clustara/internal/store"
)

type serviceJupyterWorkspace struct {
	Username     string   `json:"username"`
	PVCName      string   `json:"pvc_name"`
	PVCStatus    string   `json:"pvc_status"`
	Status       string   `json:"status"`
	PodNames     []string `json:"pod_names"`
	StorageClass string   `json:"storage_class"`
	Capacity     string   `json:"capacity"`
	Source       string   `json:"source"`
}

type jupyterWorkspaceAccumulator struct {
	Workspace serviceJupyterWorkspace
	Active    bool
}

func (s *Server) handleServiceJupyterWorkspaces(w http.ResponseWriter, r *http.Request, instance store.K8sServiceInstance) {
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "method_not_allowed")
		return
	}
	catalog, err := s.db.GetK8sServiceCatalog(r.Context(), instance.CatalogID)
	if err != nil || catalog.Code != "jupyterhub" {
		writeOpenAIError(w, http.StatusUnprocessableEntity, "user workspace mapping is available for JupyterHub services only", "invalid_request_error", "jupyter_workspace_unavailable")
		return
	}
	workspaces, err := s.discoverJupyterHubWorkspaces(r.Context(), instance)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, err.Error(), "server_error", "jupyter_workspace_discovery_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"instance_id": instance.ID, "workspaces": workspaces, "total": len(workspaces), "note": "JupyterHub deployment/user labels and Pod PVC mounts are correlated; Secret values are never read."})
}

func (s *Server) discoverJupyterHubWorkspaces(ctx context.Context, instance store.K8sServiceInstance) ([]serviceJupyterWorkspace, error) {
	inventory, err := s.db.ListK8sInventory(ctx, store.K8sInventoryFilter{ClusterID: instance.ClusterID, Namespace: instance.Namespace, Limit: 5000})
	if err != nil {
		return nil, err
	}
	pvcs := map[string]store.K8sInventoryItem{}
	acc := map[string]*jupyterWorkspaceAccumulator{}
	for _, item := range inventory {
		if !strings.EqualFold(item.Kind, "PersistentVolumeClaim") {
			continue
		}
		pvcs[item.Name] = item
		username := jupyterWorkspaceUsername(item)
		if username == "" || !jupyterHubItemAssociated(item, instance) {
			continue
		}
		acc[item.Name] = &jupyterWorkspaceAccumulator{Workspace: serviceJupyterWorkspace{
			Username: username, PVCName: item.Name, PVCStatus: firstNonEmpty(item.Status, "unknown"), Status: "idle",
			StorageClass: cleanRestoreValue(item.Spec["storageClassName"]), Capacity: jupyterWorkspaceCapacity(item), Source: "pvc_labels",
		}}
	}
	for _, item := range inventory {
		if !strings.EqualFold(item.Kind, "Pod") || !jupyterHubItemAssociated(item, instance) {
			continue
		}
		username := jupyterWorkspaceUsername(item)
		if username == "" {
			continue
		}
		for _, pvcName := range jupyterPodPVCClaims(item) {
			entry := acc[pvcName]
			if entry == nil {
				pvc := pvcs[pvcName]
				entry = &jupyterWorkspaceAccumulator{Workspace: serviceJupyterWorkspace{
					Username: username, PVCName: pvcName, PVCStatus: firstNonEmpty(pvc.Status, "unknown"), Status: "idle",
					StorageClass: cleanRestoreValue(pvc.Spec["storageClassName"]), Capacity: jupyterWorkspaceCapacity(pvc), Source: "pod_volume",
				}}
				acc[pvcName] = entry
			} else {
				entry.Workspace.Source = "pvc_labels+pod_volume"
			}
			if entry.Workspace.Username != username {
				entry.Workspace.Status = "conflict"
				continue
			}
			entry.Workspace.PodNames = append(entry.Workspace.PodNames, item.Name)
			entry.Active = entry.Active || servicePodStatusActive(item.Status)
		}
	}
	out := make([]serviceJupyterWorkspace, 0, len(acc))
	for _, entry := range acc {
		sort.Strings(entry.Workspace.PodNames)
		if entry.Workspace.Status != "conflict" && entry.Active {
			entry.Workspace.Status = "active"
		}
		out = append(out, entry.Workspace)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Username == out[j].Username {
			return out[i].PVCName < out[j].PVCName
		}
		return out[i].Username < out[j].Username
	})
	return out, nil
}

func jupyterWorkspaceUsername(item store.K8sInventoryItem) string {
	for _, key := range []string{"hub.jupyter.org/username", "jupyterhub/username", "jupyter.org/username", "clustara.io/workspace-owner"} {
		if value := strings.TrimSpace(firstNonEmpty(item.Labels[key], item.Annotations[key])); value != "" {
			return value
		}
	}
	return ""
}

func jupyterHubItemAssociated(item store.K8sInventoryItem, instance store.K8sServiceInstance) bool {
	for _, key := range []string{"clustara.io/service-instance", "app.kubernetes.io/instance", "hub.jupyter.org/deployment", "release"} {
		value := strings.TrimSpace(firstNonEmpty(item.Labels[key], item.Annotations[key]))
		if value != "" && (value == instance.ID || value == instance.Name) {
			return true
		}
	}
	return false
}

func jupyterPodPVCClaims(item store.K8sInventoryItem) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, raw := range serviceAnySlice(item.Spec["volumes"]) {
		volume := asMapAny(raw)
		claim := asMapAny(volume["persistentVolumeClaim"])
		name := cleanRestoreValue(claim["claimName"])
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func jupyterWorkspaceCapacity(item store.K8sInventoryItem) string {
	resources := asMapAny(item.Spec["resources"])
	requests := asMapAny(resources["requests"])
	return cleanRestoreValue(requests["storage"])
}

func servicePodStatusActive(status string) bool {
	status = strings.ToLower(strings.TrimSpace(status))
	return status != "" && status != "succeeded" && status != "failed" && status != "completed" && status != "terminated"
}

func validWorkspaceOwner(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for _, ch := range value {
		if ch < 0x20 || ch == 0x7f {
			return false
		}
	}
	return true
}
