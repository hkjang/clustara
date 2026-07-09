package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"clustara/internal/store"
)

func TestHarborRegistryRobotAndLaunchFlow(t *testing.T) {
	db := openTestStore(t)
	defer db.Close()
	logger := store.NewAsyncLogger(db, 8, filepath.Join(t.TempDir(), "harbor.ndjson"))
	logger.Start()
	defer logger.Stop(t.Context())
	server, err := NewServer(testConfig("http://upstream.invalid", "secret"), db, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(server.Routes())
	defer srv.Close()
	if err := db.UpsertK8sCluster(t.Context(), store.K8sCluster{ID: "prod-cluster", Name: "prod-cluster", Status: "ready"}); err != nil {
		t.Fatal(err)
	}

	regResp := postJSON(t, srv.URL+"/admin/harbor/registries", "", map[string]any{
		"name": "corp-harbor",
		"url":  "mock://harbor.local",
	})
	defer regResp.Body.Close()
	if regResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(regResp.Body)
		t.Fatalf("registry create status=%d body=%s", regResp.StatusCode, body)
	}
	var regOut struct {
		Registry store.HarborRegistry `json:"registry"`
	}
	if err := json.NewDecoder(regResp.Body).Decode(&regOut); err != nil {
		t.Fatal(err)
	}
	if regOut.Registry.ID == "" || regOut.Registry.URL != "mock://harbor.local" {
		t.Fatalf("registry mismatch: %+v", regOut.Registry)
	}

	testResp := postJSON(t, srv.URL+"/admin/harbor/registries/"+regOut.Registry.ID+"/test", "", map[string]any{})
	defer testResp.Body.Close()
	var testOut map[string]any
	if err := json.NewDecoder(testResp.Body).Decode(&testOut); err != nil {
		t.Fatal(err)
	}
	if testResp.StatusCode != http.StatusOK || testOut["status"] != "connected" {
		t.Fatalf("registry test mismatch status=%d out=%+v", testResp.StatusCode, testOut)
	}

	robotToken := "robot-token-should-not-leak"
	robotResp := postJSON(t, srv.URL+"/admin/harbor/robots", "", map[string]any{
		"registry_id":  regOut.Registry.ID,
		"project_name": "platform",
		"name":         "robot$platform+pull",
		"token":        robotToken,
		"expires_at":   "2099-01-01T00:00:00Z",
	})
	robotBody, _ := io.ReadAll(robotResp.Body)
	robotResp.Body.Close()
	if robotResp.StatusCode != http.StatusCreated {
		t.Fatalf("robot create status=%d body=%s", robotResp.StatusCode, robotBody)
	}
	if strings.Contains(string(robotBody), robotToken) || strings.Contains(string(robotBody), `"token_hash"`) || strings.Contains(string(robotBody), "sha256:") {
		t.Fatalf("robot response leaked sensitive token material: %s", robotBody)
	}
	var robotOut struct {
		Robot store.HarborRobotAccount `json:"robot"`
	}
	if err := json.Unmarshal(robotBody, &robotOut); err != nil {
		t.Fatal(err)
	}
	if !robotOut.Robot.HasTokenHash {
		t.Fatalf("robot should report hash evidence without returning it: %+v", robotOut.Robot)
	}

	verifyResp := postJSON(t, srv.URL+"/admin/harbor/robots/verify", "", map[string]any{
		"robot_id": robotOut.Robot.ID,
		"token":    robotToken,
	})
	defer verifyResp.Body.Close()
	var verifyOut map[string]any
	if err := json.NewDecoder(verifyResp.Body).Decode(&verifyOut); err != nil {
		t.Fatal(err)
	}
	if verifyResp.StatusCode != http.StatusOK || verifyOut["status"] != "verified" {
		t.Fatalf("robot verify mismatch status=%d out=%+v", verifyResp.StatusCode, verifyOut)
	}

	listResp, err := http.Get(srv.URL + "/admin/harbor/robots")
	if err != nil {
		t.Fatal(err)
	}
	listBody, _ := io.ReadAll(listResp.Body)
	listResp.Body.Close()
	if strings.Contains(string(listBody), robotToken) || strings.Contains(string(listBody), "sha256:") {
		t.Fatalf("robot list leaked sensitive material: %s", listBody)
	}

	catalogResp := postJSON(t, srv.URL+"/admin/harbor/catalog/query", "", map[string]any{
		"registry_id":  regOut.Registry.ID,
		"target":       "artifacts",
		"project_name": "platform",
		"repository":   "api",
		"robot_name":   "robot$platform+pull",
		"token":        robotToken,
	})
	catalogBody, _ := io.ReadAll(catalogResp.Body)
	catalogResp.Body.Close()
	if catalogResp.StatusCode != http.StatusOK {
		t.Fatalf("catalog status=%d body=%s", catalogResp.StatusCode, catalogBody)
	}
	if strings.Contains(string(catalogBody), robotToken) || !strings.Contains(string(catalogBody), "sha256:abc") {
		t.Fatalf("catalog response should include digest sample but not token: %s", catalogBody)
	}

	secretResp := postJSON(t, srv.URL+"/admin/harbor/pull-secret/preview", "", map[string]any{
		"registry_id":  regOut.Registry.ID,
		"project_name": "platform",
		"namespace":    "prod",
		"secret_name":  "harbor-platform-pull",
		"robot_name":   "robot$platform+pull",
		"token":        robotToken,
	})
	secretBody, _ := io.ReadAll(secretResp.Body)
	secretResp.Body.Close()
	if secretResp.StatusCode != http.StatusOK {
		t.Fatalf("secret preview status=%d body=%s", secretResp.StatusCode, secretBody)
	}
	if strings.Contains(string(secretBody), robotToken) || !strings.Contains(string(secretBody), "REDACTED_BY_CLUSTARA") {
		t.Fatalf("pull secret preview should be redacted and token-free: %s", secretBody)
	}

	latestResp := postJSON(t, srv.URL+"/admin/harbor/launches/preview", "", map[string]any{
		"registry_id":  regOut.Registry.ID,
		"robot_id":     robotOut.Robot.ID,
		"project_name": "platform",
		"repository":   "api",
		"tag":          "latest",
		"namespace":    "prod",
		"app_name":     "api",
	})
	defer latestResp.Body.Close()
	var latestOut map[string]any
	if err := json.NewDecoder(latestResp.Body).Decode(&latestOut); err != nil {
		t.Fatal(err)
	}
	if latestResp.StatusCode != http.StatusOK || latestOut["decision"] != "deny" {
		t.Fatalf("latest launch should be denied status=%d out=%+v", latestResp.StatusCode, latestOut)
	}

	launchResp := postJSON(t, srv.URL+"/admin/harbor/launches", "", map[string]any{
		"registry_id":  regOut.Registry.ID,
		"robot_id":     robotOut.Robot.ID,
		"project_name": "platform",
		"repository":   "api",
		"tag":          "1.2.3",
		"digest":       "sha256:abc",
		"cluster_id":   "prod-cluster",
		"namespace":    "prod",
		"app_name":     "api",
		"secret_name":  "harbor-platform-pull",
		"replicas":     2,
		"port":         8080,
	})
	defer launchResp.Body.Close()
	var launchOut struct {
		Launch  store.HarborLaunchRequest `json:"launch"`
		Preview map[string]any            `json:"preview"`
	}
	if err := json.NewDecoder(launchResp.Body).Decode(&launchOut); err != nil {
		t.Fatal(err)
	}
	if launchResp.StatusCode != http.StatusCreated || launchOut.Launch.Decision != "allow" || !strings.Contains(launchOut.Launch.ManifestPreview, "imagePullSecrets") {
		t.Fatalf("launch create mismatch status=%d out=%+v", launchResp.StatusCode, launchOut)
	}
	if !strings.Contains(launchOut.Launch.Image, "harbor.local/platform/api@sha256:abc") {
		t.Fatalf("launch image should be digest-pinned: %s", launchOut.Launch.Image)
	}

	draftResp := postJSON(t, srv.URL+"/admin/harbor/launches/"+launchOut.Launch.ID+"/manifest-change", "", map[string]any{})
	defer draftResp.Body.Close()
	var draftOut struct {
		ManifestChangeID string `json:"manifest_change_id"`
		ManifestChange   struct {
			Request store.K8sManifestChangeRequest `json:"request"`
		} `json:"manifest_change"`
		ManifestChanges []struct {
			ID        string `json:"id"`
			Kind      string `json:"kind"`
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
			Operation string `json:"operation"`
			Status    string `json:"status"`
		} `json:"manifest_changes"`
	}
	if err := json.NewDecoder(draftResp.Body).Decode(&draftOut); err != nil {
		t.Fatal(err)
	}
	if draftResp.StatusCode != http.StatusCreated || draftOut.ManifestChangeID == "" {
		t.Fatalf("manifest draft create mismatch status=%d out=%+v", draftResp.StatusCode, draftOut)
	}
	if len(draftOut.ManifestChanges) != 2 {
		t.Fatalf("launch handoff should create Deployment and Service drafts: %+v", draftOut.ManifestChanges)
	}
	seenKinds := map[string]bool{}
	for _, row := range draftOut.ManifestChanges {
		seenKinds[row.Kind] = true
		if row.ID == "" || row.Operation != "create" || row.Status != "draft" {
			t.Fatalf("manifest draft row mismatch: %+v", row)
		}
	}
	if !seenKinds["Deployment"] || !seenKinds["Service"] {
		t.Fatalf("launch handoff should include Deployment and Service: %+v", draftOut.ManifestChanges)
	}
	if draftOut.ManifestChange.Request.Kind != "Deployment" || draftOut.ManifestChange.Request.Status != "draft" || draftOut.ManifestChange.Request.BeforeYAML != "" {
		t.Fatalf("manifest draft should be a new Deployment create request: %+v", draftOut.ManifestChange.Request)
	}
	if draftOut.ManifestChange.Request.Impact["operation"] != "create" || !strings.Contains(draftOut.ManifestChange.Request.AfterYAML, "imagePullSecrets") || strings.Contains(draftOut.ManifestChange.Request.AfterYAML, "harbor-platform-pull") {
		t.Fatalf("manifest draft should preserve create impact and mask pull secret name: %+v", draftOut.ManifestChange.Request)
	}
	updatedLaunch, err := db.GetHarborLaunchRequest(t.Context(), launchOut.Launch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updatedLaunch.Status != "manifest_drafted" {
		t.Fatalf("launch status should reflect Manifest Change handoff: %+v", updatedLaunch)
	}
	reqs, err := db.ListK8sManifestChangeRequests(t.Context(), store.K8sManifestChangeFilter{ClusterID: "prod-cluster", Namespace: "prod", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 {
		t.Fatalf("expected two manifest change requests for launch, got %d: %+v", len(reqs), reqs)
	}
}
