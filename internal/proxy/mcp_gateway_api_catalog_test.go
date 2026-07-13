package proxy

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGatewayAPICatalogCoversEveryOpenAPIOperation(t *testing.T) {
	want := 0
	seen := map[string]bool{}
	for _, endpoint := range apiEndpoints {
		for _, method := range endpoint.methods {
			key := strings.ToUpper(method) + " " + endpoint.path
			if !seen[key] {
				seen[key] = true
				want++
			}
		}
	}
	catalog := gatewayAPICatalog()
	if len(catalog) != want {
		t.Fatalf("MCP API catalog coverage=%d want=%d", len(catalog), want)
	}
	results := searchGatewayAPICatalog("manifest changes", "k8s", "POST", 20)
	if len(results) == 0 {
		t.Fatal("manifest change API must be discoverable from MCP")
	}
	foundDedicated := false
	for _, result := range results {
		if result.Path == "/admin/k8s/manifest-changes" && result.MCPExposure == "dedicated_tool" && len(result.MCPTools) > 0 {
			foundDedicated = true
		}
	}
	if !foundDedicated {
		t.Fatalf("manifest change search must point to dedicated MCP tools: %+v", results)
	}
	if korean := searchGatewayAPICatalog("YAML 변경", "k8s", "POST", 20); len(korean) == 0 {
		t.Fatal("Korean LLM query must discover English OpenAPI manifest operations")
	}
}

func TestGatewayMCPPublishesInstructionsAndAPICatalogResources(t *testing.T) {
	init := gwDispatch(t, "initialize", "")
	if init == nil || !strings.Contains(string(init.Result), "gateway_search_api_catalog") || !strings.Contains(string(init.Result), "YAML") {
		t.Fatalf("initialize must teach the LLM how to discover and change safely: %+v", init)
	}
	resources := gwDispatch(t, "resources/list", "")
	for _, uri := range []string{"gateway://api/catalog", "gateway://api/coverage", "gateway://operator-guide"} {
		if resources == nil || !strings.Contains(string(resources.Result), uri) {
			t.Fatalf("resources/list missing %s: %+v", uri, resources)
		}
	}
	s := &Server{}
	req := httptest.NewRequest("POST", "/mcp/gateway", nil)
	response := s.gatewayResourcesRead(req, nil, json.RawMessage(`1`), json.RawMessage(`{"uri":"gateway://api/coverage"}`))
	if response == nil || response.Error != nil || !strings.Contains(string(response.Result), "mcp_catalog_coverage_percent") {
		t.Fatalf("coverage resource read failed: %+v", response)
	}
}
