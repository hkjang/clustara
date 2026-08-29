package proxy

import (
	"context"
	"net/http"
	"testing"
	"time"

	"clustara/internal/store"
)

// The old verifier read the cluster out of the token with fmt.Sscanf("%s\n%d"), and %s stops
// at the first whitespace. A cluster registered with the id "victim\n9999999999" therefore
// produced a token whose payload parsed as cluster "victim" with an expiry in the year 2286:
// it authenticated as a DIFFERENT cluster, and — because the parse never matched its own id —
// not as its own. Cluster ids were admin-supplied and only TrimSpace'd.
//
// An agent token authorizes writing and DELETING that cluster's entire inventory, which is
// what the compliance, incident and security surfaces read.
func TestAgentTokenCannotBeConfusedIntoAnotherCluster(t *testing.T) {
	db, _ := newPolicyStatusServer(t)
	server := &Server{cfg: testConfig("http://upstream.invalid", "secret"), db: db}
	ctx := context.Background()

	crafted := "victim\n9999999999"
	token := server.issueAgentToken(ctx, crafted, time.Now().Add(time.Hour))
	if server.verifyAgentToken(ctx, token, "victim") {
		t.Fatal("a token issued for a newline-bearing cluster id authenticated as the cluster whose " +
			"name it embeds; that grants write and delete over another cluster's whole inventory")
	}
	// The binding is exact, so it does still verify for the exact odd id it was issued for.
	// That id can no longer be registered, but the token parser no longer depends on that.
	if !server.verifyAgentToken(ctx, token, crafted) {
		t.Fatal("a token must verify for the exact cluster id it was issued for")
	}

	// A cluster id containing a plain space used to produce a token that could never verify,
	// so the agent 401'd forever and looked like an agent bug. Exact binding fixes that too.
	spaced := "prod cluster"
	if !server.verifyAgentToken(ctx, server.issueAgentToken(ctx, spaced, time.Now().Add(time.Hour)), spaced) {
		t.Fatal("a token must verify for the exact cluster id it was issued for")
	}
	// ...and still not for a prefix of it.
	if server.verifyAgentToken(ctx, server.issueAgentToken(ctx, spaced, time.Now().Add(time.Hour)), "prod") {
		t.Fatal("a token verified for a prefix of its cluster id")
	}
}

// Cluster ids are rejected at registration when they carry whitespace or control characters:
// nothing legitimate needs one, and every key built from the id is clearer without.
func TestClusterRegistrationRejectsUntypableIDs(t *testing.T) {
	for _, id := range []string{"victim\n9999999999", "prod cluster", "a\tb", "prod\x00"} {
		if validClusterID(id) {
			t.Errorf("cluster id %q accepted; it embeds whitespace or a control character", id)
		}
	}
	for _, id := range []string{"k8scl_9f2a", "prod-seoul", "team.a:prod"} {
		if !validClusterID(id) {
			t.Errorf("ordinary cluster id %q rejected", id)
		}
	}
}

// A leaked agent token had no remedy short of rotating GATEWAY_SECRET — the HMAC key for
// every cluster's tokens at once, and the encryption key for stored cluster credentials.
// Revocation is now per-cluster.
func TestAgentTokenRevocationKillsOneClusterOnly(t *testing.T) {
	db, srv := newPolicyStatusServer(t)
	ctx := context.Background()
	for _, id := range []string{"c1", "c2"} {
		if err := db.UpsertK8sCluster(ctx, store.K8sCluster{ID: id, Name: id, Status: "registered"}); err != nil {
			t.Fatal(err)
		}
	}
	server := &Server{cfg: testConfig("http://upstream.invalid", "secret"), db: db}
	leaked := server.issueAgentToken(ctx, "c1", time.Now().Add(time.Hour))
	other := server.issueAgentToken(ctx, "c2", time.Now().Add(time.Hour))
	if !server.verifyAgentToken(ctx, leaked, "c1") || !server.verifyAgentToken(ctx, other, "c2") {
		t.Fatal("freshly issued tokens must verify")
	}

	resp, err := http.Post(srv.URL+"/admin/k8s/agent/revoke-tokens?cluster_id=c1", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke returned %d", resp.StatusCode)
	}

	if server.verifyAgentToken(ctx, leaked, "c1") {
		t.Fatal("a revoked cluster's token still verifies; revocation did nothing")
	}
	if !server.verifyAgentToken(ctx, other, "c2") {
		t.Fatal("revoking one cluster killed another cluster's agent")
	}
	// A manifest regenerated after the revocation must work again.
	if !server.verifyAgentToken(ctx, server.issueAgentToken(ctx, "c1", time.Now().Add(time.Hour)), "c1") {
		t.Fatal("a token issued after revocation must verify; otherwise the cluster is bricked")
	}
}

// Tokens issued before generations existed carry no generation field and must keep working
// until that cluster is revoked at least once — an upgrade must not silently stop every agent.
func TestLegacyAgentTokensSurviveUpgradeButNotRevocation(t *testing.T) {
	db, _ := newPolicyStatusServer(t)
	server := &Server{cfg: testConfig("http://upstream.invalid", "secret"), db: db}
	ctx := context.Background()

	legacy := server.issueLegacyAgentTokenForTest("c1", time.Now().Add(time.Hour))
	if !server.verifyAgentToken(ctx, legacy, "c1") {
		t.Fatal("a token issued by the previous version stopped verifying on upgrade")
	}
	if err := db.UpsertAdminSetting(ctx, store.AdminSetting{
		Key: agentTokenGenPrefix + "c1", Category: "k8s_agent", ValueJSON: "1", ValueType: "int", Source: "admin",
	}, "tester", "test revoke"); err != nil {
		t.Fatal(err)
	}
	if server.verifyAgentToken(ctx, legacy, "c1") {
		t.Fatal("revocation must kill pre-generation tokens too, or a leaked old token is immortal")
	}
}

func TestAgentTokenRevokeRejectsUnknownCluster(t *testing.T) {
	_, srv := newPolicyStatusServer(t)
	resp, err := http.Post(srv.URL+"/admin/k8s/agent/revoke-tokens?cluster_id=nope", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("revoking an unknown cluster returned %d, want 404", resp.StatusCode)
	}
}
