package proxy

import "net/http"

func (s *Server) registerEnterpriseRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/orgs", s.handleEnterpriseOrganizations)
	mux.HandleFunc("/admin/workspaces", s.handleEnterpriseWorkspaces)
	mux.HandleFunc("/admin/projects", s.handleEnterpriseProjects)
	mux.HandleFunc("/admin/catalog/entities", s.handleCatalogEntities)
	mux.HandleFunc("/admin/catalog/ownership-map", s.handleCatalogOwnershipMap)
	mux.HandleFunc("/admin/access-bindings/evaluate", s.handleAccessBindingEvaluate)
	mux.HandleFunc("/admin/access-bindings", s.handleAccessBindings)
	mux.HandleFunc("/admin/enterprise/enforcement", s.handleEnterpriseEnforcementStatus)
}

func (s *Server) registerFleetRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/fleet/overview", s.handleFleetOverview)
	mux.HandleFunc("/admin/fleet/search", s.handleFleetSearch)
	mux.HandleFunc("/admin/fleet/lifecycle", s.handleFleetLifecycle)
	mux.HandleFunc("/admin/fleet/compare", s.handleFleetCompare)
	mux.HandleFunc("/admin/fleet/blast-radius", s.handleFleetBlastRadius)
	mux.HandleFunc("/admin/fleet/score", s.handleFleetScore)
	mux.HandleFunc("/admin/fleet/actions/dry-run", s.handleFleetActionDryRun)
	mux.HandleFunc("/admin/fleet/progressive-actions", s.handleFleetProgressiveActions)
}

func (s *Server) registerSecOpsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/security/posture", s.handleSecurityPosture)
	mux.HandleFunc("/admin/security/images", s.handleSecurityImages)
	mux.HandleFunc("/admin/security/cves", s.handleSecurityCVEs)
	mux.HandleFunc("/admin/security/signing", s.handleSecurityImageSigning)
	mux.HandleFunc("/admin/security/admission/simulate", s.handleSecurityAdmissionSimulate)
	mux.HandleFunc("/admin/security/runtime-threats", s.handleSecurityRuntimeThreats)
	mux.HandleFunc("/admin/security/network-graph", s.handleSecurityNetworkGraph)
	mux.HandleFunc("/admin/security/exceptions", s.handleSecurityExceptionsAlias)
	mux.HandleFunc("/admin/security/compliance", s.handleSecurityComplianceReport)
}

func (s *Server) registerAIOpsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/problems", s.handleAIOpsProblems)
	mux.HandleFunc("/admin/problems/", s.handleAIOpsProblemDetail)
}

func (s *Server) registerFinOpsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/finops/overview", s.handleFinOpsOverview)
	mux.HandleFunc("/admin/finops/costs", s.handleFinOpsCosts)
	mux.HandleFunc("/admin/finops/anomalies", s.handleFinOpsAnomalies)
	mux.HandleFunc("/admin/finops/rightsizing", s.handleFinOpsRightsizing)
	mux.HandleFunc("/admin/finops/billing-imports", s.handleFinOpsBillingImports)
	mux.HandleFunc("/admin/finops/idle-resources", s.handleFinOpsIdleResources)
	mux.HandleFunc("/admin/finops/gpu-costs", s.handleFinOpsGPUCosts)
	mux.HandleFunc("/admin/finops/unit-economics", s.handleFinOpsUnitEconomics)
	mux.HandleFunc("/admin/finops/chargeback", s.handleFinOpsChargeback)
	mux.HandleFunc("/admin/finops/savings-workflows", s.handleFinOpsSavingsWorkflows)
}

func (s *Server) registerGitOpsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/gitops/overview", s.handleGitOpsOverview)
	mux.HandleFunc("/admin/gitops/sources", s.handleGitOpsSources)
	mux.HandleFunc("/admin/gitops/drift", s.handleGitOpsDrift)
	mux.HandleFunc("/admin/gitops/pr-drafts", s.handleGitOpsPRDrafts)
	mux.HandleFunc("/admin/gitops/progressive-rollouts", s.handleGitOpsProgressiveRollouts)
	mux.HandleFunc("/admin/gitops/rollback-plans", s.handleGitOpsRollbackPlans)
	mux.HandleFunc("/admin/gitops/change-calendar", s.handleGitOpsChangeCalendar)
	mux.HandleFunc("/admin/gitops/deployment-evidence", s.handleGitOpsDeploymentEvidence)
}

func (s *Server) registerGovernanceHubRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/governance/evidence", s.handleGovernanceEvidence)
	mux.HandleFunc("/admin/governance/cmdb-links", s.handleGovernanceCMDBLinks)
	mux.HandleFunc("/admin/governance/tickets", s.handleGovernanceTickets)
	mux.HandleFunc("/admin/governance/risk-register", s.handleGovernanceRiskRegister)
	mux.HandleFunc("/admin/governance/executive-report", s.handleGovernanceExecutiveReport)
	mux.HandleFunc("/admin/governance/audit-search", s.handleGovernanceAuditSearch)
}
