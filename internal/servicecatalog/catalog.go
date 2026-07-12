package servicecatalog

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"text/template"
)

type Definition struct {
	Code, Name, Category, Description, Icon, DeploymentType string
	Version, Image, Template                                string
	GPURequired                                             bool
}

type RenderInput struct {
	Name, Namespace, Image, CPU, Memory, Storage string
	Replicas, Port                               int
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
var imageRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@+-]*$`)
var cpuQuantity = regexp.MustCompile(`^[0-9]+m?$`)
var byteQuantity = regexp.MustCompile(`^[0-9]+(Ki|Mi|Gi|Ti)?$`)

func ValidateInput(in RenderInput) []string {
	errs := []string{}
	if len(in.Name) < 1 || len(in.Name) > 63 || !dnsLabel.MatchString(in.Name) {
		errs = append(errs, "인스턴스명은 Kubernetes DNS label 형식이어야 합니다")
	}
	if len(in.Namespace) < 1 || len(in.Namespace) > 63 || !dnsLabel.MatchString(in.Namespace) {
		errs = append(errs, "namespace는 Kubernetes DNS label 형식이어야 합니다")
	}
	if strings.TrimSpace(in.Image) == "" {
		errs = append(errs, "digest 또는 승인된 내부 이미지가 필요합니다")
	} else if !imageRef.MatchString(in.Image) {
		errs = append(errs, "이미지 참조 형식이 올바르지 않습니다")
	}
	if strings.Contains(in.Image, ":latest") {
		errs = append(errs, "mutable latest tag는 사용할 수 없습니다")
	}
	if in.Replicas < 0 || in.Replicas > 100 {
		errs = append(errs, "replicas는 0~100 범위여야 합니다")
	}
	if !cpuQuantity.MatchString(in.CPU) {
		errs = append(errs, "CPU quantity 형식이 올바르지 않습니다")
	}
	if !byteQuantity.MatchString(in.Memory) {
		errs = append(errs, "Memory quantity 형식이 올바르지 않습니다")
	}
	if !byteQuantity.MatchString(in.Storage) {
		errs = append(errs, "Storage quantity 형식이 올바르지 않습니다")
	}
	return errs
}

func Render(def Definition, in RenderInput) (string, error) {
	if errs := ValidateInput(in); len(errs) > 0 {
		return "", fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	t, err := template.New(def.Code).Option("missingkey=error").Parse(def.Template)
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := t.Execute(&out, in); err != nil {
		return "", err
	}
	return out.String(), nil
}

const workloadTemplate = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels: {app.kubernetes.io/name: {{.Name}}, app.kubernetes.io/managed-by: clustara}
spec:
  replicas: {{.Replicas}}
  selector: {matchLabels: {app.kubernetes.io/name: {{.Name}}}}
  template:
    metadata: {labels: {app.kubernetes.io/name: {{.Name}}}}
    spec:
      serviceAccountName: {{.Name}}
      securityContext: {runAsNonRoot: true}
      containers:
      - name: app
        image: {{.Image}}
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: false, capabilities: {drop: ["ALL"]}}
        resources: {requests: {cpu: {{.CPU}}, memory: {{.Memory}}}, limits: {cpu: {{.CPU}}, memory: {{.Memory}}}}
        ports: [{name: http, containerPort: {{.Port}}}]
        readinessProbe: {tcpSocket: {port: http}, initialDelaySeconds: 10}
        livenessProbe: {tcpSocket: {port: http}, initialDelaySeconds: 30}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: {{.Name}}, namespace: {{.Namespace}}}
---
apiVersion: v1
kind: Service
metadata: {name: {{.Name}}, namespace: {{.Namespace}}}
spec: {selector: {app.kubernetes.io/name: {{.Name}}}, ports: [{name: tcp, port: {{.Port}}, targetPort: http}]}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: {{.Name}}-default-deny, namespace: {{.Namespace}}}
spec: {podSelector: {matchLabels: {app.kubernetes.io/name: {{.Name}}}}, policyTypes: [Ingress, Egress]}
`

const statefulTemplate = `apiVersion: apps/v1
kind: StatefulSet
metadata: {name: {{.Name}}, namespace: {{.Namespace}}, labels: {app.kubernetes.io/managed-by: clustara}}
spec:
  serviceName: {{.Name}}
  replicas: {{.Replicas}}
  selector: {matchLabels: {app.kubernetes.io/name: {{.Name}}}}
  template:
    metadata: {labels: {app.kubernetes.io/name: {{.Name}}}}
    spec:
      serviceAccountName: {{.Name}}
      securityContext: {runAsNonRoot: true}
      containers:
      - name: service
        image: {{.Image}}
        securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}}
        resources: {requests: {cpu: {{.CPU}}, memory: {{.Memory}}}, limits: {cpu: {{.CPU}}, memory: {{.Memory}}}}
        ports: [{name: tcp, containerPort: {{.Port}}}]
        volumeMounts: [{name: data, mountPath: /data}]
  volumeClaimTemplates:
  - metadata: {name: data}
    spec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: {{.Storage}}}}}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: {{.Name}}, namespace: {{.Namespace}}}
---
apiVersion: v1
kind: Service
metadata: {name: {{.Name}}, namespace: {{.Namespace}}}
spec: {clusterIP: None, selector: {app.kubernetes.io/name: {{.Name}}}, ports: [{name: tcp, port: {{.Port}}}]}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: {{.Name}}-default-deny, namespace: {{.Namespace}}}
spec: {podSelector: {matchLabels: {app.kubernetes.io/name: {{.Name}}}}, policyTypes: [Ingress, Egress]}
`

func Builtins() []Definition {
	return []Definition{
		{Code: "postgresql", Name: "PostgreSQL", Category: "database", Description: "상태 저장 PostgreSQL 서비스", Icon: "database", DeploymentType: "manifest", Version: "17", Image: "harbor.local/library/postgres:17", Template: statefulTemplate},
		{Code: "redis", Name: "Redis", Category: "database", Description: "인메모리 캐시/데이터 서비스", Icon: "database", DeploymentType: "manifest", Version: "7.4", Image: "harbor.local/library/redis:7.4", Template: statefulTemplate},
		{Code: "tomcat", Name: "Tomcat", Category: "was", Description: "표준 Java WAS", Icon: "app", DeploymentType: "manifest", Version: "10.1", Image: "harbor.local/library/tomcat:10.1", Template: workloadTemplate},
		{Code: "spring-boot", Name: "Spring Boot", Category: "application", Description: "Spring Boot 컨테이너 애플리케이션", Icon: "app", DeploymentType: "manifest", Version: "3", Image: "harbor.local/library/spring-boot:3", Template: workloadTemplate},
		{Code: "jupyterlab", Name: "JupyterLab", Category: "data-analysis", Description: "단독 분석 워크스페이스", Icon: "notebook", DeploymentType: "manifest", Version: "4", Image: "harbor.local/library/jupyterlab:4", Template: workloadTemplate},
		{Code: "jupyterhub", Name: "JupyterHub", Category: "data-analysis", Description: "다중 사용자 Notebook 플랫폼", Icon: "notebook", DeploymentType: "helm", Version: "4", Image: "harbor.local/library/jupyterhub:4", Template: workloadTemplate},
	}
}
