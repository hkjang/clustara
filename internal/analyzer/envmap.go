package analyzer

import (
	"regexp"
	"sort"
	"strings"

	"clustara/internal/store"
)

// Env Source Map: resolve a Pod's declared environment variables to their SOURCE (literal /
// ConfigMap / Secret / Downward API) per container, plus a Secret-hygiene risk scan — so operators
// see "이 Pod에 어떤 설정이 어디서 왔는가" without ever exposing Secret values. Pure over the spec.
//
// Secret values are NEVER resolved here: the Pod spec only carries references (name/key), and
// literal values whose key looks sensitive are masked.

// EnvVarSource is one declared env var and where it comes from.
type EnvVarSource struct {
	Container  string `json:"container"`
	Init       bool   `json:"init"`
	Name       string `json:"name"`
	SourceType string `json:"source_type"` // literal | configmap | secret | field | resource | configmap_all | secret_all
	SourceName string `json:"source_name,omitempty"`
	SourceKey  string `json:"source_key,omitempty"`
	Value      string `json:"value,omitempty"` // only for literal/field/resource; masked when sensitive
	Optional   bool   `json:"optional,omitempty"`
	Masked     bool   `json:"masked,omitempty"`
}

// EnvRisk is one Secret-hygiene/operational finding over the env declaration.
type EnvRisk struct {
	Container string `json:"container"`
	Name      string `json:"name"`
	Severity  string `json:"severity"` // high | medium | low
	Issue     string `json:"issue"`
}

// EnvSourceMap is the full per-Pod result.
type EnvSourceMap struct {
	Vars   []EnvVarSource `json:"vars"`
	Risks  []EnvRisk      `json:"risks"`
	Counts struct {
		Literal   int `json:"literal"`
		ConfigMap int `json:"configmap"`
		Secret    int `json:"secret"`
		Other     int `json:"other"`
	} `json:"counts"`
}

// sensitiveEnvHints: 이름에 이 문자열이 포함되면 항상 민감 값으로 간주(부분 문자열 매칭).
var sensitiveEnvHints = []string{
	"password", "passwd", "pwd", "secret", "token",
	"apikey", "api_key", "access_key", "accesskey",
	"private", "credential",
	// DB/연결 문자열: DSN·connection string 은 값 자체가 자격증명을 포함.
	"dsn", "connectionstring", "connection_string", "connstr", "conn_str",
}

// sensitiveEnvSuffixes: 이름이 이 접미사로 끝나면 DB 접속정보/연결 문자열일 가능성이 높음.
// (예: MAIN_DB, USER_DB). 접미사 매칭이라 DEBUG·DB_HOST 같은 오탐은 걸리지 않음.
var sensitiveEnvSuffixes = []string{"_db", "_dburl", "_dburi"}

// sensitiveEnvCombos: 이름에 이 문자열들이 모두 포함되면 DB 연결 문자열(자격증명 포함 가능)로 간주.
// (예: DB_URL, DATABASE_URI, PG_DB_CONNECTION). "db"+연결류를 함께 요구해 오탐을 줄임.
var sensitiveEnvCombos = [][]string{
	{"db", "url"}, {"db", "uri"}, {"db", "conn"},
	{"database", "url"}, {"database", "uri"}, {"database", "conn"},
}

// credentialURIRe: scheme://user:password@host 형태의 연결 문자열(자격증명 내장)을 값에서 탐지.
// postgres://·mysql://·mongodb://·redis://·amqp:// 등 스킴 무관하게 userinfo 의 password 를 잡음.
var credentialURIRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://[^:@/?#\s]*:[^@/?#\s]+@`)

func looksSensitiveEnv(name string) bool {
	l := strings.ToLower(name)
	for _, h := range sensitiveEnvHints {
		if strings.Contains(l, h) {
			return true
		}
	}
	for _, s := range sensitiveEnvSuffixes {
		if strings.HasSuffix(l, s) {
			return true
		}
	}
	for _, combo := range sensitiveEnvCombos {
		all := true
		for _, part := range combo {
			if !strings.Contains(l, part) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// looksSensitiveEnvValue: 키 이름과 무관하게 값이 자격증명을 내장한 연결 문자열이면 true.
func looksSensitiveEnvValue(value string) bool {
	return credentialURIRe.MatchString(strings.TrimSpace(value))
}

// BuildEnvSourceMap parses a workload/Pod spec's containers (env + envFrom) into a source map plus
// a Secret-hygiene risk scan.
func BuildEnvSourceMap(it store.K8sInventoryItem) EnvSourceMap {
	ps := podSpecOf(it)
	out := EnvSourceMap{Vars: []EnvVarSource{}, Risks: []EnvRisk{}}

	scan := func(containers []any, init bool) {
		for _, raw := range containers {
			c := asAnyMap(raw)
			cname := str(c["name"])
			for _, ev := range asAnySlice(c["env"]) {
				e := asAnyMap(ev)
				v := EnvVarSource{Container: cname, Init: init, Name: str(e["name"])}
				if vf := asAnyMap(e["valueFrom"]); len(vf) > 0 {
					switch {
					case len(asAnyMap(vf["secretKeyRef"])) > 0:
						ref := asAnyMap(vf["secretKeyRef"])
						v.SourceType = "secret"
						v.SourceName, v.SourceKey, v.Optional = str(ref["name"]), str(ref["key"]), asBool(ref["optional"])
						out.Counts.Secret++
					case len(asAnyMap(vf["configMapKeyRef"])) > 0:
						ref := asAnyMap(vf["configMapKeyRef"])
						v.SourceType = "configmap"
						v.SourceName, v.SourceKey, v.Optional = str(ref["name"]), str(ref["key"]), asBool(ref["optional"])
						out.Counts.ConfigMap++
					case len(asAnyMap(vf["fieldRef"])) > 0:
						v.SourceType = "field"
						v.SourceKey = str(asAnyMap(vf["fieldRef"])["fieldPath"])
						out.Counts.Other++
					case len(asAnyMap(vf["resourceFieldRef"])) > 0:
						v.SourceType = "resource"
						v.SourceKey = str(asAnyMap(vf["resourceFieldRef"])["resource"])
						out.Counts.Other++
					default:
						v.SourceType = "other"
						out.Counts.Other++
					}
				} else {
					v.SourceType = "literal"
					out.Counts.Literal++
					val := str(e["value"])
					if looksSensitiveEnv(v.Name) || looksSensitiveEnvValue(val) {
						v.Value, v.Masked = "***", true
						out.Risks = append(out.Risks, EnvRisk{Container: cname, Name: v.Name, Severity: "high", Issue: "민감해 보이는 이름의 평문 env — Secret 참조로 이전 권장"})
					} else {
						v.Value = val
					}
				}
				out.Vars = append(out.Vars, v)
			}
			// envFrom: bulk import of all keys from a ConfigMap/Secret.
			for _, ef := range asAnySlice(c["envFrom"]) {
				f := asAnyMap(ef)
				if ref := asAnyMap(f["secretRef"]); len(ref) > 0 {
					out.Vars = append(out.Vars, EnvVarSource{Container: cname, Init: init, Name: "(envFrom)", SourceType: "secret_all", SourceName: str(ref["name"]), Optional: asBool(ref["optional"])})
					out.Counts.Secret++
					out.Risks = append(out.Risks, EnvRisk{Container: cname, Name: str(ref["name"]), Severity: "medium", Issue: "Secret 전체를 envFrom으로 주입 — 필요한 key만 주입 권장"})
				}
				if ref := asAnyMap(f["configMapRef"]); len(ref) > 0 {
					out.Vars = append(out.Vars, EnvVarSource{Container: cname, Init: init, Name: "(envFrom)", SourceType: "configmap_all", SourceName: str(ref["name"]), Optional: asBool(ref["optional"])})
					out.Counts.ConfigMap++
				}
			}
		}
	}
	scan(asAnySlice(ps["initContainers"]), true)
	scan(asAnySlice(ps["containers"]), false)

	sort.SliceStable(out.Risks, func(i, j int) bool {
		return sevRank(out.Risks[i].Severity) < sevRank(out.Risks[j].Severity)
	})
	return out
}

func sevRank(s string) int {
	switch s {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}
