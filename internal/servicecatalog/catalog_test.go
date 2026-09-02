package servicecatalog

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ValidateInput is the only gate between a self-service request body and a manifest that an
// operator applies to a real cluster: every value below arrives from user-supplied JSON
// (`values` in the instance-create payload). These tests pin the values it must refuse.

func baseInput() RenderInput {
	return RenderInput{
		Name:      "orders",
		Namespace: "team-a",
		Image:     "harbor.local/library/postgres:17",
		CPU:       "500m",
		Memory:    "1Gi",
		Storage:   "20Gi",
		Replicas:  1,
		Port:      5432,
	}
}

func TestValidateInputAcceptsRealisticRequest(t *testing.T) {
	if errs := ValidateInput(baseInput()); len(errs) > 0 {
		t.Fatalf("valid input rejected: %v", errs)
	}
}

// A port lands in `containerPort:` verbatim. Nothing else checks it, so an out-of-range value
// rendered a manifest the API server rejects only at apply time — after approval.
func TestValidateInputRejectsPortOutOfRange(t *testing.T) {
	for _, port := range []int{0, -1, 65536, 1 << 20} {
		in := baseInput()
		in.Port = port
		errs := ValidateInput(in)
		if len(errs) == 0 {
			t.Fatalf("port %d accepted", port)
		}
		if _, err := Render(Definition{Code: "postgresql", Template: statefulTemplate}, in); err == nil {
			t.Fatalf("port %d rendered a manifest", port)
		}
	}
	for _, port := range []int{1, 8080, 65535} {
		in := baseInput()
		in.Port = port
		if errs := ValidateInput(in); len(errs) > 0 {
			t.Fatalf("port %d rejected: %v", port, errs)
		}
	}
}

// An image with no tag is Kubernetes-speak for `:latest`, so it must fail the same guard as a
// literal `:latest`. It previously passed both this check and the production digest gate.
func TestValidateInputRejectsMutableImageReferences(t *testing.T) {
	for _, image := range []string{
		"harbor.local/library/postgres",
		"harbor.local/library/postgres:latest",
		"postgres",
		"harbor.local:5000/library/postgres",
	} {
		in := baseInput()
		in.Image = image
		if errs := ValidateInput(in); len(errs) == 0 {
			t.Fatalf("mutable image %q accepted", image)
		}
	}
}

// The guard was a `:latest` substring test, so a legitimate tag that merely starts with "latest"
// was refused. Digest-pinned references are immutable even when the tag reads `latest`.
func TestValidateInputAcceptsPinnedImageReferences(t *testing.T) {
	for _, image := range []string{
		"harbor.local/library/tomcat:latest-jdk21",
		"harbor.local:5000/library/postgres:17",
		"harbor.local/library/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"harbor.local/library/postgres:latest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		in := baseInput()
		in.Image = image
		if errs := ValidateInput(in); len(errs) > 0 {
			t.Fatalf("pinned image %q rejected: %v", image, errs)
		}
	}
}

// "0" matched the quantity patterns. A zero storage request is rejected outright by the PVC
// validator, and a zero memory limit OOM-kills the container on its first allocation.
func TestValidateInputRejectsZeroQuantities(t *testing.T) {
	for _, tc := range []struct{ field, value string }{
		{"cpu", "0"}, {"cpu", "0m"}, {"cpu", "000"},
		{"memory", "0"}, {"memory", "0Gi"},
		{"storage", "0"}, {"storage", "0Ti"},
	} {
		in := baseInput()
		switch tc.field {
		case "cpu":
			in.CPU = tc.value
		case "memory":
			in.Memory = tc.value
		case "storage":
			in.Storage = tc.value
		}
		if errs := ValidateInput(in); len(errs) == 0 {
			t.Fatalf("%s=%q accepted", tc.field, tc.value)
		}
	}
}

func TestValidateInputRejectsMalformedIdentifiers(t *testing.T) {
	for _, mut := range []func(*RenderInput){
		func(in *RenderInput) { in.Name = "" },
		func(in *RenderInput) { in.Name = "Orders" },
		func(in *RenderInput) { in.Name = "orders-" },
		func(in *RenderInput) { in.Name = strings.Repeat("a", 64) },
		func(in *RenderInput) { in.Namespace = "team_a" },
		func(in *RenderInput) { in.Image = "" },
		func(in *RenderInput) { in.Image = "harbor.local/lib rary/postgres:17" },
		func(in *RenderInput) { in.Replicas = -1 },
		func(in *RenderInput) { in.Replicas = 101 },
		func(in *RenderInput) { in.CPU = "half" },
		func(in *RenderInput) { in.Memory = "1GB" },
	} {
		in := baseInput()
		mut(&in)
		if errs := ValidateInput(in); len(errs) == 0 {
			t.Fatalf("invalid input accepted: %+v", in)
		}
	}
}

// Every builtin template must render to documents an operator can actually apply.
func TestBuiltinsRenderParseableManifests(t *testing.T) {
	for _, def := range Builtins() {
		in := baseInput()
		in.Image = def.Image + "-pinned"
		out, err := Render(def, in)
		if err != nil {
			t.Fatalf("%s: render: %v", def.Code, err)
		}
		docs := 0
		dec := yaml.NewDecoder(strings.NewReader(out))
		for {
			var doc map[string]any
			err := dec.Decode(&doc)
			if err != nil {
				break
			}
			if doc == nil {
				continue
			}
			docs++
			if _, ok := doc["kind"]; !ok {
				t.Fatalf("%s: document %d has no kind", def.Code, docs)
			}
		}
		if docs < 4 {
			t.Fatalf("%s: expected at least 4 documents, got %d", def.Code, docs)
		}
	}
}
