package prometheus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseVector(t *testing.T) {
	body := []byte(`{"status":"success","data":{"resultType":"vector","result":[
		{"metric":{"namespace":"prod","workload":"api"},"value":[1719200000,"123.45"]},
		{"metric":{"namespace":"prod","workload":"web"},"value":[1719200000,"NaN"]},
		{"metric":{"namespace":"prod","workload":"db"},"value":[1719200000,"7"]}
	]}}`)
	out, err := parseVector(body)
	if err != nil {
		t.Fatal(err)
	}
	// NaN is skipped → 2 valid samples.
	if len(out) != 2 {
		t.Fatalf("expected 2 samples (NaN skipped), got %d: %+v", len(out), out)
	}
	if out[0].Labels["workload"] != "api" || out[0].Value != 123.45 {
		t.Fatalf("first sample wrong: %+v", out[0])
	}
}

func TestParseVectorError(t *testing.T) {
	if _, err := parseVector([]byte(`{"status":"error","error":"bad query"}`)); err == nil {
		t.Fatal("error status should return an error")
	}
}

func TestQueryAgainstFakeServer(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"n","workload":"a"},"value":[1,"42"]}]}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "tok")
	out, err := c.Query(context.Background(), "histogram_quantile(0.95, x)")
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != "histogram_quantile(0.95, x)" {
		t.Fatalf("query not passed through: %q", gotQuery)
	}
	if len(out) != 1 || out[0].Value != 42 {
		t.Fatalf("unexpected result: %+v", out)
	}
}
