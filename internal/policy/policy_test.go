package policy

import (
	"testing"

	"rdpshot/internal/model"
)

func TestEvaluateFailsWithoutNLA(t *testing.T) {
	doc := Default()
	hosts := []model.Host{{
		Endpoint: model.Endpoint{Address: "10.0.0.1", Port: 3389},
		State:    "open",
		Service:  &model.ServiceInfo{NLARequired: false, TLSVersion: "TLS 1.2"},
	}}
	res := Evaluate(doc, hosts, nil)
	if res.Passed {
		t.Fatalf("expected fail, got %+v", res)
	}
}
